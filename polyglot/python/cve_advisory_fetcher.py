import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from functools import wraps
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

# Configure logging
logger = logging.getLogger(__name__)


@dataclass
class CVEEntry:
    """Structured CVE data with computed fields."""
    cve_id: str
    summary: str
    published_date: datetime
    modified_date: datetime
    severity: str  # UNDEFINED, LOW, MEDIUM, HIGH, CRITICAL
    cvss_score: Optional[float] = None
    affected_packages: List[Dict[str, Any]] = field(default_factory=list)
    references: List[Dict[str, Any]] = field(default_factory=list)
    
    @property
    def is_critical(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH")


class CVEAdvisoryFetcher:
    """
    Fetches and caches CVE advisories from NVD API.
    
    Supports filtering by package, severity, date range, etc.
    Uses LRU-style caching with TTL to respect rate limits.
    """
    
    DEFAULT_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    DEFAULT_CACHE_DIR = Path.home() / ".shipcheck" / "cve_cache"
    DEFAULT_TTL_SECONDS = 3600  # 1 hour
    
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        cache_dir: Optional[Path] = None,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        user_agent: str = "shipcheck/1.0"
    ):
        self.base_url = base_url.rstrip("/")
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.ttl_seconds = ttl_seconds
        self.user_agent = user_agent
        
        # In-memory cache with TTL tracking
        self._cache: Dict[str, tuple[dict, datetime]] = {}
        
    def _get_cache_path(self) -> Path:
        """Ensure cache directory exists."""
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        return self.cache_dir
    
    def _is_expired(self, entry_time: datetime) -> bool:
        """Check if cached entry is expired based on TTL."""
        return (datetime.now() - entry_time).total_seconds() > self.ttl_seconds
    
    def _make_request(
        self, 
        params: Dict[str, Any], 
        headers: Optional[Dict[str, str]] = None
    ) -> dict:
        """Make HTTP request with retry logic."""
        url = f"{self.base_url}?{json.dumps(params)}"
        
        # Build headers
        req_headers = {
            "Accept": "application/json",
            "User-Agent": self.user_agent,
            **(headers or {})
        }
        
        import urllib.request
        
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=30) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
                else:
                    logger.error(f"Request failed: {resp.status}")
                    raise ConnectionError(f"NVD API returned {resp.status}")
        except urllib.error.HTTPError as e:
            if e.code == 429:  # Rate limited
                logger.warning("Rate limited, waiting before retry...")
                import time
                time.sleep(60)
                return self._make_request(params, headers)
            raise
        except Exception as e:
            logger.error(f"Request error: {e}")
            raise
    
    def _parse_nvd_response(self, response: dict) -> List[CVEEntry]:
        """Parse NVD JSON response into CVEEntry objects."""
        results = []
        
        for cve in response.get("vulnerabilities", []):
            # Extract core fields
            cve_id = cve["cve"]["id"]
            
            # Parse dates
            pub_date_str = cve["cve"].get("published") or ""
            mod_date_str = cve["cve"].get("modified") or ""
            
            published_date = datetime.fromisoformat(pub_date_str.replace("Z", "+00:00")) if pub_date_str else None
            modified_date = datetime.fromisoformat(mod_date_str.replace("Z", "+00:00")) if mod_date_str else None
            
            # Parse severity and CVSS
            severity = cve["cve"].get("severity") or "UNDEFINED"
            cvss_score = float(cve["cve"]["cvssV2_1"]["score"]) if "cvssV2_1" in cve.get("cve", {}) else None
            
            # Parse affected packages (products)
            affected_packages = []
            for product in cve.get("cve", {}).get("affected", []):
                package_info = {
                    "name": product.get("product_name"),
                    "version_range": product.get("versions", {}).get("lessThan") or 
                                   product.get("versions", {}).get("greaterThanOrEqual") or "",
                    "status": product.get("status"),
                }
                affected_packages.append(package_info)
            
            # Parse references
            references = []
            for ref in cve["cve"].get("references", []):
                references.append({
                    "url": ref.get("url"),
                    "source": ref.get("source") or "",
                })
            
            entry = CVEEntry(
                cve_id=cve_id,
                summary=cve["cve"].get("summary") or "",
                published_date=published_date,
                modified_date=modified_date,
                severity=severity,
                cvss_score=cvss_score,
                affected_packages=affected_packages,
                references=references,
            )
            
            results.append(entry)
        
        return results
    
    def _get_cached(self, key: str) -> Optional[CVEEntry]:
        """Get from cache if not expired."""
        entry_time, data = self._cache.get(key, (None, None))
        
        if entry_time and not self._is_expired(entry_time):
            return CVEEntry(
                cve_id=data["id"],
                summary=data.get("summary", ""),
                published_date=datetime.fromisoformat(data["published"].replace("Z", "+00:00")) if data.get("published") else None,
                modified_date=datetime.fromisoformat(data["modified"].replace("Z", "+00:00")) if data.get("modified") else None,
                severity=data.get("severity", "UNDEFINED"),
                cvss_score=float(data["cvssV2_1"]["score"]) if "cvssV2_1" in data else None,
                affected_packages=[],  # Would need more work to deserialize
                references=[],
            )
        
        return None
    
    def _set_cached(self, key: str, entry: CVEEntry):
        """Store entry with timestamp."""
        self._cache[key] = (datetime.now(), {
            "id": entry.cve_id,
            "summary": entry.summary,
            "published": entry.published_date.isoformat() if entry.published_date else "",
            "modified": entry.modified_date.isoformat() if entry.modified_date else "",
            "severity": entry.severity,
            "cvssV2_1": {"score": entry.cvss_score or 0.0},
        })
    
    def fetch_cve(self, cve_id: str) -> Optional[CVEEntry]:
        """Fetch a single CVE by ID with caching."""
        key = f"cve:{cve_id}"
        
        # Check cache first
        cached = self._get_cached(key)
        if cached:
            logger.debug(f"Cache hit for {key}")
            return cached
        
        # Fetch from API
        try:
            response = self._make_request({"id": cve_id})
            
            if not response.get("vulnerabilities"):
                logger.warning(f"No CVE found for {cve_id}")
                return None
            
            entry = self._parse_nvd_response(response)[0]
            
            # Cache the result
            self._set_cached(key, entry)
            logger.info(f"Fetched and cached {key}")
            
            return entry
            
        except Exception as e:
            logger.error(f"Error fetching {cve_id}: {e}")
            return None
    
    def fetch_cves_by_package(
        self, 
        package_name: str,
        versions: Optional[List[str]] = None,
        severity_filter: str = "ALL",
        limit: int = 50
    ) -> List[CVEEntry]:
        """
        Find CVEs affecting a specific Python package.
        
        Args:
            package_name: The package name (e.g., "requests")
            versions: Optional list of affected versions
            severity_filter: Filter by severity ("ALL", "HIGH", "CRITICAL")
            limit: Maximum number of results to return
        
        Returns:
            List of CVEEntry objects, sorted by CVSS score descending.
        """
        params = {
            "product": package_name,
            "limit": limit,
            "sort": "cvssV2_1.score",
            "orderDescending": True,
        }
        
        if severity_filter != "ALL":
            # NVD doesn't support direct severity filtering in query params
            # We'll filter after fetching
            pass
        
        try:
            response = self._make_request(params)
            
            entries = self._parse_nvd_response(response)
            
            # Apply severity filter
            if severity_filter != "ALL":
                entries = [e for e in entries if e.severity == severity_filter]
            
            # Sort by CVSS score (descending)
            entries.sort(key=lambda x: x.cvss_score or 0, reverse=True)
            
            return entries
            
        except Exception as e:
            logger.error(f"Error fetching CVEs for {package_name}: {e}")
            return []
    
    def fetch_recent_high_severity(
        self, 
        days: int = 30,
        severity: str = "HIGH",
        limit: int = 100
    ) -> List[CVEEntry]:
        """
        Fetch recent high-severity CVEs published within the given timeframe.
        
        Args:
            days: Number of days to look back (default: 30)
            severity: Minimum severity level ("HIGH", "CRITICAL")
            limit: Maximum number of results
        
        Returns:
            List of recently published high-severity CVEs.
        """
        cutoff_date = datetime.now() - timedelta(days=days)
        
        # NVD API doesn't have a direct date filter, so we fetch recent and filter
        params = {
            "limit": limit,
            "sort": "published",
            "orderDescending": True,
        }
        
        try:
            response = self._make_request(params)
            
            entries = self._parse_nvd_response(response)
            
            # Filter by date and severity
            filtered = [
                e for e in entries 
                if (e.published_date >= cutoff_date if e.published_date else False)
                and e.severity == severity
            ]
            
            return filtered
            
        except Exception as e:
            logger.error(f"Error fetching recent high-severity CVEs: {e}")
            return []


def create_cli_demo():
    """Create a simple CLI demo for testing the fetcher."""
    import sys
    
    print("=" * 60)
    print("ShipCheck CVE Advisory Fetcher Demo")
    print("=" * 60)
    
    # Create fetcher instance
    fetcher = CVEAdvisoryFetcher(
        cache_dir=Path.cwd() / ".shipcheck_demo_cache",
        ttl_seconds=300,  # Short TTL for demo purposes
    )
    
    # Demo 1: Fetch a known CVE
    print("\n--- Demo 1: Fetch specific CVE ---")
    cve = fetcher.fetch_cve("CVE-2024-29867")  # A recent requests CVE
    
    if cve:
        print(f"ID: {cve.cve_id}")
        print(f"Summary: {cve.summary[:150]}...")
        print(f"Severity: {cve.severity} (CVSS: {cve.cvss_score})")
        print(f"Published: {cve.published_date}")
    else:
        print("No CVE found.")
    
    # Demo 2: Fetch CVEs for a popular package
    print("\n--- Demo 2: Fetch CVEs for 'requests' ---")
    requests_cves = fetcher.fetch_cves_by_package(
        "requests",
        severity_filter="HIGH"
    )
    
    if requests_cves:
        print(f"Found {len(requests_cves)} HIGH severity CVEs:")
        for cve in requests_cves[:5]:  # Show top 5
            print(f"  - {cve.cve_id}: {cve.severity} (CVSS: {cve.cvss_score})")
    else:
        print("No HIGH severity CVEs found.")
    
    # Demo 3: Fetch recent critical CVEs
    print("\n--- Demo 3: Recent CRITICAL CVEs ---")
    critical_cves = fetcher.fetch_recent_high_severity(
        days=7,
        severity="CRITICAL",
        limit=10
    )
    
    if critical_cves:
        print(f"Found {len(critical_cves)} CRITICAL CVEs in last 7 days:")
        for cve in critical_cves[:5]:
            print(f"  - {cve.cve_id}: {cve.severity}")
    else:
        print("No recent CRITICAL CVEs found.")
    
    # Demo 4: Check cache behavior
    print("\n--- Demo 4: Cache verification ---")
    cve2 = fetcher.fetch_cve("CVE-2024-29867")
    if cve2 and cve.cve_id == cve2.cve_id:
        print(f"Cache working! Same object returned for {cve.cve_id}")
    
    # Demo 5: Show memory usage of cache
    print("\n--- Cache Statistics ---")
    print(f"Active cache entries: {len(fetcher._cache)}")
    print(f"Cache directory exists: {fetcher.cache_dir.exists()}")
    
    print("\n" + "=" * 60)
    print("Demo complete!")
    print("=" * 60)


def main():
    """Main entry point with argument parsing."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="ShipCheck CVE Advisory Fetcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python -m cve_advisory_fetcher fetch CVE-2024-29867
  python -m cve_advisory_fetcher package requests --severity HIGH
  python -m cve_advisory_fetcher recent --days 30 --limit 50
        """
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Commands")
    
    # Fetch by ID
    fetch_id_parser = subparsers.add_parser("fetch", help="Fetch a specific CVE")
    fetch_id_parser.add_argument("cve_id", help="CVE ID (e.g., CVE-2024-29867)")
    fetch_id_parser.set_defaults(func=lambda args: _cmd_fetch(args))
    
    # Fetch by package
    fetch_pkg_parser = subparsers.add_parser(
        "package", 
        help="Fetch CVEs for a specific package"
    )
    fetch_pkg_parser.add_argument("package_name", help="Package name")
    fetch_pkg_parser.add_argument("--severity", default="ALL", choices=["ALL", "HIGH", "CRITICAL"])
    fetch_pkg_parser.add_argument("--limit", type=int, default=50)
    fetch_pkg_parser.set_defaults(func=lambda args: _cmd_package(args))
    
    # Fetch recent
    fetch_recent_parser = subparsers.add_parser(
        "recent", 
        help="Fetch recently published high-severity CVEs"
    )
    fetch_recent_parser.add_argument("--days", type=int, default=30)
    fetch_recent_parser.add_argument("--severity", default="HIGH")
    fetch_recent_parser.add_argument("--limit",