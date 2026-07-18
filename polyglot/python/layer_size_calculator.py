"""
polyglot/python/layer_size_calculator.py

Dockerfile layer size calculator for shipcheck tool.
Parses Dockerfiles and estimates total image size by analyzing each layer's contribution.
"""

import re
import json
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any, Tuple


@dataclass
class LayerInfo:
    """Represents a single Docker layer with its estimated size."""
    instruction: str
    line_number: int
    base_size: float  # in bytes
    description: str = ""
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "instruction": self.instruction,
            "line": self.line_number,
            "size_bytes": round(self.base_size, 2),
            "description": self.description
        }


@dataclass
class SizeReport:
    """Complete size analysis report."""
    total_estimated: float
    base_image: Optional[str] = None
    layers: List[LayerInfo] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_bytes": round(self.total_estimated, 2),
            "total_mb": round(self.total_estimated / (1024 * 1024), 2),
            "base_image": self.base_image,
            "layers": [l.to_dict() for l in self.layers],
            "warnings": self.warnings
        }


class LayerSizeCalculator:
    """
    Calculates estimated Docker image size from a Dockerfile.
    
    Uses heuristics and registry data when available to provide accurate estimates.
    """
    
    # Default base image sizes (approximate, in bytes)
    DEFAULT_BASE_SIZES = {
        "alpine": 50_000_000,      # ~48MB
        "scratch": 100_000,         # minimal
        "debian:slim": 70_000_000,  # ~67MB
        "ubuntu:20.04": 90_000_000, # ~85MB
    }
    
    # Package manager output estimates (in bytes)
    PACKAGE_OUTPUT_ESTIMATES = {
        "apt-get install": 150_000_000,   # ~143MB typical additions
        "apk add": 20_000_000,            # ~19MB
        "yum install": 80_000_000,        # ~76MB
    }
    
    def __init__(self, dockerfile_content: str):
        self.lines = dockerfile_content.splitlines()
        self.current_line = 0
        
    def calculate(self) -> SizeReport:
        """Calculate total estimated image size."""
        report = SizeReport(total_estimated=0.0)
        
        # Parse all layers first
        for line_num, line in enumerate(self.lines, 1):
            stripped = line.strip()
            
            # Skip empty lines and comments
            if not stripped or stripped.startswith("#"):
                continue
            
            instruction = self._extract_instruction(stripped)
            if not instruction:
                continue
                
            layer = LayerInfo(
                instruction=instruction,
                line_number=line_num,
                base_size=0.0,
                description=self._describe_layer(instruction, stripped)
            )
            
            report.layers.append(layer)
            report.total_estimated += layer.base_size
        
        # Fetch real base image sizes if available
        self._fetch_base_sizes(report)
        
        return report
    
    def _extract_instruction(self, line: str) -> Optional[str]:
        """Extract the main instruction from a Dockerfile line."""
        # Handle multi-line instructions (backslash continuation)
        while line.endswith("\\") and self.current_line < len(self.lines):
            next_line = self.lines[self.current_line].strip() if self.current_line < len(self.layers) else ""
            line = line[:-1] + " " + next_line.strip()
        
        # Remove arguments to get just the instruction
        parts = line.split(None, 1)
        return parts[0].upper().rstrip("$") if parts else None
    
    def _describe_layer(self, instruction: str, full_line: str) -> str:
        """Generate a human-readable description for debugging."""
        args = full_line.split(None, 1)[1] if len(full_line.split()) > 1 else ""
        
        descriptions = {
            "FROM": f"Base image (args: {args[:50]}...)",
            "COPY": f"Copy files/dirs ({len(args.split()} args)",
            "ADD": f"Add files with tar support ({len(args.split())} args)",
            "RUN": f"Shell command execution",
            "ENV": f"Environment variable",
            "ARG": f"Build-time argument",
        }
        
        return descriptions.get(instruction, f"{instruction}: {args[:50]}")
    
    def _fetch_base_sizes(self, report: SizeReport) -> None:
        """Fetch real base image sizes from Docker Hub API."""
        import urllib.request
        
        # Extract base image name from FROM instruction
        for layer in reversed(report.layers):
            if layer.instruction == "FROM":
                args = layer.description.split("args: ")[-1] if "args:" in layer.description else ""
                base_image = args.strip().split()[0].rstrip(":")  # Get just the image name
                
                if base_image and base_image not in self.DEFAULT_BASE_SIZES:
                    url = f"https://hub.docker.com/v2/repositories/{base_image}/"
                    
                    try:
                        req = urllib.request.Request(url, headers={"Accept": "application/json"})
                        with urllib.request.urlopen(req, timeout=5) as resp:
                            data = json.loads(resp.read().decode())
                            
                            # Get size from tags (use latest tag if available)
                            for tag in reversed(data.get("tags", [])):
                                tag_url = f"{url}tags/{tag}/"
                                
                                try:
                                    req2 = urllib.request.Request(tag_url, headers={"Accept": "application/json"})
                                    with urllib.request.urlopen(req2, timeout=5) as resp2:
                                        size_data = json.loads(resp2.read().decode())
                                        
                                        if "size" in size_data.get("manifest", {}):
                                            report.base_image = base_image
                                            report.layers[0].base_size = size_data["manifest"]["size"]
                                            break
                                except:
                                    continue
                    except Exception:
                        pass  # Network issues are not fatal
        
        # Apply defaults if no network fetch succeeded
        for layer in reversed(report.layers):
            if layer.instruction == "FROM":
                args = layer.description.split("args: ")[-1] if "args:" in layer.description else ""
                base_image = args.strip().split()[0].rstrip(":")
                
                if base_image and base_image not in self.DEFAULT_BASE_SIZES:
                    # Try to match common patterns
                    for default_name, size in self.DEFAULT_BASE_SIZES.items():
                        if base_image.startswith(default_name):
                            layer.base_size = size
                            break
    
    def _estimate_package_manager_output(self, instruction: str, args: str) -> float:
        """Estimate the output size of package manager commands."""
        for pattern, estimate in self.PACKAGE_OUTPUT_ESTIMATES.items():
            if pattern.lower() in instruction.lower():
                return estimate
        
        # Default estimate for unknown RUN instructions
        return 10_000_000  # ~9.5MB conservative default


def main():
    """Demo/entry point with example usage."""
    sample_dockerfile = """
FROM python:3.9-slim

# Install dependencies
RUN apt-get update && \\
    apt-get install -y --no-install-recommends \\\
        gcc libffi-dev libssl-dev \\
        && rm -rf /var/lib/apt/lists/*

COPY . /app/
WORKDIR /app

RUN pip install -r requirements.txt

ENV PYTHONUNBUFFERED=1

CMD ["python", "main.py"]
    """
    
    calculator = LayerSizeCalculator(sample_dockerfile)
    report = calculator.calculate()
    
    print(json.dumps(report.to_dict(), indent=2))


if __name__ == "__main__":
    main()