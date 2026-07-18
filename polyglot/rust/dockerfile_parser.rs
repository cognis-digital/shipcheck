use std::collections::{HashMap, HashSet};
use std::fmt;

/// Represents a parsed Dockerfile instruction
#[derive(Debug, Clone)]
pub enum Instruction {
    /// FROM image:tag [AS alias]
    From(ImageRef),
    /// RUN <command>
    Run(String),
    /// COPY src dst
    Copy(Vec<String>),
    /// ADD src dst
    Add(Vec<String>),
    /// ENV KEY=VALUE
    Env(HashMap<String, String>),
    /// ARG NAME
    Arg(String),
    /// LABEL key=value
    Label(HashMap<String, String>),
    /// EXPOSE port/protocol
    Expose(u16, Option<String>),
    /// CMD ["arg", "value"] or cmd string
    Cmd(Vec<String>),
    /// ENTRYPOINT similar to CMD
    Entrypoint(Vec<String>),
    /// WORKDIR /path
    Workdir(String),
    /// USER username|uid:groupname|gid
    User(String),
    /// VOLUME ["/mount"]
    Volume(Vec<String>),
    /// HEALTHCHECK <config>
    Healthcheck(HealthcheckConfig),
    /// SHELL ["bash", "-c", "command"]
    Shell(Vec<String>),
    /// UNKNOWN for unrecognized instructions
    Unknown(String, Vec<String>),
}

/// Represents a parsed image reference (e.g., alpine:3.18)
#[derive(Debug, Clone)]
pub struct ImageRef {
    pub registry: Option<String>,
    pub namespace: String,
    pub name: String,
    pub tag: Option<String>,
    pub digest: Option<String>,
}

/// Configuration for a HEALTHCHECK instruction
#[derive(Debug, Clone)]
pub struct HealthcheckConfig {
    pub interval: u64, // seconds
    pub timeout: u64,  // seconds
    pub retries: u32,   // number of retries
    pub start_period: u64, // seconds
}

/// Result of parsing a Dockerfile
#[derive(Debug)]
pub struct ParseResult {
    pub instructions: Vec<Instruction>,
    pub base_images: Vec<ImageRef>,
    pub warnings: Vec<String>,
}

impl ImageRef {
    /// Create an image reference from a string like "alpine:3.18" or "gcr.io/project/image@sha256:..."
    pub fn parse(input: &str) -> Self {
        let mut registry = None;
        let mut namespace = String::new();
        let mut name = String::new();
        let mut tag = None;
        let mut digest = None;

        // Check for digest (sha256:...)
        if let Some(at_pos) = input.find('@') {
            digest = Some(input[at_pos + 1..].to_string());
            input = &input[..at_pos];
        }

        // Check for tag (last : not followed by @ or end of string)
        let mut colon_pos = input.rfind(':').unwrap_or(0);
        
        // If colon is at the very end, it might be a digest separator already handled
        if colon_pos > 0 && !input.ends_with(":") {
            // Check if this colon introduces a tag (not part of registry:port)
            let before_colon = &input[..colon_pos];
            
            // If there's no / in the string, it's likely name:tag
            if before_colon.contains('/') {
                // Could be registry:port/image or namespace/image:tag
                // Find the last / to split namespace from image
                let slash_pos = before_colon.rfind('/').unwrap_or(0);
                
                if colon_pos > slash_pos {
                    // Format: namespace/image:tag
                    let (ns, img) = before_colon.split_at(slash_pos + 1);
                    namespace = ns.to_string();
                    name = img[..colon_pos].to_string();
                    tag = Some(input[colon_pos + 1..].to_string());
                } else {
                    // Format: registry:port/image or just image:tag
                    if let Some(last_slash) = before_colon.rfind('/') {
                        namespace = before_colon[..last_slash + 1].to_string();
                        name = before_colon[last_slash + 1..colon_pos].to_string();
                        tag = Some(input[colon_pos + 1..].to_string());
                    } else {
                        // Just image:tag
                        namespace = before_colon.to_string();
                        name = input[colon_pos + 1..].to_string();
                        tag = Some(input[colon_pos + 1..].to_string());
                    }
                }
            } else {
                // No /, so it's registry:port/image or image:tag
                if before_colon.contains(':') && !before_colon.ends_with(":") {
                    let (reg_port, img) = before_colon.split_at(colon_pos);
                    
                    // Check if this looks like a port (numeric only)
                    if reg_port.parse::<u16>().is_ok() {
                        registry = Some(reg_port.to_string());
                        name = img[..colon_pos].to_string();
                        tag = Some(input[colon_pos + 1..].to_string());
                    } else {
                        // It's likely namespace/image:tag where the last : is for tag
                        let (ns, img) = before_colon.split_at(before_colon.len() - colon_pos);
                        namespace = ns.to_string();
                        name = img[..colon_pos].to_string();
                        tag = Some(input[colon_pos + 1..].to_string());
                    }
                } else {
                    // Simple case: just image:tag or just image
                    if before_colon.contains(':') && !before_colon.ends_with(":") {
                        namespace = before_colon[..colon_pos].to_string();
                        name = input[colon_pos + 1..].to_string();
                        tag = Some(input[colon_pos + 1..].to_string());
                    } else {
                        // Just image, no tag
                        namespace = before_colon.to_string();
                        name = input[..colon_pos].to_string();
                    }
                }
            }
        }

        ImageRef {
            registry,
            namespace: if namespace.is_empty() { None }.unwrap_or(namespace),
            name: if name.is_empty() { None }.unwrap_or(name),
            tag: tag,
            digest,
        }
    }
}

impl fmt::Display for ImageRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut parts = Vec::new();
        
        if let Some(ref reg) = self.registry {
            parts.push(reg.clone());
        }
        
        if let Some(ref ns) = self.namespace {
            if !ns.is_empty() || parts.is_empty() {
                parts.push(ns.clone());
            }
        }
        
        if let Some(ref nm) = self.name {
            if !nm.is_empty() || (parts.len() < 2) {
                parts.push(nm.clone());
            }
        }
        
        // Add tag if present and not just a digest
        if let Some(ref tg) = self.tag {
            if !tg.is_empty() && self.digest.is_none() {
                parts.push(tg.clone());
            }
        }
        
        write!(f, "{}", parts.join(":"))
    }
}

/// A simple in-memory CVE database for demonstration
pub struct CveDatabase {
    entries: HashMap<String, Vec<CveEntry>>,
}

impl Default for CveDatabase {
    fn default() -> Self {
        let mut db = CveDatabase::new();
        
        // Add some sample CVEs for common images
        db.add_cve("alpine".to_string(), vec![
            CveEntry {
                id: "CVE-2023-12345".to_string(),
                severity: Severity::Medium,
                description: "OpenSSL vulnerability in Alpine Linux packages".to_string(),
                fixed_in: Some("3.19".to_string()),
            },
        ]);
        
        db.add_cve("ubuntu".to_string(), vec![
            CveEntry {
                id: "CVE-2023-67890".to_string(),
                severity: Severity::High,
                description: "glibc buffer overflow in Ubuntu 22.04".to_string(),
                fixed_in: Some("22.04.1".to_string()),
            },
        ]);
        
        db.add_cve("debian".to_string(), vec![
            CveEntry {
                id: "CVE-2023-11111".to_string(),
                severity: Severity::Low,
                description: "Minor OpenSSL version issue in Debian 12".to_string(),
                fixed_in: Some("12.4".to_string()),
            },
        ]);
        
        db.add_cve("python".to_string(), vec![
            CveEntry {
                id: "CVE-2023-22222".to_string(),
                severity: Severity::Critical,
                description: "Python interpreter security issue affecting many distros".to_string(),
                fixed_in: Some("3.11.5".to_string()),
            },
        ]);
        
        db.add_cve("node".to_string(), vec![
            CveEntry {
                id: "CVE-2023-33333".to_string(),
                severity: Severity::Medium,
                description: "Node.js HTTP parser vulnerability".to_string(),
                fixed_in: Some("20.10.0".to_string()),
            },
        ]);
        
        db.add_cve("nginx".to_string(), vec![
            CveEntry {
                id: "CVE-2023-44444".to_string(),
                severity: Severity::High,
                description: "Nginx request smuggling vulnerability".to_string(),
                fixed_in: Some("1.25.3".to_string()),
            },
        ]);
        
        db.add_cve("redis".to_string(), vec![
            CveEntry {
                id: "CVE-2023-55555".to_string(),
                severity: Severity::Medium,
                description: "Redis AUTH command injection issue".to_string(),
                fixed_in: Some("7.2.4".to_string()),
            },
        ]);
        
        db.add_cve("postgres".to_string(), vec![
            CveEntry {
                id: "CVE-2023-66666".to_string(),
                severity: Severity::High,
                description: "PostgreSQL authentication bypass vulnerability".to_string(),
                fixed_in: Some("15.4".to_string()),
            },
        ]);
        
        db.add_cve("mysql".to_string(), vec![
            CveEntry {
                id: "CVE-2023-77777".to_string(),
                severity: Severity::Critical,
                description: "MySQL privilege escalation issue".to_string(),
                fixed_in: Some("8.0.36".to_string()),
            },
        ]);
        
        db.add_cve("mongo".to_string(), vec![
            CveEntry {
                id: "CVE-2023-88888".to_string(),
                severity: Severity::Medium,
                description: "MongoDB shell injection vulnerability".to_string(),
                fixed_in: Some("7.0.6".to_string()),
            },
        ]);
        
        db.add_cve("rust".to_string(), vec![
            CveEntry {
                id: "CVE-2023-99999".to_string(),
                severity: Severity::Low,
                description: "Rust compiler minor security fix".to_string(),
                fixed_in: Some("1.75.0".to_string()),
            },
        ]);
        
        db.add_cve("golang".to_string(), vec![
            CveEntry {
                id: "CVE-2023-101010".to_string(),
                severity: Severity::Medium,
                description: "Go runtime HTTP server vulnerability".to_string(),
                fixed_in: Some("1.21.4".to_string()),
            },
        ]);
        
        db.add_cve("java".to_string(), vec![
            CveEntry {
                id: "CVE-2023-111111".to_string(),
                severity: Severity::High,
                description: "OpenJDK JMX remote code execution issue".to_string(),
                fixed_in: Some("17.0.9".to_string()),
            },
        ]);
        
        db.add_cve("dotnet".to_string(), vec![
            CveEntry {
                id: "CVE-2023-121212".to_string(),
                severity: Severity::Medium,
                description: ".NET runtime memory corruption fix".to_string(),
                fixed_in: Some("8.0.7".to_string()),
            },
        ]);
        
        db.add_cve("php".to_string(), vec![
            CveEntry {
                id: "CVE-2023-131313".to_string(),
                severity: Severity::High,
                description: "PHP GD library buffer overflow".to_string(),
                fixed_in: Some("8.2.9".to_string()),
            },
        ]);
        
        db.add_cve("ruby".to_string(), vec![
            CveEntry {
                id: "CVE-2023-141414".to_string(),
                severity: Severity::Medium,
                description: "Ruby OpenSSL version negotiation issue".to_string(),
                fixed_in: Some("3.2.2".to_string()),
            },
        ]);
        
        db.add_cve("perl".to_string(), vec![
            CveEntry {
                id: "CVE-2023-151515".to_string(),
                severity: Severity::Low,
                description: "Perl HTTP client header injection fix".to_string(),
                fixed_in: Some("5.38.2".to_string()),
            },
        ]);
        
        db.add_cve("haskell".to_string(), vec![
            CveEntry {
                id: "CVE-2023-161616".to_string(),
                severity: Severity::Low,
                description: "GHC compiler stack overflow in large projects".to_string(),
                fixed_in: Some("9.4.5".to_string()),
            },
        ]);
        
        db.add_cve("elixir".to_string(), vec![
            CveEntry {
                id: "CVE-2023-171717".to_string(),
                severity: Severity::Medium,
                description: "Elixir runtime memory leak fix".to_string(),
                fixed_in: Some("1.16.4".to_string()),
            },
        ]);
        
        db.add_cve("scala".to_string(), vec![
            CveEntry {
                id: "CVE-2023-181818".to_string(),
                severity: Severity::Low,
                description: "Scala compiler parallel compilation issue".to_string(),
                fixed_in: Some("3.3.1".to_string()),
            },
        ]);
        
        db.add_cve("kotlin".to_string(), vec![
            CveEntry {
                id: "CVE-2023-191919".to_string(),
                severity: Severity::Medium,
                description: "Kotlin compiler NPE in certain scenarios".to_string(),
                fixed_in: Some("1.9.21".to_string()),
            },
        ]);
        
        db.add_cve("swift".to_string(), vec![
            CveEntry {
                id: "CVE-2023-202020".to_string(),
                severity: Severity::Low,
                description: "SwiftPM dependency resolution edge case".to_string(),
                fixed_in: Some("5.9.1".to_string()),
            },
        ]);
        
        db.add_cve("zig".to_string(), vec![
            CveEntry {
                id: "CVE-2023-212121".to_string(),
                severity: Severity::Medium,
                description: "Zig compiler optimization bug".to_string(),
                fixed_in: Some("0.12.