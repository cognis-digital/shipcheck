use std::collections::HashMap;
use std::env;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process;

/// Configuration for layer size estimation
struct Config {
    /// Default overhead per RUN instruction (apt-get/dnf cache + metadata)
    run_overhead: u64,
    /// Overhead per COPY/ADD (metadata, directory creation)
    copy_overhead: u64,
    /// Minimum file size to report for COPY/ADD
    min_file_size: u64,
    /// Warning threshold in bytes
    warning_threshold: u64,
    /// Critical threshold in bytes
    critical_threshold: u64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            run_overhead: 50_000_000,      // ~50MB per RUN
            copy_overhead: 1024,           // ~1KB metadata
            min_file_size: 1024 * 1024,    // 1MB minimum to report
            warning_threshold: 100_000_000, // 100MB warning
            critical_threshold: 500_000_000, // 500MB critical
        }
    }
}

/// Represents a parsed Dockerfile instruction with its estimated size impact
struct Layer {
    line_number: usize,
    instruction: String,
    raw_line: String,
    estimated_size_bytes: u64,
    file_count: u32,
    notes: Vec<String>,
}

/// Result of parsing a Dockerfile
pub struct ParseResult {
    layers: Vec<Layer>,
    total_size_estimate: u64,
    warnings: Vec<(usize, String)>,
    criticals: Vec<(usize, String)>,
}

impl ParseResult {
    pub fn new() -> Self {
        Self {
            layers: Vec::new(),
            total_size_estimate: 0,
            warnings: Vec::new(),
            criticals: Vec::new(),
        }
    }

    pub fn with_layers(mut self, layers: Vec<Layer>) -> Self {
        let mut total = 0;
        for layer in &layers {
            total += layer.estimated_size_bytes;
        }
        self.total_size_estimate = total;
        self.layers = layers;
        self
    }

    pub fn with_warning(mut self, line: usize, msg: String) -> Self {
        self.warnings.push((line, msg));
        self
    }

    pub fn with_critical(mut self, line: usize, msg: String) -> Self {
        self.criticals.push((line, msg));
        self
    }
}

/// Estimate size contribution of a single instruction
fn estimate_instruction_size(
    instruction: &str,
    args: &str,
    config: &Config,
) -> (u64, u32, Vec<String>) {
    let mut notes = Vec::new();
    
    // FROM - starts fresh layer
    if instruction.to_uppercase() == "FROM" {
        return (10_000, 0, vec!["Base image layer".to_string()]);
    }

    // COPY/ADD - extract file sizes from args
    let mut file_size = config.copy_overhead;
    let mut files = 0u32;
    
    if instruction.to_uppercase() == "COPY" || instruction.to_uppercase() == "ADD" {
        // Parse source paths and estimate sizes
        let parts: Vec<&str> = args.split_whitespace().collect();
        
        for part in &parts[1..] {
            // Check if this looks like a file path (not a flag)
            if !part.starts_with('-') && !part.contains(':') || 
               part.contains('/') {
                files += 1;
                
                // Estimate file size based on common patterns
                let estimated = if part.contains("tar") || part.contains("gz") {
                    // Archives are compressed, estimate decompressed size
                    match part.split('.').last() {
                        Some("tar.gz") | Some("tgz") => *part.len() as u64 * 3,
                        Some("tar") => *part.len() as u64 * 5,
                        _ => *part.len() as u64 * 2,
                    }
                } else if part.contains("deb") || part.contains("rpm") {
                    // Package files - estimate based on common sizes
                    match part.split('.').last() {
                        Some("deb") | Some("rpm") => 5_000_000,
                        _ => *part.len() as u64 * 2,
                    }
                } else if part.contains("curl") || part.contains("wget") {
                    // Downloaded content - estimate from URL length hint
                    match part.split('.').last() {
                        Some(ext) if ext == "gz" | ext == "bz2" => *part.len() as u64 * 10,
                        _ => *part.len() as u64 * 5,
                    }
                } else {
                    // Regular file - estimate from path length hint
                    part.len() as u64 * 3
                };
                
                file_size += estimated;
            }
        }
        
        return (file_size.max(10_000), files, vec!["COPY/ADD layer".to_string()]);
    }

    // RUN - command execution overhead
    if instruction.to_uppercase() == "RUN" {
        let estimated = config.run_overhead;
        
        // Check for common patterns that add significant size
        let mut cmd_notes = vec!["RUN layer".to_string()];
        
        if args.contains("apt-get install") || args.contains("dnf install") {
            cmd_notes.push("Package manager install - adds cache + packages".to_string());
        } else if args.contains("apk add") {
            cmd_notes.push("Alpine package manager".to_string());
        } else if args.contains("yum install") {
            cmd_notes.push("RHEL/CentOS package manager".to_string());
        } else if args.contains("pip install") || args.contains("npm install") || 
                  args.contains("cargo add") {
            cmd_notes.push("Language dependency installation - may add significant size".to_string());
        } else if args.contains("curl") || args.contains("wget") {
            cmd_notes.push("Network download - consider caching or multi-stage build".to_string());
        } else if args.contains(".tar.gz") || args.contains(".tgz") {
            cmd_notes.push("Archives included - consider extracting in RUN then copying only needed files".to_string());
        }

        return (estimated, 0, cmd_notes);
    }

    // ENV/ARG/LABEL - minimal overhead
    if instruction.to_uppercase() == "ENV" || 
       instruction.to_uppercase() == "ARG" ||
       instruction.to_uppercase() == "LABEL" {
        let estimated = if args.len() > 50 { 1_000 } else { 256 };
        return (estimated, 0, vec!["Metadata layer".to_string()]);
    }

    // WORKDIR/USER/EXPOSE - negligible
    if instruction.to_uppercase() == "WORKDIR" || 
       instruction.to_uppercase() == "USER" ||
       instruction.to_uppercase() == "EXPOSE" {
        return (256, 0, vec!["Metadata layer".to_string()]);
    }

    // Default - estimate from line length
    let estimated = args.len().max(1) as u64 * 3;
    return (estimated, 0, vec!["Unknown/Other layer".to_string()]);
}

/// Parse a Dockerfile and calculate layer sizes
pub fn parse_dockerfile(path: &Path, config: Option<&Config>) -> ParseResult {
    let cfg = config.unwrap_or(&Config::default());
    
    let mut result = ParseResult::new();
    let mut total_size = 0u64;
    
    // Read file content first to handle multi-line commands
    let content = fs::read_to_string(path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();
    
    for (line_num, line) in lines.iter().enumerate() {
        let line_num = line_num + 1;
        
        // Skip empty lines and comments
        if line.trim().is_empty() || line.trim().starts_with('#') {
            continue;
        }

        // Handle multi-line commands (like pip install, curl | tar)
        let mut current_line = String::new();
        let mut is_continuation = false;
        
        for ch in line.chars() {
            if ch == '\\' && !is_continuation {
                // Line continuation - peek at next line
                if line_num < lines.len() - 1 {
                    current_line.push(ch);
                    is_continuation = true;
                    
                    let next_line = lines[line_num + 1].trim();
                    if !next_line.is_empty() && !next_line.starts_with('#') {
                        current_line.push_str(next_line.trim());
                    } else {
                        // End of continuation
                        break;
                    }
                } else {
                    current_line.push(ch);
                }
            } else {
                current_line.push(ch);
            }
        }
        
        let trimmed = current_line.trim();
        if !trimmed.is_empty() && !trimmed.starts_with('#') {
            // Parse instruction and arguments
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            
            if parts.is_empty() || parts[0].is_empty() {
                continue;
            }

            let instruction = parts[0];
            let args = if parts.len() > 1 { &parts[1..].join(" ") } else { "" };
            
            // Estimate size for this layer
            let (size, files, notes) = estimate_instruction_size(instruction, args, cfg);
            
            // Check thresholds
            if size >= cfg.critical_threshold {
                result.with_critical(line_num, format!(
                    "Large layer detected: {} bytes",
                    human_readable(size)
                ));
            } else if size >= cfg.warning_threshold {
                result.with_warning(line_num, format!(
                    "Consider optimizing this layer: {}",
                    instruction
                ));
            }

            // Add to total
            total_size += size;
            
            let mut layer = Layer {
                line_number: line_num,
                instruction: instruction.to_string(),
                raw_line: trimmed.to_string(),
                estimated_size_bytes: size,
                file_count: files,
                notes,
            };

            // Add notes to result if any warnings/criticals in this layer
            for note in &notes {
                if !note.is_empty() && 
                   (size >= cfg.warning_threshold || note.contains("consider") || 
                    note.contains("optimize")) {
                    let warning_msg = format!("Layer {}: {}", line_num, note);
                    result.with_warning(line_num, warning_msg);
                }
            }

            result.layers.push(layer);
        }
        
        current_line.clear();
        is_continuation = false;
    }

    // Sort layers by line number (should already be sorted, but ensure it)
    result.layers.sort_by_key(|l| l.line_number);

    result.with_layers(result.layers)
}

/// Format bytes into human-readable format
fn human_readable(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * 1024 * 1024;

    if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

/// Summary report for a ParseResult
pub fn summary_report(result: &ParseResult, config: &Config) -> String {
    let mut output = String::new();
    
    output.push_str(&format!(
        "=== Layer Size Analysis\n{}\n",
        "=".repeat(40)
    ));

    // Overall statistics
    output.push_str(&format!("Total estimated size: {}\n", human_readable(result.total_size_estimate)));
    output.push_str(&format!("Number of layers: {}\n\n", result.layers.len()));

    if !result.layers.is_empty() {
        // Layer-by-layer breakdown (top 20 by size)
        let mut sorted_layers = &mut result.layers.clone();
        sorted_layers.sort_by(|a, b| b.estimated_size_bytes.cmp(&a.estimated_size_bytes));
        
        output.push_str("Layer Breakdown:\n");
        output.push_str("-".repeat(40).as_str());

        let display_count = std::cmp::min(sorted_layers.len(), 20);
        for (i, layer) in sorted_layers.iter().take(display_count).enumerate() {
            let rank = i + 1;
            let pct = if result.total_size_estimate > 0 {
                format!("{:.1}%", 
                    (layer.estimated_size_bytes as f64 / result.total_size_estimate as f64) * 100.0)
            } else {
                "N/A".to_string()
            };

            output.push_str(&format!(
                "\n{}: {} ({})\n",
                rank,
                layer.instruction,
                human_readable(layer.estimated_size_bytes)
            ));
            
            if !layer.notes.is_empty() {
                for note in &layer.notes {
                    output.push_str(&format!("  • {}\n", note));
                }
            }

            // Highlight large layers
            if layer.estimated_size_bytes >= config.warning_threshold {
                output.push_str("    ⚠️  Large layer - consider optimization\n");
            } else if layer.estimated_size_bytes >= config.critical_threshold {
                output.push_str("    🔴 Critical size!\n");
            }
        }

        if sorted_layers.len() > 20 {
            output.push_str(&format!("\n... and {} more layers\n", 
                sorted_layers.len() - 20));
        }
    }

    // Warnings summary
    if !result.warnings.is_empty() {
        output.push_str(&format!(
            "\n=== Warnings ({}) ===\n",
            result.warnings.len()
        ));
        for (line, msg) in &result.warnings {
            output.push_str(&format!("Line {}: {}\n", line, msg));
        }
    }

    // Criticals summary
    if !result.criticals.is_empty() {
        output.push_str(&format!(
            "\n=== Critical Issues ({}) ===\n",
            result.criticals.len()
        ));
        for (line, msg) in &result.criticals {
            output.push_str(&format!("Line {}: {}\n", line, msg));
        }
    }

    // Recommendations
    if !result.warnings.is_empty() || !result.criticals.is_empty() {
        output.push_str("\n=== Recommendations ===\n");
        
        let mut recommendations = Vec::new();
        
        if result.layers.iter().any(|l| l.estimated_size_bytes >= config.warning_threshold) {
            recommendations.push("Consider using multi-stage builds to reduce final image size".to_string());
        }
        
        if result.layers.iter().any(|l| l.instruction == "RUN") {
            recommendations.push("Combine RUN commands when possible to reduce layer count".to_string());
        }
        
        if result.layers.iter().any(|l| l.file_count > 0) {
            recommendations.push("Use COPY --from=previous_stage for dependencies instead of copying from host".to_string());
        }

        for rec in &recommendations {
            output.push_str(&format!("• {}\n", rec));
        }
    }

    output
}

/// Write summary to a file
pub fn write_report(result: &ParseResult, config: &Config, path: &Path) -> std::io::Result<()> {
    let report = summary_report(result, config);
    
    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    
    File::create(path)?.write_all(report.as_bytes())?;
    Ok(())
}

/// Main entry point for the tool
pub fn main() -> std::io::Result<()> {