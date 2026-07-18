#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <optional>
#include <algorithm>
#include <cctype>
#include <filesystem>

namespace fs = std::filesystem;

// Forward declarations
class DockerfileParser;

// Structure to hold parsed image information from FROM instructions
struct ImageInfo {
    std::string repository;  // e.g., "ubuntu" or "library/ubuntu"
    std::string tag;         // e.g., "20.04", "latest", or empty for digest
    std::string digest;      // e.g., "sha256:abc123..."
    bool is_digest = false;  // true if using @digest syntax
    
    std::string get_full_name() const {
        if (is_digest) return repository + "@" + digest;
        if (!tag.empty()) return repository + ":" + tag;
        return repository;
    }
};

// Structure to hold CVE advisory information
struct CveAdvisory {
    std::string cve_id;      // e.g., "CVE-2024-1234"
    std::string package;     // affected package name
    std::string version;     // vulnerable version range
    std::string severity;    // LOW, MEDIUM, HIGH, CRITICAL
    int cvss_score = 0;
    std::string url;         // advisory URL
    
    bool operator<(const CveAdvisory& other) const {
        return cve_id < other.cve_id;
    }
};

// Structure to hold the complete parsed Dockerfile state
struct ParsedDockerfile {
    std::vector<ImageInfo> images;
    std::map<std::string, CveAdvisory> advisories;  // keyed by CVE ID
    
    // Get all image names for quick lookup
    std::vector<std::string> get_all_image_names() const {
        std::vector<std::string> result;
        for (const auto& img : images) {
            result.push_back(img.get_full_name());
        }
        return result;
    }
    
    // Get total number of base images used
    size_t get_image_count() const {
        return images.size();
    }
};

// State machine for parsing multi-line commands (backslash continuation)
enum class ParseState {
    NORMAL,
    CONTINUATION,  // Line ends with backslash
    COMMENT,       // Pure comment line
    EMPTY          // Empty or whitespace-only line
};

class DockerfileParser {
private:
    std::string filename;
    ParsedDockerfile result;
    
    ParseState current_state = ParseState::NORMAL;
    std::string continuation_buffer;  // For handling backslash continuations
    
    // Helper to trim whitespace from both ends of a string
    static std::string trim(const std::string& s) {
        auto start = s.find_first_not_of(" \t\r\n");
        if (start == std::string::npos) return "";
        
        auto end = s.find_last_not_of(" \t\r\n");
        return s.substr(start, end - start + 1);
    }
    
    // Check if a line is purely a comment
    static bool is_comment_line(const std::string& line) {
        auto trimmed = trim(line);
        return !trimmed.empty() && trimmed[0] == '#';
    }
    
    // Check if a line ends with backslash continuation
    static bool has_continuation(const std::string& line) {
        auto trimmed = trim(line);
        return !trimmed.empty() && 
               trimmed.back() == '\\' && 
               (trimmed.size() >= 2 || trimmed[trimmed.size()-1] != '\\');
    }
    
    // Extract the command part, removing trailing backslash if present
    static std::string extract_command(const std::string& line) {
        auto trimmed = trim(line);
        if (!trimmed.empty() && trimmed.back() == '\\' && 
            (trimmed.size() >= 2 || trimmed[trimmed.size()-1] != '\\')) {
            return trimmed.substr(0, trimmed.size() - 1);
        }
        return trimmed;
    }
    
    // Tokenize a command line into parts
    static std::vector<std::string> tokenize(const std::string& cmd) {
        std::vector<std::string> tokens;
        std::istringstream iss(cmd);
        std::string token;
        
        while (iss >> token) {
            // Handle quoted strings - keep them intact
            if ((token.front() == '\'' || token.front() == '"') && 
                token.back() == token.front()) {
                tokens.push_back(token);
            } else {
                std::istringstream tss(token);
                while (tss >> token) {
                    tokens.push_back(token);
                }
            }
        }
        
        return tokens;
    }

public:
    explicit DockerfileParser(const std::string& fname = "") 
        : filename(fname), result() {}
    
    // Parse a Dockerfile from file path or string content
    ParsedDockerfile parse(const std::string& content) {
        if (filename.empty()) {
            return parse_content(content);
        } else {
            return parse_file(filename, content);
        }
    }

private:
    ParsedDockerfile parse_content(const std::string& content) {
        auto lines = split_into_lines(content);
        
        for (const auto& line : lines) {
            ParseState next_state = ParseState::NORMAL;
            
            if (is_comment_line(line)) {
                next_state = ParseState::COMMENT;
            } else if (line.empty() || trim(line).empty()) {
                next_state = ParseState::EMPTY;
            } else if (has_continuation(line)) {
                next_state = ParseState::CONTINUATION;
            }
            
            // Process the line content (without trailing backslash for continuation)
            std::string cmd = extract_command(line);
            
            if (!cmd.empty()) {
                process_line(cmd, next_state);
            }
        }
        
        return result;
    }

    ParsedDockerfile parse_file(const std::string& fname, const std::string& content) {
        // First try to read from file system
        if (!fs::exists(fname)) {
            // Fall back to treating as content string
            return parse_content(content);
        }
        
        auto data = fs::read_text_file(fname).value_or("");
        return parse_content(data);
    }

    std::vector<std::string> split_into_lines(const std::string& text) {
        std::vector<std::string> lines;
        std::istringstream iss(text);
        std::string line;
        
        while (std::getline(iss, line)) {
            // Normalize line endings
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            lines.push_back(line);
        }
        
        return lines;
    }

    void process_line(const std::string& cmd, ParseState state) {
        auto tokens = tokenize(cmd);
        if (tokens.empty()) return;
        
        // Handle FROM instruction - most important for image analysis
        if (std::toupper(tokens[0]) == "FROM") {
            parse_from_instruction(tokens);
            return;
        }
        
        // Note other instructions that might affect CVE scanning
        if (is_relevant_for_cve(tokens)) {
            result.images.push_back(ImageInfo{
                .repository = "other",  // Placeholder for non-FROM images
                .tag = "",
                .digest = ""
            });
        }
    }

    bool is_relevant_for_cve(const std::vector<std::string>& tokens) {
        static const std::vector<std::string> relevant_ops = {
            "RUN", "COPY", "ADD", "ENV", "ARG"
        };
        
        for (const auto& op : relevant_ops) {
            if (std::toupper(tokens[0]) == op) return true;
        }
        return false;
    }

    void parse_from_instruction(const std::vector<std::string>& tokens) {
        // FROM syntax: FROM [ARG] image[:tag][@digest] [AS stage-name]
        
        if (tokens.size() < 2) return;
        
        ImageInfo info;
        
        // Check for AS clause (stage name) - skip it
        bool found_as = false;
        size_t as_pos = std::string::npos;
        
        for (size_t i = 1; i < tokens.size(); ++i) {
            if (std::toupper(tokens[i]) == "AS") {
                found_as = true;
                as_pos = i;
                break;
            }
        }
        
        // Extract image reference (everything between FROM and AS, or end of line)
        size_t start = 1;
        if (!found_as) {
            start = 0;
        } else {
            start = as_pos + 1;
        }
        
        std::string image_ref;
        for (size_t i = start; i < tokens.size(); ++i) {
            // Check if this token starts with @ (digest syntax)
            if (!image_ref.empty() && 
                !std::isspace(tokens[i][0]) && 
                tokens[i].front() == '@') {
                image_ref += " ";
            }
            image_ref += tokens[i];
        }
        
        // Parse the image reference into repository, tag, digest
        parse_image_reference(image_ref, info);
        
        result.images.push_back(info);
    }

    void parse_image_reference(const std::string& ref, ImageInfo& info) {
        if (ref.empty()) return;
        
        // Check for digest syntax (@sha256:...)
        size_t at_pos = ref.find('@');
        if (at_pos != std::string::npos) {
            info.digest = ref.substr(at_pos + 1);
            info.is_digest = true;
            
            // Repository is everything before @
            auto repo_end = ref.rfind(':', at_pos - 1);
            if (repo_end == std::string::npos) {
                info.repository = ref.substr(0, at_pos);
            } else {
                info.repository = ref.substr(0, repo_end + 1);
            }
            
            return;
        }
        
        // Check for tag syntax (:tag)
        size_t colon_pos = ref.find_last_of(':');
        
        if (colon_pos != std::string::npos && 
            !ref.substr(colon_pos).empty() &&
            !std::isspace(ref[colon_pos])) {
            info.tag = ref.substr(colon_pos + 1);
            
            // Repository is everything before the last colon
            auto repo_end = ref.rfind(':', colon_pos - 1);
            if (repo_end == std::string::npos) {
                info.repository = ref;
            } else {
                info.repository = ref.substr(0, repo_end + 1);
            }
        } else {
            // No tag specified
            info.tag = "latest";
            info.repository = ref;
        }
    }

public:
    // Get parsed results
    ParsedDockerfile get_results() const {
        return result;
    }
    
    // Check if a specific image is in the Dockerfile
    bool contains_image(const std::string& full_name) const {
        for (const auto& img : result.images) {
            if (img.get_full_name() == full_name || 
                img.repository == full_name) {
                return true;
            }
        }
        return false;
    }
    
    // Get unique image names (deduplicated by repository:tag)
    std::vector<std::string> get_unique_images() const {
        std::map<std::string, bool> seen;  // second value tracks if digest was used
        std::vector<std::string> unique;
        
        for (const auto& img : result.images) {
            std::string key = img.get_full_name();
            
            // Consider images with same repo:tag as duplicates unless one uses digest
            bool is_duplicate = seen.count(key);
            if (!is_duplicate || !seen[key]) {
                unique.push_back(key);
                seen[key] = img.is_digest;
            }
        }
        
        return unique;
    }
    
    // Get total size estimate (simplified - would need registry API for real data)
    std::string get_size_estimate() const {
        if (result.images.empty()) {
            return "Unknown";
        }
        
        // This is a placeholder - in production you'd query registries
        // For now, just report count and note it needs external lookup
        return fmt("Base images: {} (requires registry API for exact sizes)", 
                   result.get_image_count());
    }

private:
    std::string format(const char* fmt, const std::string& s) {
        return fmt + " " + s;  // Simple wrapper - replace with proper formatting if needed
    }
};

// Global instance for command-line tool usage
DockerfileParser g_parser;

void print_usage(const char* prog_name) {
    std::cout << "Usage: " << prog_name << " [OPTIONS] <dockerfile> | <content>\n"
              << "\n"
              << "Options:\n"
              << "  -h, --help     Show this help message\n"
              << "  -v, --verbose  Verbose output with all images found\n"
              << "  -s, --size     Show size estimates (requires network)\n"
              << "\n"
              << "Examples:\n"
              << "  " << prog_name << " Dockerfile\n"
              << "  " << prog_name << " -v Dockerfile\n"
              << "  echo 'FROM ubuntu:20.04' | " << prog_name << " --stdin\n";
}

void print_parsed_results(const ParsedDockerfile& parsed, bool verbose = false) {
    std::cout << "\n=== Parsed Dockerfile Results ===\n\n";
    
    if (parsed.images.empty()) {
        std::cout << "No FROM instructions found.\n";
        return;
    }
    
    std::cout << "Found " << parsed.get_image_count() << " base image(s):\n\n";
    
    for (size_t i = 0; i < parsed.images.size(); ++i) {
        const auto& img = parsed.images[i];
        
        std::string prefix = (i == 0) ? "[1st]" : 
                           ((i == parsed.get_image_count() - 1) ? "[Last]" : "[Nth]");
        
        std::cout << "  " << prefix << " " << img.get_full_name();
        
        if (!img.tag.empty()) {
            std::cout << " (tag: " << img.tag << ")";
        }
        
        if (img.is_digest) {
            std::cout << " (digest: " << img.digest.substr(0, 12) + "...") << ")";
        }
        
        std::cout << "\n";
    }
    
    if (!parsed.advisories.empty()) {
        std::cout << "\n--- CVE Advisories Found ---\n";
        for (const auto& [cve_id, advisory] : parsed.advisories) {
            std::cout << "  " << cve_id << ": " 
                      << advisory.severity << " - " << advisory.package;
            if (!advisory.version.empty()) {
                std::cout << " <" << advisory.version << ">";
            }
            std::cout << "\n    URL: " << advisory.url << "\n";
        }
    } else {
        std::cout << "\n--- CVE Advisories ---\n  None found yet (requires external data fetch)\n";
    }
    
    if (!verbose) {
        std::cout << "\n" << parsed.get_size_estimate() << "\n";
    }
}

// Simple function to fetch image size from Docker Hub registry
std::string fetch_image_size(const std::string& repo, const std::string& tag = "latest") {
    // This would make a real HTTP request in production
    // For demo purposes, return a placeholder
    
    // Common sizes for reference:
    if (repo == "ubuntu" && tag == "20.04") {
        return "756 MB";
    } else if (repo == "alpine" && tag == "3.18") {
        return "56