#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <map>
#include <iomanip>
#include <algorithm>
#include <cctype>

namespace shipcheck {

// ============================================================================
// Configuration and Constants
// ============================================================================

constexpr size_t DEFAULT_BUFFER_SIZE = 4096;
constexpr double APTGET_BASE_OVERHEAD_MB = 15.0;
constexpr double NPM_INSTALL_ESTIMATE_MB = 200.0;
constexpr double PIP_INSTALL_ESTIMATE_MB = 150.0;

// ============================================================================
// Utility Functions
// ============================================================================

std::string trim(const std::string& str) {
    auto start = str.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    auto end = str.find_last_not_of(" \t\r\n");
    return str.substr(start, end - start + 1);
}

std::vector<std::string> tokenize(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string token;
    
    while (iss >> token) {
        // Remove inline comments
        size_t commentPos = token.find('#');
        if (commentPos != std::string::npos) {
            token.erase(commentPos);
        }
        
        // Trim whitespace from ends
        auto start = token.find_first_not_of(" \t");
        auto end = token.find_last_not_of(" \t");
        if (start != std::string::npos && end != std::string::npos) {
            tokens.push_back(token.substr(start, end - start + 1));
        } else if (!token.empty()) {
            tokens.push_back(token);
        }
    }
    
    return tokens;
}

// ============================================================================
// Size Estimator for Common Commands
// ============================================================================

struct LayerEstimate {
    std::string command;
    double estimatedSizeMB = 0.0;
    bool isApproximation = true;
};

LayerEstimate estimateCommand(const std::vector<std::string>& tokens) {
    if (tokens.empty()) return {{}, 0.0, false};
    
    const std::string cmd = trim(tokens[0]);
    LayerEstimate result{cmd, 0.0, true};
    
    // apt-get install/uninstall
    if (cmd.find("apt-get") != std::string::npos) {
        if (cmd.find("install") != std::string::npos) {
            result.estimatedSizeMB = APTGET_BASE_OVERHEAD_MB + 50.0;
        } else if (cmd.find("remove") != std::string::npos || 
                   cmd.find("purge") != std::string::npos) {
            result.estimatedSizeMB = -20.0; // Negative for removal
        }
    }
    
    // npm install
    else if (cmd == "npm" && tokens.size() > 1 && tokens[1] == "install") {
        result.estimatedSizeMB = NPM_INSTALL_ESTIMATE_MB;
    }
    
    // pip install
    else if (cmd == "pip" || cmd == "python3-pip") {
        if (cmd.find("install") != std::string::npos) {
            result.estimatedSizeMB = PIP_INSTALL_ESTIMATE_MB;
        }
    }
    
    // yarn install
    else if (cmd == "yarn" && tokens.size() > 1 && tokens[1] == "install") {
        result.estimatedSizeMB = NPM_INSTALL_ESTIMATE_MB * 0.8;
    }
    
    // go get / mod tidy
    else if (cmd.find("go") != std::string::npos) {
        if (cmd.find("get") != std::string::npos || cmd.find("mod tidy") != std::string::npos) {
            result.estimatedSizeMB = 50.0;
        }
    }
    
    // ruby gems
    else if (cmd == "gem" && tokens.size() > 1 && tokens[1] == "install") {
        result.estimatedSizeMB = 30.0;
    }
    
    // rust cargo
    else if (cmd == "cargo" && tokens.size() > 1 && tokens[1] == "add") {
        result.estimatedSizeMB = 25.0;
    }
    
    return result;
}

// ============================================================================
// Dockerfile Parser and Layer Builder
// ============================================================================

struct DockerLayer {
    std::string baseImage;
    std::vector<LayerEstimate> commands;
    double totalEstimatedSizeMB = 0.0;
    bool isMultiStage = false;
};

class LayerBuilder {
public:
    LayerBuilder() : currentLayer{}, currentBaseImage{} {}
    
    void startNewLayer(const std::string& base) {
        if (!currentBaseImage.empty()) {
            finalizeCurrent();
        }
        
        currentBaseImage = base;
        currentLayer.baseImage = base;
        currentLayer.totalEstimatedSizeMB = 0.0;
    }
    
    void addCommand(const LayerEstimate& estimate) {
        currentLayer.commands.push_back(estimate);
        if (estimate.estimatedSizeMB > 0) {
            currentLayer.totalEstimatedSizeMB += estimate.estimatedSizeMB;
        } else if (estimate.estimatedSizeMB < 0) {
            // Removal - reduce total but keep positive for display
            double newTotal = currentLayer.totalEstimatedSizeMB + estimate.estimatedSizeMB;
            currentLayer.totalEstimatedSizeMB = std::max(1.0, newTotal);
        }
    }
    
    void finalizeCurrent() {
        if (!currentBaseImage.empty()) {
            layers.push_back(currentLayer);
        }
    }
    
    void markMultiStage() {
        currentLayer.isMultiStage = true;
    }
    
    const std::vector<DockerLayer>& getLayers() const {
        return layers;
    }
    
private:
    DockerLayer currentLayer;
    std::string currentBaseImage;
    std::vector<DockerLayer> layers;
};

// ============================================================================
// Main Parser Class
// ============================================================================

class DockerfileParser {
public:
    explicit DockerfileParser(const std::string& content) 
        : content_(content), layerBuilder_() {}
    
    void parse() {
        // Split into lines
        std::vector<std::string> lines;
        std::istringstream stream(content_);
        
        while (std::getline(stream, line)) {
            if (!line.empty()) {
                lines.push_back(line);
            }
        }
        
        parseLines(lines);
    }
    
    const LayerBuilder& getLayerBuilder() const {
        return layerBuilder_;
    }
    
private:
    std::string content_;
    std::vector<std::string> lines_;
    LayerBuilder layerBuilder_;
    
    void parseLines(const std::vector<std::string>& lines) {
        for (const auto& line : lines) {
            auto tokens = tokenize(line);
            
            if (tokens.empty()) continue;
            
            const std::string cmd = trim(tokens[0]);
            
            // Handle FROM instruction
            if (cmd == "FROM") {
                if (tokens.size() >= 2) {
                    layerBuilder_.startNewLayer(trim(tokens[1]));
                    
                    // Check for multi-stage build
                    size_t fromPos = line.find("FROM");
                    size_t nextFromPos = line.find("FROM", fromPos + 4);
                    if (nextFromPos != std::string::npos) {
                        layerBuilder_.markMultiStage();
                    }
                } else {
                    // No base image specified, treat as continuation
                    continue;
                }
            }
            
            // Handle ARG, ENV, LABEL - metadata, not layers
            else if (cmd == "ARG" || cmd == "ENV" || cmd == "LABEL") {
                continue;
            }
            
            // Handle COPY and ADD
            else if (cmd == "COPY" || cmd == "ADD") {
                LayerEstimate estimate = {{}, 0.0, false};
                
                // Estimate based on source paths
                for (size_t i = 1; i < tokens.size(); ++i) {
                    const std::string& src = trim(tokens[i]);
                    
                    if (src.find("http://") == 0 || src.find("https://") == 0) {
                        estimate.estimatedSizeMB += 5.0; // HTTP fetch overhead
                    } else if (src.find(".git") != std::string::npos) {
                        estimate.estimatedSizeMB += 100.0; // Git repo
                    } else if (src.find("node_modules") == 0 || 
                               src.find("vendor/") == 0 ||
                               src.find("lib/") == 0) {
                        estimate.estimatedSizeMB += 200.0; // Dependency directories
                    }
                }
                
                layerBuilder_.addCommand(estimate);
            }
            
            // Handle RUN commands
            else if (cmd == "RUN") {
                LayerEstimate estimate = estimateCommand(tokens);
                layerBuilder_.addCommand(estimate);
            }
            
            // Handle other instructions - add small overhead for shell processing
            else if (cmd != "FROM" && cmd != "ARG" && cmd != "ENV" && 
                     cmd != "LABEL" && cmd != "COPY" && cmd != "ADD") {
                LayerEstimate estimate = {{}, 0.5, true}; // Shell overhead
                layerBuilder_.addCommand(estimate);
            }
        }
        
        // Finalize any remaining layer
        layerBuilder_.finalizeCurrent();
    }
    
    std::string line;
};

// ============================================================================
// Output Formatters
// ============================================================================

std::string formatSize(double mb) {
    if (mb < 1.0) return std::to_string(mb * 1024) + " KB";
    if (mb < 1024.0) return std::to_string(mb) + " MB";
    
    double gb = mb / 1024.0;
    if (gb >= 1024.0) {
        double tb = gb / 1024.0;
        return std::to_string(tb) + " TB";
    }
    
    return std::to_string(gb) + " GB";
}

void printLayerSummary(const LayerBuilder& builder, const std::string& title = "") {
    if (title.empty()) {
        title = "Dockerfile Analysis Summary";
    }
    
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << title << "\n";
    std::cout << std::string(60, '=') << "\n\n";
    
    const auto& layers = builder.getLayers();
    
    if (layers.empty()) {
        std::cout << "No layers detected. Check that the Dockerfile was parsed correctly.\n";
        return;
    }
    
    double totalSizeMB = 0.0;
    
    for (size_t i = 0; i < layers.size(); ++i) {
        const auto& layer = layers[i];
        
        std::cout << "Layer " << (i + 1) << ": ";
        if (!layer.baseImage.empty()) {
            std::cout << "FROM " << layer.baseImage << "\n";
        } else {
            std::cout << "(continuation)\n";
        }
        
        if (layer.commands.empty()) {
            std::cout << "  [No commands]\n";
        } else {
            // Group commands by type
            std::map<std::string, int> commandCounts;
            double layerSizeMB = layer.totalEstimatedSizeMB;
            
            for (const auto& cmd : layer.commands) {
                if (!cmd.command.empty()) {
                    commandCounts[cmd.command]++;
                }
            }
            
            std::cout << "  Commands: ";
            bool first = true;
            for (const auto& [cmd, count] : commandCounts) {
                if (!first) std::cout << ", ";
                std::cout << cmd << " x" << count;
                first = false;
            }
            std::cout << "\n";
            
            // Show size breakdown for this layer
            std::cout << "  Estimated Size: " << formatSize(layerSizeMB) << "\n";
        }
        
        totalSizeMB += layer.totalEstimatedSizeMB;
    }
    
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "TOTAL ESTIMATED SIZE: " << formatSize(totalSizeMB) << "\n";
    std::cout << std::string(60, '=') << "\n\n";
}

// ============================================================================
// CVE Advisory Checker (Mock Implementation)
// ============================================================================

struct CveAdvisory {
    int id;
    std::string package;
    double severityScore; // 0-10, higher is worse
    std::string description;
};

std::vector<CveAdvisory> checkForCves(const LayerBuilder& builder) {
    std::vector<CveAdvisory> advisories;
    
    // This would integrate with real CVE databases in production
    // For now, provide a mock implementation
    
    const auto& layers = builder.getLayers();
    
    for (const auto& layer : layers) {
        if (!layer.baseImage.empty()) {
            // Check base image against known vulnerable images
            std::map<std::string, double> knownVulnerableImages;
            
            // Example: older Ubuntu/Debian versions
            if (layer.baseImage.find("ubuntu:") != std::string::npos) {
                if (layer.baseImage.find("14.04") != std::string::npos ||
                    layer.baseImage.find("16.04") != std::string::npos) {
                    advisories.push_back({1, "base-image", 7.5,
                        "Ubuntu 14/16.04 has known security issues"});
                } else if (layer.baseImage.find("20.04") == 0 || 
                           layer.baseImage.find("22.04") == 0) {
                    advisories.push_back({2, "base-image", 3.5,
                        "Ubuntu 20/22.04 is relatively secure"});
                }
            } else if (layer.baseImage.find("debian:") != std::string::npos) {
                if (layer.baseImage.find("stretch") != std::string::npos ||
                    layer.baseImage.find("jessie") != std::string::npos) {
                    advisories.push_back({3, "base-image", 6.0,
                        "Debian Stretch/Jessie has known issues"});
                } else if (layer.baseImage.find("bullseye") != std::string::npos ||
                           layer.baseImage.find("bookworm") != std::string::npos) {
                    advisories.push_back({4, "base-image", 2.5,
                        "Debian Bullseye/Bookworm is relatively secure"});
                }
            } else if (layer.baseImage == "alpine:3.10" || 
                       layer.baseImage == "alpine:3.9") {
                    advisories.push_back({5, "base-image", 4.0,
                        "Alpine 3.9/3.10 had some security issues"});
                } else if (layer.baseImage.find("alpine:") != std::string::npos) {
                    advisories.push_back({6, "base-image", 2.0,
                        "Newer Alpine versions are secure"});
            }
        }
        
        // Check for common vulnerable packages in RUN commands
        for (const auto& cmd : layer.commands) {
            if (!cmd.command.empty()) {
                std::string lowerCmd = cmd.command;
                std::transform(lowerCmd.begin(), lowerCmd.end(), 
                              lowerCmd.begin(), ::tolower);
                
                // Check apt-get install packages
                if (lowerCmd.find("apt-get") != std::string::npos &&
                    lowerCmd.find("install") != std::string::npos) {
                    
                    // Extract package names
                    size_t pos = lowerCmd.find("install");
                    if (pos != std::string::npos) {
                        std::string packagesStr = lowerCmd.substr(pos + 7);
                        
                    } else if (lowerCmd.find("npm install") != std::string::npos ||
                               lowerCmd.find("yarn add")