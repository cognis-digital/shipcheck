package polyglot.java;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Dockerfile Layer Size Calculator for shipcheck tool.
 * Parses a Dockerfile and calculates cumulative layer sizes with detailed breakdowns.
 */
public class LayerSizeCalculator {

    private static final long DEFAULT_RUN_SIZE = 1024 * 1024L; // 1MB per RUN as baseline
    private static final long DEFAULT_COPY_SIZE_ESTIMATE = 50 * 1024; // 50KB per COPY/ADD line
    private static final long DEFAULT_FROM_BASE_SIZE = 100 * 1024 * 1024L; // 100MB base image estimate

    public record LayerInfo(String instruction, String details, long size) {}

    public record Summary(long totalSize, List<LayerInfo> layers) {
        public double toMegabytes() {
            return (double) totalSize / (1024 * 1024);
        }
    }

    private static final Pattern LINE_PATTERN = Pattern.compile(
        "^\\s*(?:#\\s*|/\\*.*?\\*/\\s*)?(FROM|RUN|COPY|ADD|CMD|ENTRYPOINT|ENV|LABEL|ARG|WORKDIR|" +
        "EXPOSE|USER|VOLUME|HEALTHCHECK|SHELL|STOPSIGNAL|ONBUILD|MAINTAINER|USER|EXPOSE|" +
        "CACHED|COMMIT)\\s*(.*)$"
    );

    /**
     * Main entry point demonstrating the calculator with a sample Dockerfile.
     */
    public static void main(String[] args) throws IOException {
        // Sample Dockerfile content for demonstration
        String sampleDockerfile = 
            "# Example multi-stage build\n" +
            "FROM node:18-alpine AS builder\n" +
            "RUN apk add --no-cache yarn && yarn install\n" +
            "COPY . /app/src\n" +
            "WORKDIR /app/src\n" +
            "RUN npm run build\n" +
            "\n" +
            "# Production stage\n" +
            "FROM node:18-alpine AS production\n" +
            "WORKDIR /app\n" +
            "COPY --from=builder /app/dist/ ./dist/\n" +
            "COPY package*.json ./\n" +
            "RUN npm install --production\n" +
            "CMD [\"node\", \"dist/index.js\"]\n";

        LayerSizeCalculator calculator = new LayerSizeCalculator();
        
        System.out.println("=== ShipCheck: Dockerfile Layer Size Calculator ===\n");
        
        Summary result = calculator.calculate(sampleDockerfile);
        
        printSummary(result);
    }

    /**
     * Parses the Dockerfile and calculates layer sizes.
     */
    public Summary calculate(String dockerfileContent) {
        List<LayerInfo> layers = new ArrayList<>();
        long runningTotal = 0L;
        String currentBaseImage = "";

        for (int i = 0; i < dockerfileContent.length(); i++) {
            if (dockerfileContent.charAt(i) == '\n') {
                // Process complete line
                int start = Math.max(0, i - 1);
                while (i > 0 && Character.isWhitespace(dockerfileContent.charAt(i - 1))) {
                    i--;
                }
                
                String line = dockerfileContent.substring(start, i + 1).trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }

                Matcher matcher = LINE_PATTERN.matcher(line);
                if (!matcher.matches()) {
                    // Unknown instruction - treat as RUN with estimate
                    runningTotal += DEFAULT_RUN_SIZE;
                    layers.add(new LayerInfo("UNKNOWN", line, DEFAULT_RUN_SIZE));
                    continue;
                }

                String instruction = matcher.group(1).toUpperCase();
                String args = matcher.group(2);

                long layerSize = calculateLayerSize(instruction, args, currentBaseImage);
                
                if (instruction.equals("FROM")) {
                    runningTotal = 0L; // Fresh start
                    currentBaseImage = args.trim();
                    layers.add(new LayerInfo("FROM", "New base image: " + args, layerSize));
                } else if (instruction.equals("RUN")) {
                    runningTotal += layerSize;
                    layers.add(new LayerInfo("RUN", args.substring(0, Math.min(60, args.length())), layerSize));
                } else if (instruction.equals("COPY") || instruction.equals("ADD")) {
                    runningTotal += layerSize;
                    layers.add(new LayerInfo(instruction, args.substring(0, 40) + "...", layerSize));
                } else if (instruction.equals("CMD") || instruction.equals("ENTRYPOINT")) {
                    // Minimal size impact
                    runningTotal += 1024L;
                    layers.add(new LayerInfo(instruction, args.substring(0, 30), 1024));
                } else if (instruction.equals("ENV") || instruction.equals("LABEL") || 
                           instruction.equals("ARG") || instruction.equals("WORKDIR")) {
                    // Negligible size impact
                    runningTotal += 512L;
                    layers.add(new LayerInfo(instruction, args.substring(0, 30), 512));
                } else if (instruction.equals("EXPOSE") || instruction.equals("USER") || 
                           instruction.equals("VOLUME")) {
                    // Very minimal impact
                    runningTotal += 256L;
                    layers.add(new LayerInfo(instruction, args.substring(0, 30), 256));
                } else if (instruction.equals("HEALTHCHECK")) {
                    runningTotal += 1024L;
                    layers.add(new LayerInfo(instruction, "Health check configured", 1024));
                } else if (instruction.equals("SHELL") || instruction.equals("ONBUILD")) {
                    runningTotal += 512L;
                    layers.add(new LayerInfo(instruction, args.substring(0, 30), 512));
                }

                i++; // Move past the newline we already processed
            }
        }

        return new Summary(runningTotal, layers);
    }

    /**
     * Calculates estimated size for a specific instruction.
     */
    private long calculateLayerSize(String instruction, String args, String currentBaseImage) {
        switch (instruction.toUpperCase()) {
            case "FROM":
                // Base images vary significantly - use estimate based on common ones
                if (args.contains(":alpine")) return 50 * 1024 * 1024L;   // ~50MB
                if (args.contains(":debian") || args.contains(":ubuntu")) return 80 * 1024 * 1024L;
                if (args.contains(":slim")) return 70 * 1024 * 1024L;
                return DEFAULT_FROM_BASE_SIZE; // Default ~100MB
            case "RUN":
                // Estimate based on command length and common patterns
                long runSize = DEFAULT_RUN_SIZE;
                
                if (args.contains("apk add") || args.contains("apt-get install")) {
                    runSize += 2 * 1024 * 1024L; // Package manager overhead
                } else if (args.contains("npm install") || args.contains("yarn add")) {
                    runSize += 5 * 1024 * 1024L; // Node packages
                } else if (args.contains("pip install") || args.contains("cargo build")) {
                    runSize += 3 * 1024 * 1024L; // Python/Rust dependencies
                } else if (args.contains("curl") && args.contains("|")) {
                    runSize += 10 * 1024 * 1024L; // Downloading files
                } else if (args.contains("wget") || args.contains("git clone")) {
                    runSize += 5 * 1024 * 1024L; // Git/HTTP downloads
                }
                
                return Math.max(runSize, 1024 * 1024L);

            case "COPY":
            case "ADD":
                // Estimate based on number of source files mentioned
                String[] parts = args.split("\\s+");
                long copySize = DEFAULT_COPY_SIZE_ESTIMATE;
                
                for (int i = 0; i < parts.length - 1 && i < 5; i++) {
                    if (!parts[i].startsWith("--")) {
                        // Count source files/directories
                        String[] sources = parts[i].split("/");
                        copySize += Math.max(1, sources.length) * 2048L;
                    }
                }
                
                return copySize;

            default:
                return 512L; // Default small estimate for other instructions
        }
    }

    /**
     * Prints a formatted summary of the analysis.
     */
    private void printSummary(Summary result) {
        System.out.println("Total Estimated Size: " + String.format("%.2f", result.toMegabytes()) + " MB");
        System.out.println("Layers Analyzed: " + result.layers.size());

        if (!result.layers.isEmpty()) {
            System.out.println("\n--- Layer Breakdown ---");
            
            // Group layers by instruction type for cleaner output
            Map<String, List<LayerInfo>> grouped = new HashMap<>();
            for (LayerInfo layer : result.layers) {
                String key = layer.instruction;
                grouped.computeIfAbsent(key, k -> new ArrayList<>()).add(layer);
            }

            // Print each group
            for (Map.Entry<String, List<LayerInfo>> entry : sortedGroups(grouped)) {
                System.out.println("\n" + entry.getKey() + ":");
                long groupTotal = 0;
                
                for (LayerInfo layer : entry.getValue()) {
                    String displaySize = formatBytes(layer.size);
                    System.out.printf("  %s: %s\n", 
                        truncate(layer.details, 45), displaySize);
                    groupTotal += layer.size;
                }
                
                System.out.println(String.format("  Subtotal: %s (%.1f%% of total)", 
                    formatBytes(groupTotal), (groupTotal / (double) result.totalSize * 100)));
            }

            // Top contributors analysis
            printTopContributors(result);
        }
    }

    private void printTopContributors(Summary result) {
        System.out.println("\n--- Top Size Contributors ---");
        
        List<LayerInfo> sorted = new ArrayList<>(result.layers);
        sorted.sort((a, b) -> Long.compare(b.size(), a.size()));
        
        int limit = Math.min(5, sorted.size());
        for (int i = 0; i < limit; i++) {
            LayerInfo layer = sorted.get(i);
            System.out.printf("%d. %s: %s\n", 
                i + 1, truncate(layer.details, 40), formatBytes(layer.size));
        }

        // Identify potential optimization opportunities
        printOptimizationSuggestions(result);
    }

    private void printOptimizationSuggestions(Summary result) {
        System.out.println("\n--- Optimization Suggestions ---");
        
        boolean hasMultiStage = false;
        long multiStageSavings = 0L;
        
        for (LayerInfo layer : result.layers) {
            if (layer.instruction.equals("FROM")) {
                hasMultiStage = true;
                // Estimate savings from multi-stage builds
                String base = layer.details.split(":")[0];
                if (!base.contains("alpine") && !base.contains("slim")) {
                    multiStageSavings += 30 * 1024 * 1024L; // Assume ~30MB savings per non-alpine base
                }
            } else if (layer.instruction.equals("RUN") && 
                       layer.details.toLowerCase().contains("npm install")) {
                System.out.println("- Consider using multi-stage builds to reduce node_modules");
                break;
            } else if (layer.instruction.equals("COPY") || layer.instruction.equals("ADD")) {
                // Check for large files being copied
                String[] parts = layer.details.split("\\s+");
                for (String part : parts) {
                    if (!part.startsWith("--") && !part.startsWith(".") && 
                        !part.contains("/dist/") && !part.contains("/build/")) {
                        System.out.println("- Review COPY/ADD sources: " + truncate(part, 30));
                    }
                }
            }
        }

        if (hasMultiStage) {
            System.out.printf("- Multi-stage build detected. Estimated savings: %s\n", 
                formatBytes(multiStageSavings));
        } else {
            System.out.println("- Consider multi-stage builds to reduce final image size");
        }
    }

    private static List<Map.Entry<String, List<LayerInfo>>> sortedGroups(
            Map<String, List<LayerInfo>> grouped) {
        return new ArrayList<>(grouped.entrySet()).stream()
                .sorted(Map.Entry.comparingByKey())
                .toList();
    }

    private static String truncate(String str, int maxLen) {
        if (str.length() <= maxLen) return str;
        return str.substring(0, maxLen - 3) + "...";
    }

    private static String formatBytes(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }
}