import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

/**
 * ShipCheck - Dockerfile Linter with Image Size and CVE Analysis
 */
public class dockerfile_parser {

    // Known base image sizes (approximate, in MB)
    private static final Map<String, Double> BASE_IMAGE_SIZES = Map.of(
        "ubuntu:20.04", 750.0,
        "ubuntu:22.04", 850.0,
        "debian:bullseye", 650.0,
        "debian:bookworm", 700.0,
        "alpine:3.18", 55.0,
        "alpine:latest", 55.0,
        "scratch", 0.0,
        "gcr.io/distroless/java17-debian12", 450.0,
        "eclipse-temurin:17-jre-alpine", 90.0
    );

    // Package manager layer estimates (in MB)
    private static final Map<String, Double> PKG_LAYER_SIZES = Map.of(
        "apt-get update && apt-get install -y", 25.0,
        "apk add --no-cache", 15.0,
        "yum install -y", 30.0,
        "dnf install -y", 30.0,
        "pip install", 5.0,
        "npm install", 2.0,
        "cargo add", 1.0,
        "go get", 1.0,
        "mvn dependency:copy-dependencies", 5.0,
        "gradle dependencies --refresh-dependencies", 3.0
    );

    // Common CVEs by base image (simplified)
    private static final Map<String, List<CveEntry>> BASE_CVES = Map.of(
        "ubuntu:20.04", List.of(new CveEntry("CVE-2021-40847", 9.0, "glibc")),
        "debian:bullseye", List.of(new CveEntry("CVE-2023-36559", 7.5, "libssl"))
    );

    private static class CveEntry {
        String id;
        double severity; // CVSS score
        String package;

        CveEntry(String id, double severity, String package) {
            this.id = id;
            this.severity = severity;
            this.package = package;
        }
    }

    private static class LayerInfo {
        String instruction;
        String arguments;
        long estimatedSizeContribution; // in KB
        List<String> packagesAdded;
        boolean isBaseImage;
        String baseImageTag;

        public LayerInfo(String instruction, String args) {
            this.instruction = instruction;
            this.arguments = args;
        }

        @Override
        public String toString() {
            return instruction + " " + arguments;
        }
    }

    private static class ParseResult {
        List<LayerInfo> layers;
        double estimatedTotalSizeMB;
        Map<String, String> envVars;
        Map<String, String> args;
        List<CveEntry> detectedCves;
        boolean hasMultiStageBuild;
        long buildTimeEstimateSeconds;

        public ParseResult(List<LayerInfo> layers) {
            this.layers = layers;
            this.estimatedTotalSizeMB = calculateEstimatedSize(layers);
            this.envVars = extractEnvVars();
            this.args = extractArgs();
            this.detectedCves = detectCves(layers);
            this.hasMultiStageBuild = hasMultiStageBuild(layers);
        }

        private double calculateEstimatedSize(List<LayerInfo> layers) {
            double totalKB = 0;
            
            for (LayerInfo layer : layers) {
                if ("FROM".equals(layer.instruction)) {
                    // Base image contribution
                    String baseImage = extractBaseImage(layer.arguments);
                    if (baseImage != null && BASE_IMAGE_SIZES.containsKey(baseImage)) {
                        totalKB += BASE_IMAGE_SIZES.get(baseImage) * 1024;
                    } else {
                        // Unknown base - estimate conservatively
                        totalKB += 500 * 1024;
                    }
                } else if (layer.instruction.startsWith("RUN")) {
                    String cmd = layer.arguments;
                    
                    // Check for known package managers
                    if (cmd.contains("apt-get install") || cmd.contains("apt-get update")) {
                        totalKB += 25 * 1024;
                    } else if (cmd.contains("apk add")) {
                        totalKB += 15 * 1024;
                    } else if (cmd.contains("yum install") || cmd.contains("dnf install")) {
                        totalKB += 30 * 1024;
                    } else if (cmd.contains("pip install")) {
                        totalKB += 5 * 1024;
                    } else if (cmd.contains("npm install")) {
                        totalKB += 2 * 1024;
                    } else if (cmd.contains("cargo add") || cmd.contains("cargo build")) {
                        totalKB += 1 * 1024;
                    } else if (cmd.contains("go get") || cmd.contains("go mod download")) {
                        totalKB += 1 * 1024;
                    } else if (cmd.contains("mvn dependency:copy-dependencies")) {
                        totalKB += 5 * 1024;
                    } else if (cmd.contains("gradle dependencies") || cmd.contains("maven-dependency-plugin")) {
                        totalKB += 3 * 1024;
                    }
                    
                    // Estimate for generic RUN commands
                    int wordCount = Arrays.stream(cmd.split("\\s+")).count();
                    if (wordCount > 5) {
                        totalKB += Math.min(10, wordCount / 2) * 1024;
                    }
                } else if ("ARG".equals(layer.instruction)) {
                    // ARG doesn't add size but affects caching
                }
            }
            
            return totalKB / 1024.0;
        }

        private String extractBaseImage(String args) {
            if (args == null || args.isEmpty()) return null;
            
            // Handle multi-stage: FROM base AS builder -> use first part
            int fromIndex = args.indexOf("FROM");
            if (fromIndex > 0) {
                return args.substring(fromIndex + 4).trim();
            }
            
            // Simple case
            return args.trim().split("\\s+")[0];
        }

        private Map<String, String> extractEnvVars() {
            Map<String, String> result = new LinkedHashMap<>();
            
            for (LayerInfo layer : layers) {
                if ("ENV".equals(layer.instruction)) {
                    // ENV VAR=value or ENV VAR1=val1 VAR2=val2
                    String[] parts = layer.arguments.split("\\s+");
                    for (String part : parts) {
                        int eqIndex = part.indexOf('=');
                        if (eqIndex > 0) {
                            result.put(part.substring(0, eqIndex), 
                                       part.substring(eqIndex + 1));
                        } else {
                            // ENV VAR (no value yet - placeholder)
                            result.putIfAbsent(part, "");
                        }
                    }
                }
            }
            
            return result;
        }

        private Map<String, String> extractArgs() {
            Map<String, String> result = new LinkedHashMap<>();
            
            for (LayerInfo layer : layers) {
                if ("ARG".equals(layer.instruction)) {
                    String[] parts = layer.arguments.split("\\s+");
                    for (String part : parts) {
                        int eqIndex = part.indexOf('=');
                        if (eqIndex > 0) {
                            result.put(part.substring(0, eqIndex), 
                                       part.substring(eqIndex + 1));
                        } else {
                            // ARG VAR (no value yet - placeholder)
                            result.putIfAbsent(part, "");
                        }
                    }
                }
            }
            
            return result;
        }

        private List<CveEntry> detectCves(List<LayerInfo> layers) {
            List<CveEntry> detected = new ArrayList<>();
            
            // Check base images for known CVEs
            String baseImage = extractBaseImage(layers.get(0).arguments);
            if (baseImage != null && BASE_CVES.containsKey(baseImage)) {
                detected.addAll(BASE_CVES.get(baseImage));
            }
            
            return detected;
        }

        private boolean hasMultiStageBuild(List<LayerInfo> layers) {
            for (LayerInfo layer : layers) {
                if ("FROM".equals(layer.instruction)) {
                    // Check if this FROM instruction has an "AS" clause
                    String[] parts = layer.arguments.split("\\s+");
                    for (int i = 0; i < parts.length - 1; i++) {
                        if ("AS".equals(parts[i + 1])) {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        public double getEstimatedTotalSizeMB() {
            return estimatedTotalSizeMB;
        }

        public Map<String, String> getEnvVars() {
            return envVars;
        }

        public Map<String, String> getArgs() {
            return args;
        }

        public List<CveEntry> getDetectedCves() {
            return detectedCves;
        }

        public boolean hasMultiStageBuild() {
            return hasMultiStageBuild;
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("Estimated Size: ").append(String.format("%.2f", estimatedTotalSizeMB)).append(" MB\n");
            sb.append("Environment Variables: ").append(envVars.size()).append("\n");
            sb.append("Build Args: ").append(args.size()).append("\n");
            if (!detectedCves.isEmpty()) {
                sb.append("Detected CVEs: ").append(detectedCves.size());
                for (CveEntry cve : detectedCves) {
                    sb.append(", ").append(cve.id).append(" (").append(String.format("%.1f", cve.severity)).append(")");
                }
            } else {
                sb.append("(none)\n");
            }
            return sb.toString();
        }
    }

    private static class DockerfileParser {
        
        /**
         * Parse a Dockerfile content string.
         */
        public static ParseResult parse(String dockerfileContent) throws IOException {
            if (dockerfileContent == null || dockerfileContent.isEmpty()) {
                return new ParseResult(new ArrayList<>());
            }

            // Normalize line endings and handle backslash continuations
            String normalized = normalizeLines(dockerfileContent);
            
            List<LayerInfo> layers = new ArrayList<>();
            StringBuilder currentLine = new StringBuilder();
            boolean inComment = false;
            
            for (int i = 0; i < normalized.length(); i++) {
                char c = normalized.charAt(i);
                
                if (c == '\\') {
                    // Backslash continuation - append next line
                    continue;
                } else if (c == '#') {
                    inComment = true;
                    currentLine.append(c);
                } else if (c == '\n' || i == normalized.length() - 1) {
                    if (!inComment && !currentLine.isEmpty()) {
                        String line = currentLine.toString().trim();
                        
                        // Skip empty lines and pure comments
                        if (!line.isEmpty() && !isPureComment(line)) {
                            parseInstruction(line, layers);
                        }
                    }
                    
                    currentLine.setLength(0);
                    inComment = false;
                } else {
                    currentLine.append(c);
                }
            }

            return new ParseResult(layers);
        }

        private static String normalizeLines(String content) {
            // Normalize line endings and handle backslash continuations
            StringBuilder result = new StringBuilder();
            
            for (int i = 0; i < content.length(); i++) {
                char c = content.charAt(i);
                
                if (c == '\\') {
                    // Check if followed by newline
                    int nextNewline = content.indexOf('\n', i + 1);
                    if (nextNewline != -1) {
                        result.append(content, i + 1, nextNewline - i);
                        i = nextNewline;
                    } else {
                        result.append(c);
                    }
                } else {
                    result.append(c);
                }
            }
            
            return result.toString();
        }

        private static boolean isPureComment(String line) {
            // Check if entire instruction is a comment
            int firstNonSpace = 0;
            for (int i = 0; i < line.length(); i++) {
                char c = line.charAt(i);
                if (!Character.isWhitespace(c)) {
                    firstNonSpace = i;
                    break;
                }
            }
            
            return firstNonSpace > 0 && 
                   (line.charAt(firstNonSpace) == '#' || 
                    line.substring(firstNonSpace).startsWith("##"));
        }

        private static void parseInstruction(String line, List<LayerInfo> layers) {
            // Extract instruction and arguments
            int spaceIndex = line.indexOf(' ');
            
            String instruction;
            String args;
            
            if (spaceIndex > 0) {
                instruction = line.substring(0, spaceIndex).toUpperCase();
                args = line.substring(spaceIndex + 1);
            } else {
                instruction = line.toUpperCase();
                args = "";
            }

            // Trim and clean up arguments
            args = args.trim().replaceAll("\\s+", " ");

            layers.add(new LayerInfo(instruction, args));
        }

        /**
         * Parse a Dockerfile from a file path.
         */
        public static ParseResult parseFile(String filePath) throws IOException {
            String content = Files.readString(Paths.get(filePath));
            return parse(content);
        }

        /**
         * Generate a summary report for the parsed Dockerfile.
         */
        public static String generateReport(ParseResult result) {
            StringBuilder sb = new StringBuilder();
            
            sb.append("=== ShipCheck Analysis Report ===\n\n");
            
            // Size analysis
            sb.append("1. SIZE ANALYSIS\n");
            sb.append(String.format("   Estimated Final Image Size: %.2f MB\n", 
                                   result.getEstimatedTotalSizeMB()));
            sb.append("   \n");

            // Base image info
            String baseImage = extractBaseImage(result.layers.get(0).arguments);
            if (baseImage != null) {
                sb.append(String.format("   Primary Base Image: %s\n", baseImage));
                
                Double estimatedSize = BASE_IMAGE_SIZES.get(baseImage);
                if (estimatedSize != null) {
                    sb.append(String.format("   Base Image Estimated Size: %.2f MB\n", estimatedSize));
                } else {
                    sb.append("   Base Image Estimated Size: Unknown (~500 MB conservative)\n");
                }
            }
            
            // CVE analysis
            List<CveEntry> cves = result.getDetectedCves();
            if (!cves.isEmpty()) {
                sb.append("2. SECURITY ANALYSIS\n");
                sb.append(String.format("   Detected CVEs: %d\n", cves.size()));
                
                for (CveEntry cve : cves) {
                    String severityLevel = getSeverityLevel(cve.severity);
                    sb.append(String.format("     - %s (%s)\n", 
                                           cve.id, severityLevel));
                    sb.append(String.format("       Package: %s\n", cve.package));
                }
            } else {
                sb.append("2. SECURITY ANALYSIS\n");
                sb.append("   Detected CVEs: (none in known base images)\n");
            }
            
            // Environment variables
            Map<String, String> envVars = result.getEnvVars();
            if (!envVars.isEmpty()) {
                sb.append("3. ENVIRONMENT VARIABLES\n");
                sb.append(String.format("   Total ENV/ARG definitions: %d\n", 
                                       envVars.size()));
                
                for (Map.Entry<String, String> entry : envVars.entrySet()) {
                    sb.append(String.format("     - %s=%s\n", 
                                           escapeString(entry.getKey()), 
                                           escapeString(entry.getValue())));
                }
            } else {