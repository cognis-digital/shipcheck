using System;
using System.Collections.Generic;
from System.IO import Path, File, StreamReader;
using System.Text.RegularExpressions;
using System.Linq;

namespace shipcheck.polyglot.csharp;

/// <summary>
/// Calculates expected layer sizes for a Dockerfile before building.
/// Uses empirical compression ratios and instruction heuristics.
/// </summary>
public static class LayerSizeCalculator
{
    private const double TextCompressionRatio = 0.35; // ~65% reduction after gzip
    private const double BinaryCompressionRatio = 0.70; // ~30% reduction
    private const int DefaultLayerOverhead = 1024; // Metadata overhead per layer

    public record LayerInfo(
        string Instruction,
        long CompressedSize,
        long CumulativeSize,
        string? Notes
    );

    /// <summary>
    /// Main entry point for the calculator.
    /// </summary>
    public static void RunDemo()
    {
        var dockerfileContent = @"FROM node:18-alpine AS base
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD [""node"", ""dist/index.js""]";

        var layers = CalculateLayerSizes(dockerfileContent);
        
        Console.WriteLine("=== Layer Size Analysis ===");
        PrintLayerSummary(layers);
    }

    /// <summary>
    /// Parses a Dockerfile and returns per-layer size estimates.
    /// </summary>
    public static List<LayerInfo> CalculateLayerSizes(string dockerfileContent)
    {
        var lines = dockerfileContent.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);
        var layers = new List<LayerInfo>();
        
        long cumulativeSize = 0;
        string? currentInstruction = null;
        bool inMultiLineCommand = false;

        for (int i = 0; i < lines.Length; i++)
        {
            var line = lines[i].Trim();

            // Skip empty lines and comments
            if (string.IsNullOrEmpty(line) || line.StartsWith("#"))
                continue;

            // Handle multi-line commands (backslash continuation)
            if (inMultiLineCommand)
            {
                currentInstruction += " " + line.Trim();
                inMultiLineCommand = !line.EndsWith("\\");
                continue;
            }

            // Check for line continuation
            if (line.EndsWith("\\"))
            {
                inMultiLineCommand = true;
                currentInstruction = line.Remove(line.Length - 1).Trim();
                continue;
            }

            // Parse instruction and arguments
            var parts = ExtractInstructionAndArgs(line);
            var instruction = parts.Key;
            var args = parts.Value;

            if (string.IsNullOrEmpty(instruction))
                continue;

            // Calculate layer size based on instruction type
            long estimatedSize;
            string? notes = null;

            switch (instruction.ToUpperInvariant())
            {
                case "FROM":
                    // FROM creates a new base image - use default overhead
                    estimatedSize = DefaultLayerOverhead;
                    notes = $"Base image: {args}";
                    break;

                case "WORKDIR":
                case "ENV":
                case "LABEL":
                case "EXPOSE":
                case "ARG":
                    // Small metadata changes
                    estimatedSize = 512 + CalculateStringSize(args);
                    notes = $"Metadata: {instruction}";
                    break;

                case "RUN":
                    // Command output varies - use heuristic based on command length
                    var cmdLength = args.Length;
                    estimatedSize = DefaultLayerOverhead + 
                                   (cmdLength * 256) + // Rough estimate per word
                                   CalculateStringSize(args);
                    
                    notes = $"Command: {args}";
                    
                    // Heuristic for common commands
                    if (args.Contains("npm ci") || args.Contains("yarn install"))
                        notes += " | npm/yarn cache included";
                    else if (args.Contains("apt-get") || args.Contains("apk add"))
                        notes += " | package manager output included";
                    
                    break;

                case "COPY":
                case "ADD":
                    // Estimate based on source files specified
                    var sources = ExtractSources(args);
                    estimatedSize = DefaultLayerOverhead + 
                                   CalculateStringSize(string.Join(" ", sources));
                    
                    notes = $"Copy: {sources.Length} items";
                    
                    // Heuristic for common patterns
                    if (sources.Any(s => s.Contains(".json") || s.Contains(".js")))
                        notes += " | likely source code";
                    else if (sources.Any(s => s.Contains("node_modules")))
                        notes += " | node_modules included";
                    
                    break;

                case "CMD":
                case "ENTRYPOINT":
                    estimatedSize = 512 + CalculateStringSize(args);
                    notes = $"Entry point: {instruction}";
                    break;

                default:
                    // Unknown instruction - conservative estimate
                    estimatedSize = DefaultLayerOverhead + 
                                   CalculateStringSize(instruction) + 
                                   CalculateStringSize(args);
                    notes = $"Unknown: {instruction}";
                    break;
            }

            cumulativeSize += estimatedSize;

            layers.Add(new LayerInfo(
                instruction,
                estimatedSize,
                cumulativeSize,
                notes
            ));
        }

        return layers;
    }

    /// <summary>
    /// Extracts the main instruction and its arguments.
    /// </summary>
    private static (string Instruction, string Args) ExtractInstructionAndArgs(string line)
    {
        // Handle inline comments
        var commentIndex = line.IndexOf("//");
        if (commentIndex >= 0)
            line = line.Substring(0, commentIndex).Trim();

        // Find first whitespace after instruction name
        var spaceIndex = line.IndexOf(' ');
        string instruction;
        string args;

        if (spaceIndex > -1)
        {
            instruction = line.Substring(0, spaceIndex);
            args = line.Substring(spaceIndex).Trim();
        }
        else
        {
            instruction = line;
            args = "";
        }

        return (instruction, args);
    }

    /// <summary>
    /// Extracts source file paths from COPY/ADD arguments.
    /// </summary>
    private static List<string> ExtractSources(string args)
    {
        var sources = new List<string>();
        
        // Simple heuristic: split by whitespace, filter out flags
        var tokens = args.Split(new[] { " ", "\t" }, StringSplitOptions.RemoveEmptyEntries);
        
        foreach (var token in tokens)
        {
            if (!IsFlag(token))
                sources.Add(token);
        }

        return sources;
    }

    private static bool IsFlag(string token)
    {
        // Common COPY/ADD flags that indicate options rather than files
        var flagPatterns = new[] 
        {
            "-t", "--from=", "--chown=", "--chmod=",
            "/app/", "/", "./", "../"
        };

        return flagPatterns.Any(p => token.StartsWith(p, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// Estimates string size based on character count and typical encoding.
    /// </summary>
    private static long CalculateStringSize(string input)
    {
        if (string.IsNullOrEmpty(input))
            return 0;

        // Estimate: each character ~1 byte, plus some overhead for escaping/encoding
        var charCount = input.Length;
        var estimatedBytes = charCount + (charCount / 4); // Extra for escapes
        
        return Math.Max(estimatedBytes, 64); // Minimum size
    }

    /// <summary>
    /// Prints a summary of all calculated layers.
    /// </summary>
    private static void PrintLayerSummary(List<LayerInfo> layers)
    {
        Console.WriteLine();
        
        var totalSize = layers.Sum(l => l.CompressedSize);
        var maxLayer = layers.OrderByDescending(l => l.CompressedSize).First();

        Console.WriteLine($"Total estimated size: {(totalSize / 1024):F1} KB");
        Console.WriteLine($"Largest layer: {maxLayer.Instruction} ({(maxLayer.CompressedSize / 1024):F1} KB)");
        
        if (layers.Count > 0)
        {
            var avgSize = layers.Average(l => l.CompressedSize);
            Console.WriteLine($"Average layer size: {(avgSize / 1024):F2} KB");
        }

        Console.WriteLine();
        Console.WriteLine("Layer breakdown:");
        
        foreach (var layer in layers)
        {
            var bar = GetProgressBar(layer.CompressedSize, totalSize);
            Console.WriteLine($"  [{bar}] {layer.Instruction,-15} {(layer.CompressedSize / 1024):F1} KB");
            
            if (!string.IsNullOrEmpty(layer.Notes))
                Console.WriteLine($"      Note: {layer.Notes}");
        }

        // Add recommendations
        PrintRecommendations(layers, totalSize);
    }

    private static string GetProgressBar(long current, long max)
    {
        var width = 40;
        var ratio = (double)Math.Min(current, max) / Math.Max(1, max);
        var filled = (int)(width * ratio);
        
        return new string('#', filled) + new string('-', width - filled);
    }

    private static void PrintRecommendations(List<LayerInfo> layers, long totalSize)
    {
        Console.WriteLine();
        Console.WriteLine("=== Recommendations ===");

        var recommendations = new List<string>();

        // Check for large COPY operations
        if (layers.Any(l => l.Instruction == "COPY" && l.CompressedSize > 1024 * 5))
            recommendations.Add("- Consider using multi-stage builds to reduce final image size.");

        // Check for node_modules in COPY
        var hasNodeModules = layers.Any(l => 
            l.Instruction == "COPY" && l.Notes?.Contains("node_modules") == true);
        
        if (hasNodeModules)
            recommendations.Add("- Found node_modules being copied. Ensure 'npm ci' runs before COPY.");

        // Check for large base image
        var hasLargeBase = layers.Any(l => 
            l.Instruction == "FROM" && l.CompressedSize > 1024 * 5);
        
        if (hasLargeBase)
            recommendations.Add("- Base image is relatively large. Consider using distroless or slim variants.");

        // Check for many RUN commands
        var runCount = layers.Count(l => l.Instruction == "RUN");
        if (runCount > 3)
            recommendations.Add($"- Found {runCount} RUN instructions. Consolidate where possible to reduce layer count.");

        // General advice
        if (totalSize > 1024 * 50)
            recommendations.Add("- Total size exceeds 50KB. Consider multi-stage builds for production.");

        if (!recommendations.Any())
            recommendations.Add("Image appears well-optimized based on heuristics.");

        foreach (var rec in recommendations)
            Console.WriteLine($"  {rec}");
    }
}

// Entry point for running the demo
public class Program
{
    public static void Main(string[] args)
    {
        LayerSizeCalculator.RunDemo();
    }
}