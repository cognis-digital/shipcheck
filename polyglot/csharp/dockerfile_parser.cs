using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace shipcheck
{
    /// <summary>
    /// Represents a parsed Dockerfile instruction with its metadata.
    */
    public class Instruction
    {
        public string? Command { get; set; }
        public string? Arguments { get; set; }
        public int LineNumber { get; set; }
        public bool IsComment { get; set; }
        public bool IsEmptyLine { get; set; }

        public override string ToString() => $"{Command}: {Arguments}";
    }

    /// <summary>
    /// Represents a base image reference found in the Dockerfile.
    */
    public class BaseImage
    {
        public string ImageName { get; set; } = "";
        public int LineNumber { get; set; }
        public bool IsLatestTag { get; set; }

        public override string ToString() => $"{ImageName} (line {LineNumber})";
    }

    /// <summary>
    /// Represents a detected security advisory or potential issue.
    */
    public class Advisory
    {
        public int LineNumber { get; set; }
        public string Type { get; set; } = "";
        public string Message { get; set; } = "";
        public string? Suggestion { get; set; }

        public override string ToString() => $"{Type}: {Message}";
    }

    /// <summary>
    /// Main parser for Dockerfile content.
    */
    public class DockerfileParser
    {
        private const int DefaultMaxLines = 1000;
        private readonly List<Instruction> _instructions = new();
        private readonly List<BaseImage> _baseImages = new();
        private readonly List<Advisory> _advisories = new();

        public IReadOnlyList<Instruction> Instructions => _instructions.AsReadOnly();
        public IReadOnlyList<BaseImage> BaseImages => _baseImages.AsReadOnly();
        public IReadOnlyList<Advisory> Advisories => _advisories.AsReadOnly();

        /// <summary>
        /// Parses a Dockerfile string and returns analysis results.
        */
        public static (DockerfileParser parser, List<string> warnings) Parse(string content)
        {
            var parser = new DockerfileParser();
            var lines = content.Split(new[] { "\r\n", "\n" }, StringSplitOptions.None);

            foreach (var line in lines)
            {
                parser.ProcessLine(line);
            }

            return (parser, parser._advisories.Select(a => a.ToString()).ToList());
        }

        /// <summary>
        /// Parses content from a file path.
        */
        public static (DockerfileParser parser, List<string> warnings) ParseFile(string path)
        {
            var content = File.ReadAllText(path);
            return Parse(content);
        }

        private void ProcessLine(string line)
        {
            if (_instructions.Count >= DefaultMaxLines)
            {
                _advisories.Add(new Advisory
                {
                    LineNumber = _instructions.Count + 1,
                    Type = "LIMIT",
                    Message = $"Dockerfile exceeds recommended limit of {DefaultMaxLines} lines.",
                    Suggestion = "Consider splitting into multiple files or using multi-stage builds."
                });
            }

            var trimmed = line.Trim();

            if (string.IsNullOrEmpty(trimmed))
            {
                _instructions.Add(new Instruction { LineNumber = _instructions.Count + 1, IsEmptyLine = true });
                return;
            }

            if (trimmed.StartsWith("#"))
            {
                _instructions.Add(new Instruction { LineNumber = _instructions.Count + 1, IsComment = true, Arguments = trimmed });
                return;
            }

            var parts = trimmed.Split(' ', 2);
            var command = parts[0].ToUpperInvariant();
            var args = parts.Length > 1 ? parts[1] : "";

            _instructions.Add(new Instruction
            {
                Command = command,
                Arguments = args,
                LineNumber = _instructions.Count + 1
            });

            if (command == "FROM")
            {
                ParseBaseImage(args);
            }
        }

        private void ParseBaseImage(string imageSpec)
        {
            var parts = imageSpec.Split(' ', 2);
            var imageName = parts[0];
            var tag = parts.Length > 1 ? parts[1] : "";

            var isLatest = string.IsNullOrWhiteSpace(tag) || tag.Equals("latest", StringComparison.OrdinalIgnoreCase);

            _baseImages.Add(new BaseImage
            {
                ImageName = imageSpec,
                LineNumber = _instructions.Last().LineNumber,
                IsLatestTag = isLatest
            });

            if (isLatest && !imageName.Contains(":"))
            {
                _advisories.Add(new Advisory
                {
                    LineNumber = _instructions.Last().LineNumber,
                    Type = "SECURITY",
                    Message = $"Using 'latest' tag on {imageName} may cause unpredictable builds.",
                    Suggestion = "Pin to a specific version: FROM ${image}:${version}"
                });
            }

            if (imageName.Contains("scratch") || imageName.Contains("alpine"))
            {
                _advisories.Add(new Advisory
                {
                    LineNumber = _instructions.Last().LineNumber,
                    Type = "INFO",
                    Message = $"Good choice: lightweight base image detected.",
                    Suggestion = null
                });
            }

            if (imageName.Contains("dotnet") || imageName.Contains(".NET"))
            {
                var sizeHint = GetDotNetImageSizeHint(imageName);
                _advisories.Add(new Advisory
                {
                    LineNumber = _instructions.Last().LineNumber,
                    Type = "SIZE",
                    Message = $"Base image {imageName} typically requires ~{sizeHint}MB download.",
                    Suggestion = sizeHint > 200 ? "Consider using a smaller SDK image for builds." : null
                });
            }
        }

        private static string GetDotNetImageSizeHint(string imageName)
        {
            if (imageName.Contains("sdk")) return "1.5-2.0";
            if (imageName.Contains("aspnet")) return "800-900";
            if (imageName.Contains("runtime")) return "300-400";
            return "100-200";
        }

        /// <summary>
        /// Generates a summary report of the parsed Dockerfile.
        */
        public string GenerateReport()
        {
            var sb = new System.Text.StringBuilder();

            sb.AppendLine("=== ShipCheck Dockerfile Report ===");
            sb.AppendLine($"Total instructions: {_instructions.Count}");
            sb.AppendLine($"Base images found: {_baseImages.Count}");
            sb.AppendLine($"Advisories detected: {_advisories.Count}");
            sb.AppendLine();

            if (_baseImages.Any())
            {
                sb.AppendLine("--- Base Images ---");
                foreach (var img in _baseImages)
                {
                    var tagInfo = img.IsLatestTag ? " [LATEST TAG]" : "";
                    sb.AppendLine($"  Line {img.LineNumber}: {img.ImageName}{tagInfo}");
                }
            }

            if (_advisories.Any())
            {
                sb.AppendLine();
                sb.AppendLine("--- Advisories ---");
                foreach (var adv in _advisories)
                {
                    var suggestion = adv.Suggestion ?? "(no specific suggestion)";
                    sb.AppendLine($"  Line {adv.LineNumber}: [{adv.Type}] {adv.Message}");
                    if (!string.IsNullOrEmpty(adv.Suggestion))
                    {
                        sb.AppendLine($"    > {adv.Suggestion}");
                    }
                }
            }

            return sb.ToString();
        }

        /// <summary>
        /// Returns a concise summary for CLI output.
        */
        public string GetSummary()
        {
            var status = _advisories.Count > 0 ? $"({_advisories.Count} advisories)" : "(clean)";
            return $"Dockerfile: {_instructions.Count} lines, {_baseImages.Count} images{status}";
        }

        /// <summary>
        /// Checks if the Dockerfile uses any known problematic patterns.
        */
        public bool HasCriticalIssues() => _advisories.Any(a => a.Type == "SECURITY" || a.Type == "LIMIT");
    }

    /// <summary>
    /// Entry point for demonstration and testing.
    */
    internal static class Program
    {
        private static void Main(string[] args)
        {
            // Sample Dockerfile content for demo
            var sampleDockerfile = @"
# This is a comment
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build

WORKDIR /src

COPY . .

RUN dotnet restore ""./MyApp.csproj""

FROM build AS publish
RUN dotnet publish ""./MyApp.csproj"" -c Release -o ""/app""

FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS final
WORKDIR /app
COPY --from=publish /app .

EXPOSE 8080

ENTRYPOINT [""dotnet"", ""MyApp.dll""]
";

            Console.WriteLine("=== ShipCheck Demo ===\n");

            var (parser, warnings) = DockerfileParser.Parse(sampleDockerfile);

            // Print summary
            Console.WriteLine(parser.GetSummary());
            Console.WriteLine();

            // Print full report
            Console.WriteLine(parser.GenerateReport());

            // Show warnings
            if (warnings.Any())
            {
                Console.WriteLine("--- Warnings ---");
                foreach (var w in warnings)
                {
                    Console.WriteLine($"  Line {w.Split(':')[0]}: {w}");
                }
            }

            // Exit with appropriate code
            Environment.Exit(parser.HasCriticalIssues() ? 1 : 0);
        }
    }
}