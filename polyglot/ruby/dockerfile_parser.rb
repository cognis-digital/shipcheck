require 'yaml'
require 'json'
require 'open3' if RUBY_VERSION >= '2.5'

module Shipcheck
  # Configuration constants
  DEFAULT_CACHE_DIR = ENV['SHIPCHECK_CACHE'] || File.expand_path('.shipcheck', Dir.pwd)
  MAX_IMAGE_SIZE_MB = 1024
  LAYER_THRESHOLD_MB = 300
  
  # Base images with known CVE data (sample - would load from file in prod)
  KNOWN_CVES = {
    'ubuntu:20.04' => ['CVE-2021-40847', 'CVE-2021-40846'],
    'debian:bullseye' => ['CVE-2023-5925'],
    'alpine:3.18' => [],
  }.freeze

  # Instruction categories for linting
  LINT_CATEGORIES = {
    :base_image: /\A\s*(FROM|FROM --platform)\s+(.+)?/,
    :layer_builder: /\A\s*(RUN|COPY|ADD)\s+(.+)?/,
    :health_check: /\A\s*HEALTHCHECK\s+(.+)?/,
    :exposed_ports: /\A\s*EXPOSE\s+(.+)?/,
    :environment: /\A\s*ENV\s+(.+)?/,
  }.freeze

  class DockerfileParser
    attr_reader :content, :instructions, :base_images, :layers, :warnings, :errors
    
    def initialize(source)
      @source = source.is_a?(String) && File.exist?(source) ? source : source
      @content = read_source
      parse_instructions
      analyze_image_sizes
      detect_cves
      run_lints
    end

    private

    def read_source
      if @source.start_with?(/\.dockerfile$/i) || @source.include?('FROM ')
        File.read(@source)
      else
        @source.strip
      end
    rescue Errno::ENOENT => e
      raise "Dockerfile not found: #{@source}", e.message
    end

    def parse_instructions
      lines = @content.split("\n").map(&:strip).reject(&:empty?)
      
      instructions.each do |line|
        next unless line =~ /\A\s*(\w+)\s+(.*)/
        
        instruction, args = $1.downcase.to_sym, $2
        
        case instruction
        when :from
          parse_from_instruction(args)
        when :run, :copy, :add
          track_layer(instruction, args)
        else
          add_warning("Unusual instruction: #{instruction}") if !KNOWN_INSTRUCTIONS.include?(instruction)
        end
      end
    end

    def parse_from_instruction(args)
      match = /\A\s*(FROM|FROM --platform)\s+(.+)?/i.match(args)
      return unless match
      
      platform = match[2].split.first(1).join(' ') if match[2] =~ /--platform/i
      image_name = match[2].gsub(/--platform.*\s+/, '').strip.gsub(/@sha256:.*/, '')
      
      base_images << {
        name: image_name,
        platform: platform,
        line_number: @content.lines.index(line) + 1,
        raw: args.strip,
      }
    end

    def track_layer(instruction, args)
      layer_info = {
        instruction: instruction,
        content: args.strip,
        line_number: @content.lines.index(line) + 1,
      }
      
      layers << layer_info
      
      # Estimate size contribution for RUN commands
      if instruction == :run
        estimated_kb = estimate_run_size(args)
        layer_info[:estimated_size_kb] = estimated_kb unless estimated_kb.nil?
      end
    end

    def estimate_run_size(args)
      # Rough heuristic: 10-50KB per package install, 20-100KB for apt-get update
      args.scan(/apt-get\s+install|apk\s+add|dnf\s+install|yum\s+install/) do |m|
        return (30..80).to_a.sample * 5 if m # ~150-400KB per package group
      end
      
      args.scan(/apt-get\s+update/).first ? 20 : nil
    rescue
      nil
    end

    def analyze_image_sizes
      total_layers = layers.sum { |l| l[:estimated_size_kb] || 50 } # Default 50KB per layer
      
      @base_images.each do |img|
        img[:estimated_total_kb] = total_layers * 42 if img[:platform].nil?
        img[:exceeds_limit?] = (total_layers / 1024) > MAX_IMAGE_SIZE_MB
      end
    end

    def detect_cves
      KNOWN_CVES.each do |image, cve_list|
        next unless @base_images.any? { |b| b[:name] == image }
        
        base_images.find { |b| b[:name] == image }.tap do |img|
          img[:cves] = cve_list
          img[:has_cves?] = !cve_list.empty?
          
          if img[:has_cves?]
            warnings << "CVE advisories found for #{image}: #{cve_list.join(', ')}"
            
            # Check if using latest tag (higher risk)
            if image =~ /:[a-z0-9.]+$/ && !/:(latest|master)/i
              img[:using_latest?] = false
              warnings << "Consider pinning version: #{image}"
            end
          else
            img[:cves] = []
            img[:has_cves?] = false
          end
        end
      end
    rescue
      # CVE database might not be loaded yet - log and continue
      warnings << "CVE database may need initialization"
    end

    def run_lints
      lint_base_images
      lint_layer_count
      lint_health_checks
      lint_exposed_ports
    end

    def lint_base_images
      @base_images.each do |img|
        # Check for --platform flag usage
        if img[:raw] =~ /--platform/i
          warnings << "Base image uses platform flag: #{img[:name]}"
        end
        
        # Check for multi-stage build hints
        if @content.include?('AS ') || @content.include?('--target=')
          img[:multi_stage?] = true
        end
      end
    end

    def lint_layer_count
      layer_count = layers.count
      
      if layer_count > 50
        warnings << "High layer count (#{layer_count}). Consider combining RUN commands."
      elsif layer_count > 20
        warnings << "Moderate layer count (#{layer_count})"
      end
    rescue
    end

    def lint_health_checks
      health_check = @content.match(/\A\s*HEALTHCHECK\s+(.+)?/)
      
      if health_check
        cmd = health_check[1].strip
        
        # Check for common issues
        [:curl, :wget, :bash, :sh].each do |shell|
          if cmd.include?(shell) && !cmd.include?('--no-headers')
            warnings << "Healthcheck uses #{shell} - consider using /bin/sh"
          end
        end
        
        # Check for network calls without timeout
        if cmd =~ /(curl|wget)\s+(.+?)(?:\|\s*cat)?/i
          match = $2.strip.split(/\s+/)
          
          unless match.include?('--max-time') || match.include?('-m')
            warnings << "Healthcheck may lack timeout: #{cmd}"
          end
        end
      else
        if @content =~ /\A\s*(FROM|RUN)\s+(.+)?/i && !@content.include?('HEALTHCHECK')
          warnings << "Consider adding HEALTHCHECK for production"
        end
      rescue
      end
    end

    def lint_exposed_ports
      ports = []
      
      @content.scan(/\A\s*EXPOSE\s+([0-9]+(?:\/[a-z]+)?)(?:\s+[0-9]+(?:\/[a-z]+)?)*/) do |m|
        m.each { |port| ports << port } if port
      end
      
      unless ports.empty?
        warnings << "Exposed ports: #{ports.join(', ')}"
        
        # Check for common high-risk ports
        HIGH_RISK_PORTS = [22, 3306, 5432, 8080, 9000, 10000].freeze
        
        ports.each do |port|
          if HIGH_RISK_PORTS.include?(port.to_i)
            warnings << "High-risk port exposed: #{port}"
          end
        end
      end
    rescue
    end

    # Public API methods
    def base_image_names
      @base_images.map { |b| b[:name] }
    end

    def total_layers
      layers.count
    end

    def has_cves?
      @base_images.any? { |b| b[:has_cves?] }
    end

    def cve_summary
      @base_images.select { |b| b[:has_cves?] }.map do |img|
        "#{img[:name]}: #{img[:cves].join(', ')}"
      end.join("\n")
    end

    def warnings_summary
      @warnings.compact.join("\n  ")
    end

    def errors_summary
      @errors.compact.join("\n  ")
    end

    def score
      # Simple scoring: start at 100, deduct for issues
      score = 100
      
      warnings.each do |w|
        case w
        when /CVE/; score -= 5
        when /layer/i; score -= 2
        when /healthcheck/i; score -= 3
        when /port/i; score -= 1
        else
          score -= 1
        end
      end
      
      errors.each do |e|
        score -= 10
      end
      
    rescue
      50
    end

    def report(format = :text)
      case format.to_s
      when 'json'
        to_json(report_data)
      when 'yaml'
        YAML.dump(report_data)
      else
        text_report
      end
    rescue
      text_report
    end

    private

    def report_data
      {
        score: score,
        base_images: @base_images.map { |b| b[:name] },
        layer_count: total_layers,
        has_cves?: has_cves?,
        cve_summary: cve_summary,
        warnings: @warnings.compact,
        errors: @errors.compact,
      }
    end

    def text_report
      lines = []
      
      lines << "=" * 50
      lines << "Dockerfile Analysis Report"
      lines << "=" * 50
      
      lines << "\nScore: #{score}/100"
      lines << "\nBase Images:"
      @base_images.each do |img|
        status = img[:has_cves?] ? "⚠ CVEs" : "✓"
        lines << "  • #{status} - #{img[:name]}"
      end
      
      lines << "\nLayers: #{total_layers}"
      
      if @warnings.any?
        lines << "\nWarnings:"
        @warnings.each { |w| lines << "  • #{w}" }
      else
        lines << "\n✓ No warnings"
      end
      
      if @errors.any?
        lines << "\nErrors:"
        @errors.each { |e| lines << "  • #{e}" }
      else
        lines << "\n✓ No errors"
      end
      
      lines.join("\n")
    rescue
      text_report
    end

    # Class methods for convenience
    class << self
    
      def parse(file_or_content)
        parser = DockerfileParser.new(file_or_content)
        
        if format = ENV['SHIPCHECK_FORMAT'] || 'text'
          parser.report(format.to_sym)
        else
          puts parser.text_report
        end
        
        parser
    rescue => e
      STDERR.puts "Error parsing Dockerfile: #{e.message}"
      raise
    end

      def quick_check(file_or_content, options = {})
        parser = DockerfileParser.new(file_or_content)
        
        result = {
          score: parser.score,
          base_images: parser.base_image_names,
          layer_count: parser.total_layers,
          has_cves?: parser.has_cves?,
          warnings: parser.warnings_summary,
          errors: parser.errors_summary,
        }
        
        if options[:json]
          result.to_json
        else
          puts "Quick Check - Score: #{result[:score]}/100"
          puts "Base Images: #{result[:base_images].join(', ')}"
          puts "Layers: #{result[:layer_count]}"
          
          if result[:has_cves?]
            puts "\n⚠ CVEs Detected:"
            puts parser.cve_summary
          end
        end
        
        result
    rescue => e
      { score: 50, base_images: [], layer_count: 0, has_cves?: false, warnings: [e.message] }
    end

      def from_string(content)
        DockerfileParser.new(content)
    rescue => e
      raise "Failed to parse string content", e.message
    end

      def from_file(path)
        DockerfileParser.new(path)
    rescue => e
      raise "Failed to read file: #{path}", e.message
    end

    end # << self
  end
end