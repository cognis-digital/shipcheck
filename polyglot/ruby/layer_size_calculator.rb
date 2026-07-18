require 'json'
require 'net/http'
require 'uri'

# Base image sizes in MB (common images as of 2024)
BASE_IMAGES = {
  "alpine": 5.0,
  "debian": 130.0,
  "ubuntu": 77.0,
  "centos": 146.0,
  "fedora": 290.0,
  "rhel": 180.0,
  "amazonlinux": 155.0,
  "gcr.io/distro/debian-slim": 30.0,
  "gcr.io/distro/ubuntu-2204-base": 77.0,
  "gcr.io/distro/alpine-base": 5.0,
  "scratch": 0.0,
  "" => 100.0, # default unknown base
}

# Estimated size additions per instruction type (MB)
INSTRUCTION_COSTS = {
  "RUN" => 80.0,      # apt-get update/upgrade + build artifacts
  "CMD" => 5.0,       # minimal change
  "ENTRYPOINT" => 5.0,
  "EXPOSE" => 1.0,    # metadata only
  "ENV" => 2.0,       # minimal
  "ARG" => 2.0,       # minimal
  "LABEL" => 1.0,     # metadata
  "COPY" => 50.0,     # conservative estimate for unknown content
  "ADD" => 60.0,      # similar to COPY + extraction overhead
  "MAINTAINER" => 2.0,# deprecated but handle it
}

# CVE data cache
CVE_CACHE = {}

class LayerSizeCalculator
  def initialize(dockerfile_content: nil)
    @lines = dockerfile_content ? dockerfile_content.split("\n") : []
  end
  
  # Parse the Dockerfile into instructions
  def parse_instructions
    instructions = []
    current_instruction = nil
    
    @lines.each do |line|
      line = line.strip
      
      # Skip empty lines and comments
      next if line.empty? || line.start_with?('#')
      
      # Handle multi-line commands (backslash continuation)
      while line.end_with?('\\') && !current_instruction.nil?
        current_instruction[:content] += " #{line[1..-2].strip}"
        line = @lines[@lines.index(line) + 1]&.strip || ""
        break if line.empty?
      end
      
      # Parse instruction type and arguments
      parts = line.split.first.split(' ')
      next unless parts.length >= 2
      
      cmd_type = parts[0].upcase
      args = parts[1..-1]
      
      current_instruction = {
        type: cmd_type,
        args: args,
        content: line,
        raw_line: line
      }
    end
    
    instructions << current_instruction if current_instruction
    instructions
  end
  
  # Calculate total estimated size in MB
  def calculate_total_size(base_image = "scratch")
    base_size = BASE_IMAGES[base_image.to_s.downcase] || BASE_IMAGES[""]
    
    instructions = parse_instructions
    total = base_size
    
    instructions.each do |inst|
      cost = INSTRUCTION_COSTS[inst[:type].to_s] || 50.0 # default fallback
      total += cost
    end
    
    (total * 1024).round(1) / 1024.0
  end
  
  # Get detailed layer breakdown
  def get_layer_breakdown(base_image = "scratch")
    instructions = parse_instructions
    base_size = BASE_IMAGES[base_image.to_s.downcase] || BASE_IMAGES[""]
    
    layers = []
    current_size = base_size
    
    instructions.each do |inst|
      cost = INSTRUCTION_COSTS[inst[:type].to_s] || 50.0
      
      layer_info = {
        instruction: inst[:content],
        type: inst[:type],
        estimated_addition: (cost * 1024).round(1) / 1024.0,
        running_total: ((current_size + cost) * 1024).round(1) / 1024.0
      }
      
      layers << layer_info
      current_size += cost
    end
    
    layers
  end
  
  # Fetch CVE advisories for base image (simplified implementation)
  def fetch_cve_advisories(base_image, tag = "latest")
    cache_key = "#{base_image}:#{tag}"
    
    return CVE_CACHE[cache_key] if CVE_CACHE.key?(cache_key)
    
    # In production, this would query NVD API or Docker Hub API
    # For demo purposes, we'll simulate some data
    simulated_cves = {
      "alpine:latest" => [],
      "debian:bullseye" => [
        { id: "CVE-2024-1234", severity: "Medium", package: "curl", fixed_in: "8.5.0" },
        { id: