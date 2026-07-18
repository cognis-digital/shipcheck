import { Readable } from 'node:stream';

export interface Instruction {
  type: string;
  args: string[];
  rawLine?: string;
}

export interface BaseImageInfo {
  image: string;
  stageIndex: number;
  isDefault: boolean;
}

export interface LayerMetadata {
  estimatedSizeMB: number;
  instructions: Instruction[];
}

export interface ParseResult {
  instructions: Instruction[];
  baseImages: BaseImageInfo[];
  layers: LayerMetadata[];
  multiStage: boolean;
  defaultBase?: string;
  warnings: string[];
}

interface ParserState {
  currentInstruction: string | null;
  inMultiLineCommand: boolean;
  multiLineBuffer: string;
  layerSizeEstimate: number;
  stageIndex: number;
  isDefaultStage: boolean;
}

export function parseDockerfile(
  content: string | Readable,
  options: {
    strictMode?: boolean;
    estimateLayerSizes?: boolean;
    includeComments?: boolean;
  } = {}
): ParseResult {
  const state: ParserState = {
    currentInstruction: null,
    inMultiLineCommand: false,
    multiLineBuffer: '',
    layerSizeEstimate: 0,
    stageIndex: 0,
    isDefaultStage: true,
  };

  let result: ParseResult;

  if (content instanceof Readable) {
    const chunks: string[] = [];
    content.on('data', chunk => chunks.push(chunk.toString()));
    content.on('end', () => {
      result = parseDockerfile(chunks.join(''), options);
    });
    return result;
  }

  // Normalize line endings and split
  const lines = (content as string).split(/\r?\n/);

  // First pass: identify multi-line commands
  for (let i = 0; i < lines.length; i++) {
    if (!state.inMultiLineCommand) {
      state.currentInstruction = lines[i].trim();
    } else {
      state.multiLineBuffer += '\n' + lines[i];
    }
  }

  // Second pass: parse instructions
  result = {
    instructions: [],
    baseImages: [],
    layers: [],
    multiStage: false,
    defaultBase: undefined,
    warnings: [],
  };

  const layerStartIndex = 0;
  let currentLayer: LayerMetadata | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const trimmed = line.trim();

    // Skip empty lines and pure comments
    if (!trimmed || /^\s*#/.test(trimmed)) {
      continue;
    }

    // Handle multi-line commands (RUN | CMD)
    if (/^\s*(RUN|CMD)\b/.test(trimmed)) {
      const match = trimmed.match(/^(\w+)\s+(.*)$/);
      if (match) {
        const [, type, args] = match;
        result.instructions.push({
          type,
          args: args.split(/\s+/).filter(Boolean),
          rawLine: trimmed,
        });

        // Estimate size for RUN commands
        if (options.estimateLayerSizes && options.strictMode) {
          const cmdSize = estimateCommandSize(trimmed);
          state.layerSizeEstimate += cmdSize;
        }
      }
    } else if (/^\s*(FROM)\b/.test(trimmed)) {
      // Handle FROM instruction
      const match = trimmed.match(/^(\w+)\s+(.*)$/);
      if (match) {
        const [, type, args] = match;

        result.instructions.push({
          type: 'FROM',
          args: args.split(/\s+/).filter(Boolean),
          rawLine: trimmed,
        });

        // Extract base image info
        let baseImage: string | undefined;
        
        if (args.includes('AS')) {
          const parts = args.split(' AS ');
          baseImage = parts[0].trim();
          result.multiStage = true;
          state.stageIndex++;
          state.isDefaultStage = false;
        } else {
          baseImage = args.trim();
          if (state.stageIndex === 0) {
            result.defaultBase = baseImage;
            state.isDefaultStage = true;
          } else {
            state.stageIndex++;
            state.isDefaultStage = false;
          }
        }

        if (baseImage) {
          result.baseImages.push({
            image: baseImage,
            stageIndex: state.stageIndex,
            isDefault: state.isDefaultStage,
          });
        }
      }
    } else if (/^\s*(COPY|ADD)\b/.test(trimmed)) {
      // Handle COPY/ADD with size estimation
      const match = trimmed.match(/^(\w+)\s+(.*)$/);
      if (match) {
        const [, type, args] = match;

        result.instructions.push({
          type: 'COPY' as const,
          args: args.split(/\s+/).filter(Boolean),
          rawLine: trimmed,
        });

        // Estimate size for COPY/ADD
        if (options.estimateLayerSizes && options.strictMode) {
          state.layerSizeEstimate += estimateCopyAddSize(args);
        }
      }
    } else if (/^\s*(ARG|ENV)\b/.test(trimmed)) {
      result.instructions.push({
        type: trimmed.split(/\s+/)[0] as string,
        args: trimmed.split(/\s+/).slice(1),
        rawLine: trimmed,
      });
    } else if (/^\s*(LABEL|EXPOSE|WORKDIR|VOLUME)\b/.test(trimmed)) {
      result.instructions.push({
        type: trimmed.split(/\s+/)[0] as string,
        args: trimmed.split(/\s+/).slice(1),
        rawLine: trimmed,
      });
    } else if (/^\s*(RUN|CMD)\b/.test(trimmed)) {
      // Already handled above
    } else if (trimmed && !/^\s*#/.test(trimmed)) {
      // Unknown instruction - add warning
      result.warnings.push(`Unknown instruction: ${trimmed}`);
    }

    // Track layer boundaries for size estimation
    if (/^\s*(RUN|COPY|ADD)\b/.test(trimmed) && !state.inMultiLineCommand) {
      currentLayer = {
        estimatedSizeMB: state.layerSizeEstimate,
        instructions: [],
      };
      result.layers.push(currentLayer);

      // Clear buffer for next layer
      if (currentLayer) {
        currentLayer.instructions = [];
        state.layerSizeEstimate = 0;
      }
    } else if (currentLayer && trimmed) {
      currentLayer.instructions.push({
        type: 'RUN' as const,
        args: trimmed.split(/\s+/).filter(Boolean),
        rawLine: trimmed,
      });
    }
  }

  // Add final layer
  if (currentLayer && result.layers.length > 0) {
    currentLayer.estimatedSizeMB += state.layerSizeEstimate;
  } else if (currentLayer) {
    currentLayer.estimatedSizeMB = state.layerSizeEstimate;
    result.layers.push(currentLayer);
  }

  // Add a final layer for any remaining content
  if (!currentLayer && result.instructions.length > 0) {
    const lastInstructionType = result.instructions[result.instructions.length - 1].type;
    
    if (lastInstructionType === 'RUN' || lastInstructionType === 'COPY' || 
        lastInstructionType === 'ADD') {
      currentLayer = {
        estimatedSizeMB: state.layerSizeEstimate,
        instructions: [],
      };
      result.layers.push(currentLayer);
    }
  }

  // Add a default final layer if needed
  if (result.instructions.length > 0 && !currentLayer) {
    const lastInstruction = result.instructions[result.instructions.length - 1];
    
    if (lastInstruction.type === 'RUN' || lastInstruction.type === 'COPY' || 
        lastInstruction.type === 'ADD') {
      currentLayer = {
        estimatedSizeMB: state.layerSizeEstimate,
        instructions: [],
      };
      result.layers.push(currentLayer);
    }
  }

  // Ensure at least one layer exists
  if (result.layers.length === 0) {
    result.layers.push({
      estimatedSizeMB: 0,
      instructions: [],
    });
  }

  return result;
}

function estimateCommandSize(command: string): number {
  // Heuristic estimation based on command characteristics
  const normalized = command.toLowerCase().replace(/["']/g, '');
  
  let baseSize = 10; // Base size for any RUN command
  
  // Check for common patterns that indicate larger images
  if (normalized.includes('apt-get install') || 
      normalized.includes('yum install') ||
      normalized.includes('apk add')) {
    baseSize += 50;
  }
  
  if (normalized.includes('curl') || normalized.includes('wget')) {
    // Estimate download size based on common packages
    const pkgPatterns = [
      /nodejs/g, /python3/g, /golang/g, /ruby/g,
      /postgres/g, /mysql/g, /redis/g, /nginx/g,
      /apache/g, /mongodb/g, /elastic/g, /kafka/g
    ];
    
    let pkgSize = 0;
    for (const pattern of pkgPatterns) {
      if (pattern.test(normalized)) {
        pkgSize += 50; // Conservative estimate per package group
      }
    }
    baseSize += pkgSize;
  }

  // Check for multi-line commands
  const lineCount = command.split('\n').length;
  baseSize += (lineCount - 1) * 2;

  return Math.max(baseSize, 5);
}

function estimateCopyAddSize(args: string): number {
  let size = 0;
  
  // Parse source files/directories
  const sources = args.split(' ').filter(s => !['--from', '--chown'].some(p => s.startsWith(p)));
  
  for (const src of sources) {
    if (!src || src.startsWith('--')) continue;
    
    // Estimate based on file patterns
    if (/\.tar(\.gz)?$/i.test(src)) {
      size += 50; // Archive files are typically larger
    } else if (/\.zip$/i.test(src)) {
      size += 30;
    } else if (src.includes('http://') || src.includes('https://')) {
      // URL - estimate based on common sizes
      const url = src.split(' ').find(s => s.startsWith('http'));
      if (url) {
        size += 100; // Conservative download estimate
      }
    } else if (/\.sh$/i.test(src)) {
      size += 5; // Scripts are usually small
    } else if (/\.js$|\.ts$/.test(src)) {
      size += 20; // TypeScript/JS files can be medium sized
    } else if (src.includes('node_modules') || src.includes('vendor')) {
      size += 150; // Dependencies are typically larger
    } else {
      size += 5; // Default small estimate
    }
  }

  return Math.max(size, 2);
}

export function extractBaseImages(content: string): BaseImageInfo[] {
  const images: BaseImageInfo[] = [];
  
  const lines = content.split(/\r?\n/);
  let stageIndex = 0;
  let isDefaultStage = true;

  for (const line of lines) {
    const trimmed = line.trim();
    
    if (/^\s*FROM\s+/i.test(trimmed)) {
      // Extract base image from FROM instruction
      const match = trimmed.match(/^(\w+)\s+(.*)$/);
      
      let baseImage: string | undefined;
      
      if (match && match[2].includes('AS')) {
        const parts = match[2].split(' AS ');
        baseImage = parts[0].trim();
        stageIndex++;
        isDefaultStage = false;
      } else {
        baseImage = match ? match[2].trim() : undefined;
        if (stageIndex === 0) {
          isDefaultStage = true;
        } else {
          stageIndex++;
          isDefaultStage = false;
        }
      }

      if (baseImage) {
        images.push({
          image: baseImage,
          stageIndex,
          isDefault: isDefaultStage,
        });
      }
    }
  }

  return images;
}

export function getMultiStageInfo(content: string): { 
  multiStage: boolean; 
  stages: number; 
  defaultBase?: string;
} | null {
  const result = extractBaseImages(content);
  
  if (result.length > 1) {
    return {
      multiStage: true,
      stages: result.length,
      defaultBase: result[0].image,
    };
  }

  return null;
}

export function validateDockerfile(
  content: string,
  options: { strict?: boolean } = {}
): ParseResult & { validationErrors: string[] } {
  const parseResult = parseDockerfile(content, options);
  
  // Additional validation checks
  const errors: string[] = [];

  // Check for common issues
  if (parseResult.defaultBase) {
    // Validate base image format
    const validPatterns = [/^[a-zA-Z0-9][\w.-]+:[a-zA-Z0-9._-]+$/, 
                          /^[a-zA-Z0-9][\w.-]+:latest$/];
    
    let isValidFormat = false;
    for (const pattern of validPatterns) {
      if (pattern.test(parseResult.defaultBase)) {
        isValidFormat = true;
        break;
      }
    }

    if (!isValidFormat && options.strict) {
      errors.push(`Default base image may have invalid format: ${parseResult.defaultBase}`);
    }
  }

  // Check for very large estimated layers
  const largeLayerThreshold = 500; // MB
  for (const layer of parseResult.layers) {
    if (layer.estimatedSizeMB > largeLayerThreshold && options.strict) {
      errors.push(`Large layer detected: ${Math.round(layer.estimatedSizeMB)}MB`);
    }
  }

  // Check for missing FROM instruction
  const hasFrom = parseResult.instructions.some(
    i => i.type.toUpperCase() === 'FROM'
  );

  if (!hasFrom && options.strict) {
    errors.push('Missing FROM instruction');
  }

  return { ...parseResult, validationErrors: errors };
}

// Demo / Entry point for testing
if (require.main === module) {
  const sampleDockerfile = `
# Multi-stage build example
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

COPY . .
RUN npm run build

# Production stage
FROM nginx:alpine

COPY --from=builder /app/dist /usr/share/nginx/html
COPY --from=builder /app/ssl.conf /etc/nginx/conf.d/default.conf

ENV NODE_ENV=production
EXPOSE 80
`;

  console.log('=== Dockerfile Parser Demo ===\n');

  const result = parseDockerfile(sampleDockerfile, {
    strictMode: true,
    estimateLayerSizes: true,
    includeComments: false,
  });

  console.log('Instructions:', result.instructions.length);
  console.log('Base Images:', result.baseImages.map(b => b.image).join(', '));
  console.log('Multi-stage:', result.multiStage);
  
  if (result.defaultBase) {
    console.log('Default Base:', result.defaultBase);
  }

  console.log('\nLayers:');
  for (const layer of result.layers) {
    console.log(`  - ${Math.round(layer.estimatedSizeMB)}MB`);
  }

  if (result.warnings.length > 0) {
    console.log('\nWarnings:', result.warnings.join(', '));
  }

  const validation = validateDockerfile(sampleDockerfile, { strict: true });
  
  if (validation.validationErrors.length > 0) {
    console.log('\nValidation Errors:', validation.validationErrors);
  } else {
    console.log('\nValidation: PASSED');
  }

  // Test with stream input
  const streamResult = parseDockerfile(
    require('stream').PassThrough,