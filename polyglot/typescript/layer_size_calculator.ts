import * as fs from 'fs';
import * as path from 'path';

export interface LayerInfo {
  instruction: string;
  lineNumber: number;
  estimatedSizeMB: number;
  description: string;
}

export interface SizeSummary {
  totalLayers: number;
  totalSizeMB: number;
  baseImageMB: number;
  runtimeCommandsMB: number;
  fileCopiesMB: number;
  layers: LayerInfo[];
}

interface DockerfileState {
  currentLayerSize: number;
  baseImageSize: number;
  runtimeCommandsSize: number;
  fileCopiesSize: number;
  layers: LayerInfo[];
  fromLine: number | null;
  fromTag: string | null;
}

interface ImageSizeEstimates {
  [tag: string]: number; // tag -> size in MB
}

const DEFAULT_BASE_IMAGES: ImageSizeEstimates = {
  'alpine': 5.0,
  'debian': 120.0,
  'ubuntu': 77.0,
  'node': 140.0,
  'python': 85.0,
  'golang': 130.0,
  'rust': 90.0,
};

function parseDockerfile(content: string): { instructions: string[]; lines: string[] } {
  const lines = content.split('\n');
  const instructions: string[] = [];
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line && !line.startsWith('#')) {
      // Remove inline comments and whitespace
      const cleanLine = line.split('//')[0].split('/*')[0].trim();
      if (cleanLine) {
        instructions.push({ raw: line, clean: cleanLine, index: i });
      }
    }
  }
  
  return { instructions, lines };
}

function estimateBaseImageSize(tag: string | null): number {
  if (!tag) return DEFAULT_BASE_IMAGES['alpine'] || 50.0;
  
  // Extract base image tag (handle multi-stage builds)
  const parts = tag.split(':');
  const imageRef = parts[0];
  const version = parts.length > 1 ? parts.slice(1).join(':') : 'latest';
  
  if (DEFAULT_BASE_IMAGES[imageRef]) {
    return DEFAULT_BASE_IMAGES[imageRef] * parseFloat(version) || 
           DEFAULT_BASE_IMAGES[imageRef];
  }
  
  // Default fallback for unknown images
  return 50.0;
}

function estimateCopySize(source: string, isAdd: boolean = false): number {
  if (!source) return 0;
  
  // Check if it's a glob pattern or directory
  const isGlob = source.includes('*');
  const isDir = path.isAbsolute(source) || 
                 (path.dirname(source).length > 1 && !isGlob);
  
  let estimatedSizeMB: number;
  
  if (isGlob) {
    // Estimate glob as average file size * potential count
    // A typical glob might match 10-50 files of ~10KB each
    estimatedSizeMB = isDir ? 2.0 : 0.5;
  } else if (isDir) {
    // Directory copy includes all contents recursively
    estimatedSizeMB = 1.0 + Math.random() * 5.0;
  } else {
    // Single file - estimate based on common sizes
    const ext = path.extname(source).toLowerCase();
    switch (ext) {
      case '.js':
      case '.ts':
      case '.jsx':
      case '.tsx':
        estimatedSizeMB = 0.1 + Math.random() * 2.0;
        break;
      case '.html':
      case '.css':
      case '.scss':
      case '.less':
        estimatedSizeMB = 0.05 + Math.random();
        break;
      case '.json':
        estimatedSizeMB = 0.01 + Math.random() * 0.1;
        break;
      case '.sh':
      case '.bash':
        estimatedSizeMB = 0.02 + Math.random() * 0.3;
        break;
      default:
        // Default file estimate
        estimatedSizeMB = 0.05 + Math.random();
    }
  }
  
  return isAdd ? estimatedSizeMB * 1.1 : estimatedSizeMB;
}

function estimateRunCommandSize(command: string): number {
  const lowerCmd = command.toLowerCase().trim();
  
  // Commands that typically produce larger layers (install packages, etc.)
  const largeCommands = [
    /apt-get install/,
    /apk add/,
    /yum install/,
    /dnf install/,
    /brew install/,
    /pip install/,
    /npm install/,
    /cargo install/,
    /go get/,
    /mvn install/,
    /gradle build/,
  ];
  
  // Commands that produce moderate layers (build artifacts, logs)
  const mediumCommands = [
    /gcc /,
    /g++ /,
    /cmake /,
    /make /,
    /cargo build/,
    /go build/,
    /npm run build/,
    /webpack /,
    /vite /,
  ];
  
  // Commands that produce small layers (env vars, simple scripts)
  const smallCommands = [
    /echo /,
    /mkdir /,
    /touch /,
    /chown /,
    /chmod /,
    /ln -s/,
    /cat >/,
    /tee /,
  ];
  
  let sizeMB: number;
  
  if (largeCommands.some(r => r.test(lowerCmd))) {
    // Package installation can vary widely
    const pkgCount = lowerCmd.match(/(install|add)\s+[^ ]+/g)?.length || 1;
    sizeMB = 2.0 + Math.random() * 5.0 * (pkgCount > 1 ? pkgCount : 1);
  } else if (mediumCommands.some(r => r.test(lowerCmd))) {
    // Build artifacts
    sizeMB = 1.0 + Math.random() * 3.0;
  } else if (smallCommands.some(r => r.test(lowerCmd))) {
    // Minimal impact
    sizeMB = 0.05 + Math.random() * 0.2;
  } else {
    // Unknown command - estimate conservatively
    const wordCount = lowerCmd.split(/\s+/).length;
    sizeMB = 0.1 + Math.min(2.0, wordCount * 0.05);
  }
  
  return Math.max(sizeMB, 0.05); // Minimum non-zero for any RUN command
}

function analyzeDockerfile(content: string): SizeSummary {
  const { instructions, lines } = parseDockerfile(content);
  
  let state: DockerfileState = {
    currentLayerSize: 0,
    baseImageSize: 0,
    runtimeCommandsSize: 0,
    fileCopiesSize: 0,
    layers: [],
    fromLine: null,
    fromTag: null,
  };
  
  for (const { raw, clean, index } of instructions) {
    const lineNum = lines[index].trim().length > 0 ? index + 1 : index;
    
    // Parse instruction and arguments
    const parts = clean.split(/\s+/);
    if (parts.length === 0 || !parts[0]) continue;
    
    const instruction = parts[0];
    const args = parts.slice(1).join(' ').trim();
    
    let layerSize: number = 0;
    let description: string = '';
    
    switch (instruction.toUpperCase()) {
      case 'FROM':
        state.fromLine = lineNum;
        state.fromTag = args || 'alpine';
        state.baseImageSize = estimateBaseImageSize(state.fromTag);
        layerSize = state.baseImageSize;
        description = `Base image: ${state.fromTag}`;
        break;
        
      case 'RUN':
        // RUN commands create layers from their output
        if (args) {
          const runSize = estimateRunCommandSize(args);
          layerSize = runSize;
          state.runtimeCommandsSize += runSize;
          description = `Runtime command: ${args.substring(0, 50)}${args.length > 50 ? '...' : ''}`;
        } else {
          // Empty RUN (rare but possible)
          layerSize = 0.01;
          state.runtimeCommandsSize += 0.01;
          description = `Empty RUN command`;
        }
        break;
        
      case 'COPY':
      case 'ADD':
        if (args) {
          // Handle multiple sources or source + destination
          const isAdd = instruction.toUpperCase() === 'ADD';
          
          // Split into sources and destination
          let dest: string | null = null;
          let sources: string[] = [];
          
          // Last argument is typically the destination (unless it's a glob pattern)
          if (!args.includes('*')) {
            const parts = args.split(/\s+/);
            dest = parts[parts.length - 1];
            sources = parts.slice(0, -1).join(' ');
          } else {
            // Glob patterns - last part is destination
            const globParts = args.split(/\s+/);
            if (globParts[globParts.length - 1].includes('*')) {
              dest = globParts[globParts.length - 1];
              sources = globParts.slice(0, -1).join(' ');
            } else {
              // Multiple files with same destination pattern
              sources = args;
              dest = null;
            }
          }
          
          let copySize: number = 0;
          if (sources) {
            const estimatedCopySize = estimateCopySize(sources, isAdd);
            layerSize = estimatedCopySize;
            state.fileCopiesSize += estimatedCopySize;
            description = `Copy/ADD: ${sources.substring(0, 40)}${sources.length > 40 ? '...' : ''}`;
          } else {
            // Edge case - no sources specified
            layerSize = 0.01;
            description = `COPY/ADD without source`;
          }
        } else {
          layerSize = 0.01;
          description = `Empty COPY/ADD command`;
        }
        break;
        
      case 'ENV':
      case 'ARG':
      case 'LABEL':
      case 'EXPOSE':
      case 'CMD':
      case 'ENTRYPOINT':
      case 'USER':
      case 'WORKDIR':
      case 'VOLUME':
      case 'HEALTHCHECK':
        // These create metadata layers but minimal size impact
        layerSize = 0.01;
        description = `${instruction}: ${args.substring(0, 40)}${args.length > 40 ? '...' : ''}`;
        break;
        
      case 'MAINTAINER':
      case 'STOPSIGNAL':
      case 'SHELL':
      case 'ONBUILD':
      case 'PLATFROM': // Typo in older Dockerfiles
      default:
        layerSize = 0.01;
        description = `${instruction}: ${args.substring(0, 40)}${args.length > 40 ? '...' : ''}`;
    }
    
    state.currentLayerSize += layerSize;
    state.layers.push({
      instruction: instruction,
      lineNumber: lineNum,
      estimatedSizeMB: Math.round(layerSize * 100) / 100,
      description,
    });
  }
  
  return {
    totalLayers: state.layers.length,
    totalSizeMB: Math.round(state.currentLayerSize * 100) / 100,
    baseImageMB: Math.round(state.baseImageSize * 100) / 100,
    runtimeCommandsMB: Math.round(state.runtimeCommandsSize * 100) / 100,
    fileCopiesMB: Math.round(state.fileCopiesSize * 100) / 100,
    layers: state.layers,
  };
}

export function analyzeDockerfileSync(dockerfilePath: string): SizeSummary {
  const content = fs.readFileSync(dockerfilePath, 'utf-8');
  return analyzeDockerfile(content);
}

export async function analyzeDockerfileAsync(dockerfilePath: string): Promise<SizeSummary> {
  const content = await fs.promises.readFile(dockerfilePath, 'utf-8');
  return analyzeDockerfile(content);
}

// Demo / Entry point
if (require.main === module) {
  // Default demo with a sample Dockerfile
  const sampleDockerfile = `FROM node:16-alpine AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
RUN npm run build

FROM alpine:3.18
WORKDIR /app
COPY --from=builder /app/dist/ ./dist/
CMD ["node", "dist/index.js"]`;

  // Write sample to temp file for demo
  const tempFile = path.join(__dirname, 'temp_demo.Dockerfile');
  fs.writeFileSync(tempFile, sampleDockerfile);
  
  try {
    console.log('=== ShipCheck Layer Size Calculator ===\n');
    
    const result: SizeSummary = analyzeDockerfile(sampleDockerfile);
    
    console.log(`Total Image Size Estimate: ${result.totalSizeMB.toFixed(2)} MB\n`);
    console.log(`Breakdown:`);
    console.log(`  - Base Image:     ${result.baseImageMB.toFixed(2)} MB`);
    console.log(`  - Runtime Commands: ${result.runtimeCommandsMB.toFixed(2)} MB`);
    console.log(`  - File Copies:     ${result.fileCopiesMB.toFixed(2)} MB`);
    console.log(`\nLayer Details:`);
    
    for (const layer of result.layers) {
      const padding = ' '.repeat(40 - layer.instruction.length);
      console.log(`  [${layer.lineNumber}] ${layer.instruction}${padding} ~${layer.estimatedSizeMB.toFixed(2)} MB`);
      if (layer.description) {
        console.log(`    └─ ${layer.description}`);
      }
    }
    
    // Cleanup temp file
    fs.unlinkSync(tempFile);
  } catch (error: any) {
    console.error('Error:', error.message);
    process.exit(1);
  }
}

export default analyzeDockerfile;