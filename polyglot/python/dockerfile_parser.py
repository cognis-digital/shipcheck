"""
polyglot/python/dockerfile_parser.py

Dockerfile parser for shipcheck tool.

Extracts layers, instructions, base images, environment variables,
users, and security-relevant patterns from Dockerfiles.
"""

import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional


class TokenType(Enum):
    """Token types for the lexer."""
    INSTRUCTION = auto()  # FROM, RUN, COPY, etc.
    ARG = auto()         # ARG keyword
    LABEL = auto()       # LABEL keyword
    SHELL = auto()       # SHELL instruction
    USER = auto()        # USER instruction
    WORKDIR = auto()     # WORKDIR instruction
    ENV = auto()         # ENV instruction
    EXPOSE = auto()      # EXPOSE instruction
    CMD = auto()         # CMD instruction
    ENTRYPOINT = auto()  # ENTRYPOINT instruction
    VOLUME = auto()      # VOLUME instruction
    ADD = auto()         # ADD instruction
    MAINTAINER = auto()  # MAINTAINER (deprecated)
    ONBUILD = auto()     # ONBUILD instruction
    STOPSIGNAL = auto()  # STOPSIGNAL instruction
    HEALTHCHECK = auto() # HEALTHCHECK instruction
    UNKNOWN = auto()     # Unknown instruction


class InstructionType(Enum):
    """Known Dockerfile instructions."""
    FROM = "FROM"
    RUN = "RUN"
    COPY = "COPY"
    ADD = "ADD"
    CMD = "CMD"
    ENTRYPOINT = "ENTRYPOINT"
    USER = "USER"
    WORKDIR = "WORKDIR"
    ENV = "ENV"
    EXPOSE = "EXPOSE"
    LABEL = "LABEL"
    ARG = "ARG"
    MAINTAINER = "MAINTAINER"
    SHELL = "SHELL"
    VOLUME = "VOLUME"
    ONBUILD = "ONBUILD"
    STOPSIGNAL = "STOPSIGNAL"
    HEALTHCHECK = "HEALTHCHECK"


# Known instructions that take a base image argument
BASE_IMAGE_INSTRUCTIONS = {InstructionType.FROM}

# Instructions that can contain shell commands (security relevant)
SHELL_COMMAND_INSTRUCTIONS = {
    InstructionType.RUN,
    InstructionType.CMD,
    InstructionType.ENTRYPOINT,
    InstructionType.SHELL,
}


@dataclass
class Layer:
    """Represents a single layer from a RUN/COPY/ADD instruction."""
    source: str  # Source files or command for RUN
    dest: Optional[str] = None  # Destination for COPY/ADD
    instruction_type: InstructionType = InstructionType.RUN


@dataclass
class EnvironmentVariable:
    """Represents an environment variable definition."""
    name: str
    value: str
    is_build_arg: bool = False


@dataclass
class BaseImage:
    """Represents a base image reference."""
    registry: Optional[str] = None  # e.g., "gcr.io"
    repository: str  # e.g., "python:3.9-slim"
    tag: str = "latest"
    digest: Optional[str] = None


@dataclass
class UserContext:
    """Represents user context in the image."""
    name: str
    is_root: bool = False  # True if root (uid=0)


@dataclass
class SecurityPattern:
    """Security-relevant pattern found in Dockerfile."""
    category: str
    description: str
    severity: str  # "high", "medium", "low"
    instruction: Optional[str] = None
    line_number: int = 0


@dataclass
class ParsedDockerfile:
    """Complete parsed result of a Dockerfile."""
    base_images: list[BaseImage] = field(default_factory=list)
    layers: list[Layer] = field(default_factory=list)
    env_vars: dict[str, EnvironmentVariable] = field(default_factory=dict)
    build_args: dict[str, str] = field(default_factory=dict)
    users: list[UserContext] = field(default_factory=list)
    shell_instructions: list[ShellInstruction] = field(default_factory=list)
    security_patterns: list[SecurityPattern] = field(default_factory=list)
    raw_lines: list[str] = field(default_factory=list)


@dataclass
class ShellInstruction:
    """Represents a SHELL instruction."""
    shell: str  # e.g., "/bin/bash -o pipefail"
    line_number: int


def _tokenize(content: str, lines: list[str]) -> list[tuple[TokenType, str, int]]:
    """
    Tokenize Dockerfile content.
    
    Returns list of (type, value, line_number) tuples.
    Handles multi-line commands and continuation characters.
    """
    tokens = []
    i = 0
    
    while i < len(content):
        # Skip whitespace
        if content[i].isspace():
            i += 1
            continue
        
        # Handle line continuation (backslash)
        if content[i] == '\\' and i + 1 < len(content) and not content[i + 1].isspace():
            while i + 1 < len(content) and content[i + 1] != '\n':
                i += 1
            continue
        
        # Handle line continuation at end of line
        if content[i] == '\\' and i + 1 >= len(content):
            i += 2
            continue
        
        # Read word token
        start = i
        while i < len(content) and not content[i].isspace() and content[i] != '\n':
            i += 1
        
        value = content[start:i]
        
        if not value:
            continue
            
        line_num = lines[lines.index('\n'.join(lines[:i])) + 1] if '\n' in ''.join(lines[:i]) else 1
        
        # Determine token type
        upper_value = value.upper()
        
        if upper_value == "ARG":
            tokens.append((TokenType.ARG, value, line_num))
        elif upper_value == "LABEL":
            tokens.append((TokenType.LABEL, value, line_num))
        elif upper_value == "SHELL":
            tokens.append((TokenType.SHELL, value, line_num))
        elif upper_value == "USER":
            tokens.append((TokenType.USER, value, line_num))
        elif upper_value == "WORKDIR":
            tokens.append((TokenType.WORKDIR, value, line_num))
        elif upper_value == "ENV":
            tokens.append((TokenType.ENV, value, line_num))
        elif upper_value == "EXPOSE":
            tokens.append((TokenType.EXPOSE, value, line_num))
        elif upper_value == "CMD":
            tokens.append((TokenType.CMD, value, line_num))
        elif upper_value == "ENTRYPOINT":
            tokens.append((TokenType.ENTRYPOINT, value, line_num))
        elif upper_value == "VOLUME":
            tokens.append((TokenType.VOLUME, value, line_num))
        elif upper_value == "ONBUILD":
            tokens.append((TokenType.ONBUILD, value, line_num))
        elif upper_value == "STOPSIGNAL":
            tokens.append((TokenType.STOPSIGNAL, value, line_num))
        elif upper_value == "HEALTHCHECK":
            tokens.append((TokenType.HEALTHCHECK, value, line_num))
        elif upper_value in BASE_IMAGE_INSTRUCTIONS:
            tokens.append((TokenType.INSTRUCTION, value, line_num))
        else:
            # Unknown instruction - still track it
            tokens.append((TokenType.UNKNOWN, value, line_num))
    
    return tokens


def _parse_base_image(token: str) -> Optional[BaseImage]:
    """Parse a base image reference into components."""
    token = token.strip()
    if not token:
        return None
    
    # Handle digest notation
    digest_match = re.match(r'^([^@]+):?([a-zA-Z0-9_\-\.]+)@([a-f0-9]{64})$', token)
    if digest_match:
        registry_or_repo, tag, digest = digest_match.groups()
        return BaseImage(
            repository=registry_or_repo,
            tag=tag,
            digest=digest
        )
    
    # Handle registry notation (e.g., gcr.io/project/image)
    registry_match = re.match(r'^([^/]+)(?:/[^:]+)?(/.*)?$', token)
    if registry_match:
        registry, rest = registry_match.groups()
        repo_tag = rest.lstrip('/')
        
        # Split repository and tag
        colon_pos = repo_tag.rfind(':')
        if colon_pos != -1:
            repo = repo_tag[:colon_pos]
            tag = repo_tag[colon_pos + 1:]
        else:
            repo = repo_tag
            tag = "latest"
        
        return BaseImage(
            registry=registry,
            repository=repo,
            tag=tag
        )
    
    # Simple case - just image and tag
    colon_pos = token.rfind(':')
    if colon_pos != -1:
        repo = token[:colon_pos]
        tag = token[colon_pos + 1:]
    else:
        repo = token
        tag = "latest"
    
    return BaseImage(repository=repo, tag=tag)


def _parse_layer(source: str, dest: Optional[str], 
                 instruction_type: InstructionType, line_num: int) -> Layer:
    """Parse a layer source into components."""
    # Handle multi-source COPY/ADD (e.g., COPY . /app && COPY ./lib /lib)
    sources = [source] if not ' ' in source else source.split(' ')
    
    layers = []
    for s in sources:
        s = s.strip()
        if not s:
            continue
            
        # Check if this is a multi-source copy (contains && or ; after first space)
        parts = s.split('&&')
        if len(parts) > 1:
            # First part is the source, rest are commands
            src_part = parts[0].strip()
            cmd_parts = [p.strip() for p in parts[1:] if p.strip()]
            
            # The first command might have its own source
            cmd_src = cmd_parts[0] if ' ' not in cmd_parts[0] else cmd_parts[0].split(' ', 1)[0]
            cmd_dest = cmd_parts[0].split(' ', 1)[1] if len(cmd_parts[0]) > 1 else None
            
            layers.append(Layer(
                source=src_part,
                dest=cmd_dest,
                instruction_type=instruction_type,
            ))
            
            # Add remaining commands as additional sources
            for cmd in cmd_parts[1:]:
                if ' ' not in cmd:
                    continue
                src = cmd.split(' ', 1)[0]
                dst = cmd.split(' ', 1)[1] if len(cmd) > 1 else None
                layers.append(Layer(
                    source=src,
                    dest=dst,
                    instruction_type=instruction_type,
                ))
        else:
            # Single source - check for space-separated components
            parts = s.split(' ', 2)
            if len(parts) >= 3:
                src = parts[0]
                dst = parts[1]
                layers.append(Layer(
                    source=src,
                    dest=dst,
                    instruction_type=instruction_type,
                ))
            else:
                # Just a command (RUN case)
                layers.append(Layer(
                    source=s,
                    instruction_type=instruction_type,
                ))
    
    return Layer(source=sources[0] if sources else "", 
                 dest=dest,
                 instruction_type=instruction_type,
                 line_number=line_num)


def _parse_env_var(token: str) -> Optional[EnvironmentVariable]:
    """Parse an environment variable definition."""
    token = token.strip()
    if not token or '=' not in token:
        return None
    
    eq_pos = token.find('=')
    name = token[:eq_pos].strip()
    value = token[eq_pos + 1:].strip()
    
    # Remove quotes from value
    if (value.startswith('"') and value.endswith('"')) or \
       (value.startswith("'") and value.endswith("'")):
        value = value[1:-1]
    
    return EnvironmentVariable(name=name, value=value)


def _parse_user(token: str) -> Optional[UserContext]:
    """Parse a USER instruction."""
    token = token.strip()
    if not token or ':' in token:
        # Format: "user:group" - check if group is root (0)
        parts = token.split(':')
        user_name = parts[0]
        group_num = int(parts[1]) if len(parts) > 1 else 0
        
        return UserContext(name=user_name, is_root=(group_num == 0))
    
    # Just a username - assume root unless specified otherwise
    return UserContext(name=token, is_root=False)


def _parse_shell_instruction(token: str, line_num: int) -> ShellInstruction:
    """Parse a SHELL instruction."""
    shell = token.strip() if token else "/bin/sh"
    return ShellInstruction(shell=shell, line_number=line_num)


def _detect_security_patterns(parsed: ParsedDockerfile, tokens: list[tuple[TokenType, str, int]]) -> None:
    """Detect security-relevant patterns in the parsed Dockerfile."""
    
    # Check for root user at end of image
    if not parsed.users:
        parsed.security_patterns.append(SecurityPattern(
            category="USER_CONTEXT",
            description="No USER instruction found - container runs as root by default",
            severity="medium",
            line_number=0,
        ))
    
    # Check for multiple FROM instructions (multi-stage builds)
    if len(parsed.base_images) > 1:
        parsed.security_patterns.append(SecurityPattern(
            category="MULTI_STAGE_BUILD",
            description=f"Multi-stage build detected with {len(parsed.base_images)} stages. "
                        f"Ensure final stage is minimal.",
            severity="low",
            line_number=0,
        ))
    
    # Check for large layers (heuristic: RUN commands without -f or --from)
    large_layer_count = 0
    for layer in parsed.layers:
        if layer.instruction_type == InstructionType.RUN and \
           not any(c in layer.source.lower() for c in ['-f', '--from']):
            # Heuristic: long commands might indicate large layers
            if len(layer.source) > 200:
                large_layer_count += 1
    
    if large_layer_count > 3:
        parsed.security_patterns.append(SecurityPattern(
            category="LAYER_SIZE",
            description=f"Potential large layer issue detected ({large_layer_count} long RUN commands). "
                        f"Consider using -f or --from to share layers.",
            severity="low",
            line_number=0,
        ))
    
    # Check for COPY/ADD with . (current directory)
    dot_copy_count = 0
    for layer in parsed.layers:
        if layer.instruction_type in (InstructionType.COPY, InstructionType.ADD):
            if layer.source.startswith('.') or layer.source == '.':
                dot_copy_count += 1
    
    if dot_copy_count > 2:
        parsed.security_patterns.append(SecurityPattern(
            category="COPY_PATTERN",
            description=f"Multiple COPY . instructions found ({dot_copy_count}). "
                        f"Consider using COPY --from= to share layers.",
            severity="low",
            line_number=0,
        ))


def _extract_env_vars(tokens: list[tuple[TokenType, str, int]]) -> dict[str, EnvironmentVariable]:
    """Extract all environment variables from tokens."""
    env_vars = {}
    
    for token_type, value, line_num in tokens:
        if token_type == TokenType.ENV:
            # ENV can be "KEY=VALUE" or "KEY VALUE" format
            parts = value.split(' ', 1)
            if len(parts) >= 2 and '=' not in parts[0]:
                # "KEY VALUE" format - assume first part is key, rest is value
                name = parts[0]
                env_vars[name] = EnvironmentVariable(name=name, value=' '.join(parts[1:]))
            elif len(parts) == 2 and '=' in parts[0]:
                # "KEY=VALUE" format
                eq_pos = parts[0].find('=')
                name = parts[0][:eq_pos]
                env_vars[name] = EnvironmentVariable(name=name, value=parts[0][eq_pos+1:])
    
    return env_vars


def _extract_build_args(tokens: list[tuple[TokenType, str, int]]) -> dict[str, str]:
    """Extract build arguments from tokens."""
    build_args = {}
    
    for token_type, value, line_num in tokens:
        if token_type == TokenType.ARG:
            # ARG can be "KEY" or "KEY=VALUE" format
            parts = value.split('=', 1)
            name = parts[0]
            build_args[name] = parts[1] if len(parts) > 1 else ""
    
    return build_args


def _extract_users(tokens: list[tuple[TokenType, str, int]]) -> list[UserContext]:
    """Extract USER instructions from tokens."""
    users = []
    
    for token_type, value, line_num in tokens:
        if token_type == TokenType.USER:
            user_ctx = _parse_user(value)
            if user_ctx:
                users.append(user_ctx)
    
    return users


def _extract_shell_instructions(tokens: list[tuple[TokenType, str, int]]) -> list[ShellInstruction]:
    """Extract SHELL instructions from tokens."""
    shell_instrs = []
    
    for token_type,