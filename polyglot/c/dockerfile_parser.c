#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

/* ============================================================================
   Data Structures
   ============================================================================ */

typedef enum {
    INSTRUCTION_FROM,
    INSTRUCTION_RUN,
    INSTRUCTION_COPY,
    INSTRUCTION_ADD,
    INSTRUCTION_ARG,
    INSTRUCTION_ENV,
    INSTRUCTION_WORKDIR,
    INSTRUCTION_USER,
    INSTRUCTION_EXPOSE,
    INSTRUCTION_LABEL,
    INSTRUCTION_CMD,
    INSTRUCTION_ENTRYPOINT,
    INSTRUCTION_HEALTHCHECK,
    INSTRUCTION_ONBUILD,
    INSTRUCTION_STOP,
    INSTRUCTION_VOLUME,
    INSTRUCTION_SHELL,
    INSTRUCTION_MANTAINER,
    INSTRUCTION_PLATFROM,
    INSTRUCTION_UNKNOWN
} InstructionType;

typedef struct {
    char *name;
    size_t name_len;
    char *args;
    size_t args_len;
    InstructionType type;
} Instruction;

typedef enum {
    STAGE_DEFAULT,
    STAGE_BUILD,
    STAGE_RUNTIME,
    STAGE_TEST,
    STAGE_PRODUCTION,
    STAGE_CUSTOM
} StageName;

typedef struct {
    char *name;
    size_t name_len;
    int is_default;
    int has_platform;
    char platform[64];
} StageInfo;

typedef enum {
    VAR_TYPE_ARG,
    VAR_TYPE_ENV,
    VAR_TYPE_LABEL
} VarType;

typedef struct {
    char *name;
    size_t name_len;
    char *value;
    size_t value_len;
    VarType type;
    int is_undeclared;
} Variable;

typedef enum {
    STATE_INITIAL,
    STATE_READING_FROM,
    STATE_IN_FROM_ARGS,
    STATE_IN_RUN_CMD,
    STATE_IN_COPY_SRC,
    STATE_IN_ADD_SRC,
    STATE_IN_ARG_VALUE,
    STATE_IN_ENV_VALUE,
    STATE_IN_LABEL_KEY,
    STATE_IN_LABEL_VALUE,
    STATE_IN_MULTI_LINE
} ParseState;

typedef struct {
    char *filename;
    size_t filename_len;
    
    /* Current parsing state */
    ParseState state;
    InstructionType current_type;
    int in_multiline;
    int multiline_char;
    size_t line_num;
    size_t total_lines;
    
    /* Multi-stage build tracking */
    StageInfo *stages;
    size_t stages_count;
    size_t stages_capacity;
    int current_stage_idx;
    char current_stage_name[256];
    int is_multistage;
    
    /* Variable tracking */
    Variable *args;
    size_t args_count;
    size_t args_capacity;
    Variable *envs;
    size_t envs_count;
    size_t envs_capacity;
    Variable *labels;
    size_t labels_count;
    size_t labels_capacity;
    
    /* Statistics */
    size_t total_instructions;
    size_t from_count;
    size_t run_count;
    size_t copy_count;
    size_t add_count;
    size_t arg_count;
    size_t env_count;
    size_t layer_count;
    
    /* Error tracking */
    char *error_msg;
    int error_found;
} DockerfileContext;

/* ============================================================================
   Utility Functions
   ============================================================================ */

static void init_context(DockerfileContext *ctx, const char *filename) {
    ctx->filename = filename ? strdup(filename) : NULL;
    if (ctx->filename) {
        ctx->filename_len = strlen(ctx->filename);
    } else {
        ctx->filename_len = 0;
    }
    
    ctx->state = STATE_INITIAL;
    ctx->current_type = INSTRUCTION_UNKNOWN;
    ctx->in_multiline = 0;
    ctx->multiline_char = '\n';
    ctx->line_num = 0;
    ctx->total_lines = 0;
    
    /* Initialize stages */
    ctx->stages = NULL;
    ctx->stages_count = 0;
    ctx->stages_capacity = 0;
    ctx->current_stage_idx = -1;
    strcpy(ctx->current_stage_name, "default");
    ctx->is_multistage = 0;
    
    /* Initialize variables */
    ctx->args = NULL;
    ctx->args_count = 0;
    ctx->args_capacity = 0;
    ctx->envs = NULL;
    ctx->envs_count = 0;
    ctx->envs_capacity = 0;
    ctx->labels = NULL;
    ctx->labels_count = 0;
    ctx->labels_capacity = 0;
    
    /* Initialize statistics */
    ctx->total_instructions = 0;
    ctx->from_count = 0;
    ctx->run_count = 0;
    ctx->copy_count = 0;
    ctx->add_count = 0;
    ctx->arg_count = 0;
    ctx->env_count = 0;
    ctx->layer_count = 0;
    
    /* Initialize error */
    ctx->error_msg = NULL;
    ctx->error_found = 0;
}

static void free_context(DockerfileContext *ctx) {
    if (ctx->filename) {
        free(ctx->filename);
    }
    
    for (size_t i = 0; i < ctx->stages_count; i++) {
        free(ctx->stages[i].name);
    }
    free(ctx->stages);
    
    for (size_t i = 0; i < ctx->args_count; i++) {
        free(ctx->args[i].name);
        free(ctx->args[i].value);
    }
    free(ctx->args);
    
    for (size_t i = 0; i < ctx->envs_count; i++) {
        free(ctx->envs[i].name);
        free(ctx->envs[i].value);
    }
    free(ctx->envs);
    
    for (size_t i = 0; i < ctx->labels_count; i++) {
        free(ctx->labels[i].name);
        free(ctx->labels[i].value);
    }
    free(ctx->labels);
}

static void add_stage(DockerfileContext *ctx, const char *name) {
    if (ctx->stages_count >= ctx->stages_capacity) {
        size_t new_cap = ctx->stages_capacity == 0 ? 4 : ctx->stages_capacity * 2;
        StageInfo *new_stages = realloc(ctx->stages, sizeof(StageInfo) * new_cap);
        if (!new_stages) {
            return;
        }
        ctx->stages = new_stages;
        ctx->stages_capacity = new_cap;
    }
    
    StageInfo *stage = &ctx->stages[ctx->stages_count];
    stage->name = strdup(name);
    stage->name_len = strlen(stage->name);
    stage->is_default = 0;
    stage->has_platform = 0;
    stage->platform[0] = '\0';
    
    ctx->stages_count++;
}

static void add_variable(DockerfileContext *ctx, VariableType type, 
                         const char *name, const char *value) {
    size_t cap = 4;
    if (type == VAR_TYPE_ARG && ctx->args_count >= ctx->args_capacity) {
        cap = ctx->args_capacity == 0 ? 4 : ctx->args_capacity * 2;
        Variable *new_args = realloc(ctx->args, sizeof(Variable) * cap);
        if (!new_args) return;
        ctx->args = new_args;
        ctx->args_capacity = cap;
    } else if (type == VAR_TYPE_ENV && ctx->envs_count >= ctx->envs_capacity) {
        cap = ctx->envs_capacity == 0 ? 4 : ctx->envs_capacity * 2;
        Variable *new_envs = realloc(ctx->envs, sizeof(Variable) * cap);
        if (!new_envs) return;
        ctx->envs = new_envs;
        ctx->envs_capacity = cap;
    } else if (type == VAR_TYPE_LABEL && ctx->labels_count >= ctx->labels_capacity) {
        cap = ctx->labels_capacity == 0 ? 4 : ctx->labels_capacity * 2;
        Variable *new_labels = realloc(ctx->labels, sizeof(Variable) * cap);
        if (!new_labels) return;
        ctx->labels = new_labels;
        ctx->labels_capacity = cap;
    }
    
    Variable *var;
    if (type == VAR_TYPE_ARG) {
        var = &ctx->args[ctx->args_count];
    } else if (type == VAR_TYPE_ENV) {
        var = &ctx->envs[ctx->envs_count];
    } else {
        var = &ctx->labels[ctx->labels_count];
    }
    
    var->name = strdup(name);
    var->name_len = strlen(name);
    var->value = value ? strdup(value) : NULL;
    if (var->value) {
        var->value_len = strlen(var->value);
    } else {
        var->value_len = 0;
    }
    var->type = type;
    var->is_undeclared = 1;
    
    if (type == VAR_TYPE_ARG) ctx->args_count++;
    else if (type == VAR_TYPE_ENV) ctx->envs_count++;
    else ctx->labels_count++;
}

static void trim_whitespace(char *str, size_t len) {
    while (len > 0 && isspace((unsigned char)str[0])) str++, len--;
    while (len > 0 && isspace((unsigned char)str[len - 1])) str[--len] = '\0';
}

static void trim_newline(char *str, size_t len) {
    if (len > 0 && str[len - 1] == '\n') str[--len] = '\0';
    else if (len > 0 && str[len - 1] == '\r') str[--len] = '\0';
}

static char *skip_whitespace(const char *s, size_t len) {
    while (len > 0 && isspace((unsigned char)*s)) s++, len--;
    return (char *)s;
}

/* ============================================================================
   Line Parsing Functions
   ============================================================================ */

static int is_comment_line(const char *line, size_t len) {
    const char *p = skip_whitespace((const char *)line, len);
    if (*p == '#' || *p == '\0') return 1;
    return 0;
}

static int is_empty_line(const char *line, size_t len) {
    const char *p = skip_whitespace((const char *)line, len);
    return p[0] == '\0';
}

static void parse_from_instruction(DockerfileContext *ctx, 
                                    const char *rest, size_t rest_len) {
    /* FROM image:tag [--platform=arch] [AS stage-name] */
    ctx->current_type = INSTRUCTION_FROM;
    
    /* Check for --platform flag */
    if (rest_len >= 12 && strncmp(rest, "--platform=", 11) == 0) {
        const char *plat_start = rest + 11;
        size_t plat_len = rest_len - 11;
        
        /* Find the end of platform value */
        while (plat_len > 0 && !isspace((unsigned char)*plat_start)) {
            plat_start++, plat_len--;
        }
        
        strncpy(ctx->stages[ctx->current_stage_idx].platform, 
                plat_start, plat_len);
        ctx->stages[ctx->current_stage_idx].has_platform = 1;
    }
    
    /* Check for AS stage name */
    if (rest_len >= 2 && strncmp(rest, "AS ", 2) == 0) {
        const char *name_start = rest + 2;
        size_t name_len = rest_len - 2;
        
        while (name_len > 0 && !isspace((unsigned char)*name_start)) {
            name_start++, name_len--;
        }
        
        strncpy(ctx->current_stage_name, name_start, name_len);
    } else if (rest_len >= 3) {
        /* Default stage name */
        const char *name_start = rest;
        size_t name_len = rest_len;
        
        while (name_len > 0 && !isspace((unsigned char)*name_start)) {
            name_start++, name_len--;
        }
        
        strncpy(ctx->current_stage_name, name_start, name_len);
    }
    
    ctx->stages[ctx->current_stage_idx].is_default = 
        (strcmp(ctx->current_stage_name, "default") == 0);
}

static void parse_run_instruction(DockerfileContext *ctx,
                                   const char *rest, size_t rest_len) {
    /* RUN command */
    ctx->current_type = INSTRUCTION_RUN;
    
    /* Extract the command (skip any leading flags like --mount=type=cache) */
    const char *cmd_start = skip_whitespace(rest, rest_len);
    if (*cmd_start == '\0') {
        cmd_start++;
    }
    
    ctx->total_instructions++;
}

static void parse_copy_instruction(DockerfileContext *ctx,
                                    const char *rest, size_t rest_len) {
    /* COPY [--from=stage] [--chown=user:group] <src>... <dest> */
    ctx->current_type = INSTRUCTION_COPY;
    
    /* Check for --from flag (multi-stage copy) */
    if (rest_len >= 8 && strncmp(rest, "--from=", 7) == 0) {
        const char *from_start = rest + 7;
        size_t from_len = rest_len - 7;
        
        while (from_len > 0 && !isspace((unsigned char)*from_start)) {
            from_start++, from_len--;
        }
        
        strncpy(ctx->current_stage_name, from_start, from_len);
    }
    
    ctx->total_instructions++;
}

static void parse_add_instruction(DockerfileContext *ctx,
                                   const char *rest, size_t rest_len) {
    /* ADD [--from=stage] <src>... <dest> */
    ctx->current_type = INSTRUCTION_ADD;
    
    /* Check for --from flag (multi-stage add) */
    if (rest_len >= 8 && strncmp(rest, "--from=", 7) == 0) {
        const char *from_start = rest + 7;
        size_t from_len = rest_len - 7;
        
        while (from_len > 0 && !isspace((unsigned char)*from_start)) {
            from_start++, from_len--;
        }
        
        strncpy(ctx->current_stage_name, from_start, from_len);
    }
    
    ctx->total_instructions++;
}

static void parse_arg_instruction(DockerfileContext *ctx,
                                   const char *rest, size_t rest_len) {
    /* ARG <name>[=<default>] */
    ctx->current_type = INSTRUCTION_ARG;
    
    /* Find the equals sign if present */
    const char *eq_pos = strchr(rest, '=');
    int has_default = 0;
    size_t name_start, name_len, value_start, value_len;
    
    if (eq_pos) {
        name_start = rest;
        name_len = eq_pos - rest;
        value_start = eq_pos + 1;
        value_len = rest_len - (value_start - rest);
        
        /* Remove quotes from default value */
        if (value_len > 0 && 
            ((value_start[0] == '"' && value_start[value_len-1] == '"') ||
             (value_start[0] == '\'' && value_start[value_len-1] == '\''))) {
            size_t quote_len = 2;
            if (value_start[0] == '"' || value_start[0] == '\'') {
                quote_len = 2;
            }
            
            char *quoted_value = malloc(value_len + 1);
            strncpy(quoted_value, value_start, value_len - quote_len);
            quoted_value[value_len - quote_len] = '\0';
            
            add_variable(ctx, VAR_TYPE_ARG, 
                        (char *)name_start