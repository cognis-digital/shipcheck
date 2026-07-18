#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/stat.h>

#define MAX_LINE 4096
#define MAX_LAYERS 1024
#define BASE_IMAGE_SIZE (50 * 1024 * 1024) /* 50MB default */

typedef struct {
    char name[256];
    size_t estimated_size;
    int is_base;
} LayerInfo;

static LayerInfo layers[MAX_LAYERS];
static int layer_count = 0;
static char current_layer_name[256] = "";
static long long total_estimated_size = BASE_IMAGE_SIZE;

/* Get file size in bytes */
static size_t get_file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) == 0) {
        return (size_t)st.st_size;
    }
    return 1024; /* Default for unknown files */
}

/* Parse a single Dockerfile line and update layer tracking */
static void parse_line(const char *line) {
    int i, j;
    char cmd[256] = "";
    char args[MAX_LINE];
    
    if (strlen(line) == 0 || line[0] == '#') return;

    /* Trim leading whitespace and get command */
    for (i = 0; i < MAX_LINE && isspace((unsigned char)line[i]); i++) {
        ;
    }
    if (line[i] == '\0' || line[i] == '#') return;

    strncpy(cmd, &line[i], sizeof(cmd) - 1);
    cmd[sizeof(cmd) - 1] = '\0';

    /* Find end of command */
    for (i = 0; i < MAX_LINE && !isspace((unsigned char)line[i]); i++) {
        ;
    }
    strncpy(args, &line[i], sizeof(args) - 1);
    args[sizeof(args) - 1] = '\0';

    /* Handle FROM instruction */
    if (strncmp(cmd, "FROM", 4) == 0) {
        char image[256];
        int found_space = 0;
        
        for (i = 0; i < sizeof(image); i++) {
            if (!found_space && isspace((unsigned char)cmd[i])) {
                break;
            }
            image[i] = cmd[i];
            if (cmd[i] == ' ') found_space = 1;
        }
        image[found_space ? sizeof(image) - 1 : i] = '\0';

        /* Reset layer tracking for new base */
        if (layer_count > 0) {
            layers[layer_count - 1].estimated_size += total_estimated_size;
        }
        
        strncpy(current_layer_name, image, sizeof(current_layer_name) - 1);
        current_layer_name[sizeof(current_layer_name) - 1] = '\0';
        layer_count = 0;
        total_estimated_size = BASE_IMAGE_SIZE;

        printf("  [BASE] %s\n", image);
        return;
    }

    /* Handle ADD and COPY */
    if (strncmp(cmd, "ADD ", 4) == 0 || strncmp(cmd, "COPY ", 5) == 0) {
        char src[256];
        long long file_size = 1024;
        
        /* Extract source path */
        for (i = 0; i < MAX_LINE && !isspace((unsigned char)args[i]); i++) {
            ;
        }
        strncpy(src, args, sizeof(src) - 1);
        src[sizeof(src) - 1] = '\0';

        /* Check if source is a file in current directory */
        size_t fs = get_file_size(src);
        
        printf("  [COPY/ADD] %s -> +%.2f MB\n", 
               src, (double)fs / 1048576.0);
        
        total_estimated_size += fs;
        layer_count++;

        /* Track this layer */
        strncpy(layers[layer_count - 1].name, current_layer_name, sizeof(layers[0].name) - 1);
        layers[layer_count - 1].estimated_size = total_estimated_size;
        layers[layer_count - 1].is_base = (layer_count == 1);

        return;
    }

    /* Handle ENV and ARG */
    if (strncmp(cmd, "ENV ", 4) == 0 || strncmp(cmd, "ARG ", 4) == 0) {
        printf("  [META] %s\n", cmd);
        return;
    }

    /* Handle RUN - estimate based on command length */
    if (strncmp(cmd, "RUN ", 4) == 0) {
        long long run_estimate = 256 * 1024; /* Default 256KB for shell commands */
        
        /* Heuristic: longer commands might produce more output */
        size_t cmd_len = strlen(args);
        if (cmd_len > 100) {
            run_estimate += (cmd_len - 100) * 4096;
        }

        printf("  [RUN] %s\n", args);
        printf("    Est. output: +%.2f MB\n", (double)run_estimate / 1048576.0);
        
        total_estimated_size += run_estimate;
        layer_count++;

        strncpy(layers[layer_count - 1].name, current_layer_name, sizeof(layers[0].name) - 1);
        layers[layer_count - 1].estimated_size = total_estimated_size;
        layers[layer_count - 1].is_base = (layer_count == 1);

        return;
    }

    /* Handle other instructions */
    if (strncmp(cmd, "RUN ", 4) != 0 && 
        strncmp(cmd, "COPY ", 5) != 0 && 
        strncmp(cmd, "ADD ", 4) != 0 &&
        strncmp(cmd, "FROM", 4) != 0 &&
        strncmp(cmd, "ENV ", 4) != 0 &&
        strncmp(cmd, "ARG ", 4) != 0) {
        
        /* Default estimate for unknown instructions */
        printf("  [OTHER] %s\n", cmd);
    }
}

/* Print final summary */
static void print_summary(void) {
    printf("\n=== LAYER SIZE SUMMARY ===\n");
    printf("Total estimated size: %.2f MB\n\n", (double)total_estimated_size / 1048576.0);
    
    if (layer_count > 0) {
        printf("Layer breakdown:\n");
        for (int i = 0; i < layer_count; i++) {
            printf("  %2d: %.2f MB\n", 
                   i + 1,
                   (double)(layers[i].estimated_size - layers[i > 0 ? i - 1 : 0].is_base ? 0 : 0) / 1048576.0);
        }
    }
}

/* Parse entire Dockerfile */
static int parse_dockerfile(const char *filename) {
    FILE *fp;
    char line[MAX_LINE];
    int result = 0;

    fp = fopen(filename, "r");
    if (!fp) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return 1;
    }

    printf("Parsing Dockerfile: %s\n", filename);
    printf("\n--- LAYER ANALYSIS ---\n");

    while (fgets(line, sizeof(line), fp)) {
        parse_line(line);
    }

    fclose(fp);
    print_summary();
    
    return result;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <Dockerfile>\n", argv[0]);
        printf("\nExample:\n");
        printf("  %s Dockerfile\n", argv[0]);
        
        /* Demo with embedded Dockerfile */
        printf("\n--- DEMO MODE (embedded Dockerfile) ---\n");
        
        const char *demo_dockerfile = 
            "FROM ubuntu:22.04\n"
            "ENV APP=shipcheck\n"
            "RUN apt-get update && apt-get install -y curl wget\n"
            "COPY . /app/\n"
            "ADD https://example.com/config.yaml /etc/app/\n"
            "RUN make build\n"
            "CMD [\"./app\"]\n";

        /* Write demo to temp file */
        FILE *tmp = tmpfile();
        fprintf(tmp, "%s", demo_dockerfile);
        rewind(tmp);
        
        char buffer[4096];
        size_t n;
        while ((n = fread(buffer, 1, sizeof(buffer), tmp)) > 0) {
            parse_line((char*)buffer);
        }
        fclose(tmp);

        printf("\nDemo complete.\n");
    } else {
        parse_dockerfile(argv[1]);
    }

    return 0;
}