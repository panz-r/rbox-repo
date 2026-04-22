#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <ctype.h>

#include "../include/pipeline.h"
#include "../include/dfa_types.h"
#include "../include/dfa_internal.h"

#define MAX_PATTERN_SIZE 4096
#define MAX_EVAL_INPUT 256

static volatile sig_atomic_t gotsig = 0;

static void sigaction_handler(int) {
    gotsig = 1;
}

static bool extract_commands_from_pattern(const char* pattern_data, size_t pattern_len,
                                          char* commands[], size_t* cmd_count, size_t max_cmds) {
    *cmd_count = 0;
    
    const char* line_start = pattern_data;
    const char* data_end = pattern_data + pattern_len;
    
    while (line_start < data_end && *cmd_count < max_cmds) {
        const char* line_end = line_start;
        while (line_end < data_end && *line_end != '\n' && *line_end != '\r') {
            line_end++;
        }
        
        size_t line_len = line_end - line_start;
        if (line_len > 0 && line_start[0] == '[') {
            const char* bracket_end = (const char*)memchr(line_start, ']', line_len);
            if (bracket_end) {
                const char* after_bracket = bracket_end + 1;
                size_t remaining = line_len - (after_bracket - line_start);
                
                while (remaining > 0 && isspace((unsigned char)after_bracket[0])) {
                    after_bracket++;
                    remaining--;
                }
                
                if (remaining > 0) {
                    size_t cmd_len = remaining;
                    while (cmd_len > 0 && isspace((unsigned char)after_bracket[cmd_len - 1])) {
                        cmd_len--;
                    }
                    
                    if (cmd_len > 0 && cmd_len < MAX_EVAL_INPUT) {
                        memcpy(commands[*cmd_count], after_bracket, cmd_len);
                        commands[*cmd_count][cmd_len] = '\0';
                        (*cmd_count)++;
                    }
                }
            }
        }
        
        line_start = line_end;
        while (line_start < data_end && (*line_start == '\n' || *line_start == '\r')) {
            line_start++;
        }
    }
    
    return *cmd_count > 0;
}

static bool run_pipeline(const uint8_t* data, size_t size, bool verbose) {
    if (size < 4) {
        return false;
    }
    
    uint32_t config = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    
    int minimize_algo = config & 0x3;
    bool compress = (config >> 2) & 0x1;
    bool optimize_layout = (config >> 3) & 0x1;
    bool preminimize = (config >> 4) & 0x1;
    bool use_sat = (config >> 5) & 0x1;
    
    const char* pattern_start = (const char*)(data + 4);
    size_t pattern_len = 0;
    while (4 + pattern_len < size && pattern_start[pattern_len] != '\0') {
        pattern_len++;
    }
    if (pattern_len == 0) {
        return false;
    }
    
    char temp_pattern_file[] = "/tmp/pipeline_fuzz_XXXXXX.txt";
    int fd = mkstemp(temp_pattern_file);
    if (fd < 0) {
        return false;
    }
    
    ssize_t written = write(fd, pattern_start, pattern_len);
    close(fd);
    
    if (written != (ssize_t)pattern_len) {
        unlink(temp_pattern_file);
        return false;
    }
    
    pipeline_config_t cfg = {
        .minimize_algo = minimize_algo,
        .verbose = verbose,
        .compress = compress,
        .optimize_layout = optimize_layout,
        .max_states = 0,
        .max_symbols = 0
    };
    
    pipeline_t* p = pipeline_create(&cfg);
    if (!p) {
        unlink(temp_pattern_file);
        return false;
    }
    
    pipeline_error_t err = pipeline_parse_patterns(p, temp_pattern_file);
    if (err != PIPELINE_OK) {
        pipeline_destroy(p);
        unlink(temp_pattern_file);
        return true;
    }
    
    err = pipeline_build_nfa(p);
    if (err != PIPELINE_OK) {
        pipeline_destroy(p);
        unlink(temp_pattern_file);
        return true;
    }
    
    err = pipeline_convert_to_dfa(p);
    if (err != PIPELINE_OK) {
        pipeline_destroy(p);
        unlink(temp_pattern_file);
        return true;
    }
    
    err = pipeline_minimize_dfa(p, minimize_algo);
    if (err != PIPELINE_OK) {
        pipeline_destroy(p);
        unlink(temp_pattern_file);
        return true;
    }
    
    if (compress) {
        err = pipeline_compress(p);
        if (err != PIPELINE_OK) {
            pipeline_destroy(p);
            unlink(temp_pattern_file);
            return true;
        }
    }
    
    if (optimize_layout) {
        err = pipeline_optimize_layout(p);
        if (err != PIPELINE_OK) {
            pipeline_destroy(p);
            unlink(temp_pattern_file);
            return true;
        }
    }
    
    size_t binary_size = 0;
    const uint8_t* binary = pipeline_get_binary(p, &binary_size);
    
    if (binary && binary_size > 0) {
        char cmd_bufs[8][MAX_EVAL_INPUT];
        char* commands[8];
        for (int i = 0; i < 8; i++) {
            commands[i] = cmd_bufs[i];
        }
        size_t cmd_count = 0;
        
        if (!extract_commands_from_pattern(pattern_start, pattern_len, commands, &cmd_count, 8)) {
            static const char* fallback_cmds[] = {
                "cat", "ls", "git status", "echo test"
            };
            for (size_t i = 0; i < 4 && i < 8; i++) {
                size_t len = strlen(fallback_cmds[i]);
                memcpy(commands[i], fallback_cmds[i], len);
                commands[i][len] = '\0';
                cmd_count++;
            }
        }
        
        for (size_t i = 0; i < cmd_count; i++) {
            dfa_result_t result;
            memset(&result, 0, sizeof(result));
            
            bool ok = dfa_eval_with_limit(binary, binary_size, commands[i], strlen(commands[i]), &result, DFA_MAX_CAPTURES);
            
            if (ok) {
                if (result.capture_count > DFA_MAX_CAPTURES) {
                    fprintf(stderr, "BUG: capture_count %d > MAX %d\n",
                            result.capture_count, DFA_MAX_CAPTURES);
                    pipeline_destroy(p);
                    unlink(temp_pattern_file);
                    return false;
                }
                
                for (int j = 0; j < result.capture_count; j++) {
                    size_t input_len = strlen(commands[i]);
                    if (result.captures[j].start > input_len ||
                        result.captures[j].end > input_len ||
                        result.captures[j].start > result.captures[j].end) {
                        fprintf(stderr, "BUG: capture %d invalid bounds\n", j);
                        pipeline_destroy(p);
                        unlink(temp_pattern_file);
                        return false;
                    }
                }
            }
        }
    }
    
    pipeline_destroy(p);
    unlink(temp_pattern_file);
    return true;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (gotsig) {
        return 0;
    }
    
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigaction_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
    
    if (size > MAX_PATTERN_SIZE + 4) {
        size = MAX_PATTERN_SIZE + 4;
    }
    
    run_pipeline(data, size, false);
    
    return 0;
}
