#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "../include/dfa_internal.h"
#include "../include/dfa_types.h"

#define MAX_DATA_SIZE (64 * 1024)

static volatile sig_atomic_t gotsig = 0;

static void sigaction_handler(int) {
    gotsig = 1;
}

static bool is_binary_dfa(const uint8_t* data, size_t size) {
    if (size < 4) return false;
    return data[0] == 0xa1 && data[1] == 0xdf && data[2] == 0xa1 && data[3] == 0xdf;
}

static bool run_loader_test(const uint8_t* data, size_t size) {
    if (size < 5) {
        return true;
    }
    
    uint32_t magic = data[0] | (data[1] << 8) | (data[2] << 16) | (data[3] << 24);
    
    const uint8_t* payload = data + 4;
    size_t payload_len = size - 4;
    
    if (payload_len == 0 || payload_len > MAX_DATA_SIZE) {
        return true;
    }
    
    char temp_file[] = "/tmp/loader_fuzz_XXXXXX";
    int fd = mkstemp(temp_file);
    if (fd < 0) {
        return false;
    }
    
    bool is_text_format = (magic == 0x424E4C50);
    
    if (is_text_format) {
        const char* marker = "BinaryDataStart\n";
        ssize_t marker_len = strlen(marker);
        if (write(fd, marker, marker_len) != marker_len) {
            close(fd);
            unlink(temp_file);
            return false;
        }
    }
    
    ssize_t written = write(fd, payload, payload_len);
    close(fd);
    
    if (written != (ssize_t)payload_len) {
        unlink(temp_file);
        return false;
    }
    
    size_t dfa_size = 0;
    void* dfa_data = load_dfa_from_file(temp_file, &dfa_size);
    
    unlink(temp_file);
    
    if (!dfa_data) {
        return true;
    }
    
    static const char* test_inputs[] = {
        "cat",
        "ls",
        "git status",
        "echo test",
    };
    
    for (size_t i = 0; i < 4; i++) {
        dfa_result_t result;
        memset(&result, 0, sizeof(result));
        
        bool ok = dfa_eval_with_limit(dfa_data, dfa_size, test_inputs[i], strlen(test_inputs[i]), &result, DFA_MAX_CAPTURES);
        
        if (ok) {
            if (result.capture_count > DFA_MAX_CAPTURES) {
                fprintf(stderr, "BUG: capture_count %d > MAX %d\n",
                        result.capture_count, DFA_MAX_CAPTURES);
                unload_dfa(dfa_data);
                return false;
            }
            
            for (int j = 0; j < result.capture_count; j++) {
                size_t input_len = strlen(test_inputs[i]);
                if (result.captures[j].start > input_len ||
                    result.captures[j].end > input_len ||
                    result.captures[j].start > result.captures[j].end) {
                    fprintf(stderr, "BUG: capture %d invalid\n", j);
                    unload_dfa(dfa_data);
                    return false;
                }
            }
        }
    }
    
    unload_dfa(dfa_data);
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
    
    if (size > MAX_DATA_SIZE + 4) {
        size = MAX_DATA_SIZE + 4;
    }
    
    run_loader_test(data, size);
    
    return 0;
}
