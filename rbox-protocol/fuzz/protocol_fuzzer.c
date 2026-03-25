// LibFuzzer harness for rbox-protocol (C version)
// Fuzzes: header validation, response parsing, request building, command parsing

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "rbox_protocol.h"
#include "rbox_protocol_defs.h"

// Fuzzer entry point - called by libfuzzer
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length) {
    if (length == 0) return 0;

    // === Test 1: Header validation ===
    if (length >= RBOX_HEADER_SIZE) {
        rbox_header_validate((const char*)data, length);
    }

    // === Test 2: Header decoding ===
    rbox_decoded_header_t header;
    rbox_response_details_t details;
    memset(&header, 0, sizeof(header));
    memset(&details, 0, sizeof(details));
    rbox_decode_header((const char*)data, length, &header);
    rbox_decode_response_details(&header, (const char*)data, length, &details);

    // === Test 3: Env decisions decoding ===
    rbox_env_decisions_t env_decisions;
    memset(&env_decisions, 0, sizeof(env_decisions));
    rbox_decode_env_decisions(&header, &details, (const char*)data, length, &env_decisions);
    rbox_free_env_decisions(&env_decisions);

    // === Test 4: Checksum calculation ===
    for (size_t len = 1; len <= length && len <= 256; len++) {
        rbox_calculate_checksum_crc32(0, data, len);
    }

    // === Test 5: Command parsing ===
    // Create a null-terminated string from fuzz data
    char cmd_str[256];
    size_t cmd_len = 0;
    for (size_t i = 0; i < length && cmd_len < 255; i++) {
            cmd_str[cmd_len++] = data[i];
    }
    cmd_str[cmd_len] = 0;

    if (cmd_len > 0) {
        // Test rbox_command_parse
        rbox_parse_result_t parse;
        memset(&parse, 0, sizeof(parse));
        rbox_command_parse(cmd_str, cmd_len, &parse);

        // Test rbox_get_command_name - needs command + parse
        const char *cmd_name = rbox_get_command_name(cmd_str, &parse);
        (void)cmd_name;
    }

    // === Test 6: Request building ===
    if (length >= 2) {
        char *packet = malloc(4096);
        if (!packet) return 0;
        size_t plen = 0;
        const char* args[] = {"test"};

        // Use first word of fuzz data as command
        char cmd[32];
        size_t j = 0;
        for (size_t i = 0; i < length && j < 31 && data[i] >= 32 && data[i] < 127; i++) {
            cmd[j++] = data[i];
        }
        cmd[j] = 0;

        if (j > 0) {
            char *caller = "fuzzer";          // Caller name
            char *syscall = NULL;             // Syscall name (or set as needed)
            int env_var_count = 0;            // Number of environment variables
            const char **env_var_names = NULL; // Environment variable names
            const float *env_var_scores = NULL; // Environment variable scores

            rbox_build_request(packet, 4096, &plen, cmd, caller, syscall, 1, args,
                               env_var_count, env_var_names, env_var_scores);

            // === Test 7: Response building ===
            char *resp = NULL;
            size_t rlen = 0;
            uint8_t decision = (data[0] % 2);  // 0 = allow, 1 = deny
            rbox_build_response(decision, "test reason", 0, 0, 0, NULL, &resp, &rlen);
            free(resp);
        }
        free(packet);
    }

    // === Test 8: Hash function ===
    if (length >= 4) {
        uint64_t h = rbox_hash64((const char*)data, length);
        (void)h;
    }

    // === Test 9: Error strings ===
    for (int err = 0; err < 20; err++) {
        const char *estr = rbox_strerror(err);
        (void)estr;
    }

    return 0;
}
