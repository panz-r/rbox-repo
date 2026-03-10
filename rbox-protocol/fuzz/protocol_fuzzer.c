// LibFuzzer harness for rbox-protocol (C version)
// Fuzzes: header validation, response parsing, request building

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "rbox_protocol.h"
#include "rbox_protocol_defs.h"

// Fuzzer entry point - called by libfuzzer
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t length) {
    if (length == 0) return 0;
    if (length > 8192) length = 8192;
    
    // Test header validation (if we have enough data)
    if (length >= sizeof(rbox_header_t)) {
        rbox_header_validate((const rbox_header_t*)data);
    }
    
    // Test response parsing
    uint8_t decision = 0;
    rbox_parse_response((const char*)data, length, &decision);
    
    // Test checksum calculation (various lengths)
    for (size_t len = 1; len <= length && len <= 256; len++) {
        rbox_calculate_checksum(data, len);
    }
    
    // Test request building (if we have some data)
    if (length >= 2) {
        char cmd[32];
        size_t cmd_len = 0;
        for (size_t i = 0; i < length && cmd_len < 31; i++) {
            if (data[i] >= 32 && data[i] < 127) {
                cmd[cmd_len++] = data[i];
            }
        }
        cmd[cmd_len] = 0;
        
        if (cmd_len > 0) {
            char packet[4096];
            size_t plen = 0;
            const char* args[] = {"test"};
            rbox_build_request(packet, &plen, cmd, 1, args);
        }
    }
    
    return 0;
}
