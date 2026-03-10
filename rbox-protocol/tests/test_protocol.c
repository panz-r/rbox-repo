/*
 * test_protocol.c - Basic test for rbox-protocol
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rbox_protocol.h"

/* Test header validation */
void test_header_validate(void) {
    printf("Testing header validation...\n");
    
    rbox_header_t header;
    
    /* Valid header */
    memset(&header, 0, sizeof(header));
    header.magic = RBOX_MAGIC;
    header.version = RBOX_VERSION;
    header.flags = RBOX_FLAG_FIRST;
    header.chunk_len = 100;
    header.total_len = 100;
    /* Calculate checksum over 84 bytes (v5 protocol, excluding checksum field at offset 84) */
    header.checksum = 0;
    header.checksum = rbox_calculate_checksum(&header, 84);
    
    assert(rbox_header_validate(&header) == RBOX_OK);
    printf("  ✓ Valid header passes\n");
    
    /* Invalid magic */
    memset(&header, 0, sizeof(header));
    header.magic = 0xDEADBEEF;
    assert(rbox_header_validate(&header) == RBOX_ERR_MAGIC);
    printf("  ✓ Invalid magic detected\n");
    
    /* Invalid version */
    memset(&header, 0, sizeof(header));
    header.magic = RBOX_MAGIC;
    header.version = 999;
    header.flags = RBOX_FLAG_FIRST;
    header.chunk_len = 100;
    header.total_len = 100;
    header.checksum = 0;
    header.checksum = rbox_calculate_checksum(&header, 84);
    assert(rbox_header_validate(&header) == RBOX_ERR_VERSION);
    printf("  ✓ Invalid version detected\n");
    
    printf("test_header_validate: PASSED\n\n");
}

/* Test error strings */
void test_strerror(void) {
    printf("Testing error strings...\n");
    
    assert(strcmp(rbox_strerror(RBOX_OK), "Success") == 0);
    assert(strcmp(rbox_strerror(RBOX_ERR_INVALID), "Invalid parameter") == 0);
    assert(strcmp(rbox_strerror(RBOX_ERR_MAGIC), "Invalid magic number") == 0);
    assert(strcmp(rbox_strerror(RBOX_ERR_VERSION), "Unsupported protocol version") == 0);
    assert(strcmp(rbox_strerror(RBOX_ERR_CHECKSUM), "Checksum mismatch") == 0);
    assert(strcmp(rbox_strerror(RBOX_ERR_TRUNCATED), "Truncated data") == 0);
    assert(strcmp(rbox_strerror(RBOX_ERR_IO), "I/O error") == 0);
    assert(strcmp(rbox_strerror(RBOX_ERR_MEMORY), "Memory allocation failed") == 0);
    
    printf("test_strerror: PASSED\n\n");
}

/* Test checksum */
void test_checksum(void) {
    printf("Testing checksum...\n");
    
    const char *data = "test data";
    uint32_t sum1 = rbox_calculate_checksum(data, strlen(data));
    uint32_t sum2 = rbox_calculate_checksum(data, strlen(data));
    
    assert(sum1 == sum2);
    printf("  ✓ Checksum is deterministic\n");
    
    /* Different data = different checksum */
    const char *data2 = "other data";
    uint32_t sum3 = rbox_calculate_checksum(data2, strlen(data2));
    assert(sum1 != sum3);
    printf("  ✓ Different data = different checksum\n");
    
    printf("test_checksum: PASSED\n\n");
}

int main(void) {
    printf("=== rbox-protocol unit tests ===\n\n");
    
    test_header_validate();
    test_strerror();
    test_checksum();
    
    printf("=== All tests PASSED ===\n");
    return 0;
}
