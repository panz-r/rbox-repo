/*
 * test_protocol.c - Basic test for rbox-protocol
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

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
    /* Calculate checksum over header (v7 protocol, excluding checksum field at offset 119) */
    header.checksum = 0;
    header.checksum = rbox_calculate_checksum(&header, RBOX_HEADER_OFFSET_CHECKSUM);
    
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
    header.checksum = rbox_calculate_checksum(&header, RBOX_HEADER_OFFSET_CHECKSUM);
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
    assert(strcmp(rbox_strerror(RBOX_ERR_MISMATCH), "Request/response ID mismatch") == 0);
    
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

/* Test session state machine */
void test_session(void) {
    printf("Testing session interface...\n");
    
    /* Create session with no retry */
    rbox_session_t *session = rbox_session_new("/nonexistent.sock", 0, 0);
    assert(session != NULL);
    short events;
    assert(rbox_session_pollfd(session, &events) == -1);
    assert(rbox_session_state(session) == RBOX_SESSION_DISCONNECTED);
    printf("  ✓ Session created in DISCONNECTED state\n");
    
    /* Try to send without connecting - should fail */
    rbox_error_t err = rbox_session_send_request(session, "ls", 0, NULL, NULL, NULL);
    assert(err == RBOX_ERR_INVALID);
    printf("  ✓ Send request without connection returns INVALID\n");
    
    /* Try to connect to nonexistent socket */
    err = rbox_session_connect(session);
    assert(err == RBOX_ERR_IO);
    assert(rbox_session_state(session) == RBOX_SESSION_FAILED);
    printf("  ✓ Connect to nonexistent socket returns FAILED\n");
    
    /* Free session */
    rbox_session_free(session);
    printf("  ✓ Session freed\n");
    
    /* Create session with retry */
    session = rbox_session_new("/nonexistent.sock", 10, 3);
    assert(session != NULL);
    assert(rbox_session_state(session) == RBOX_SESSION_DISCONNECTED);
    printf("  ✓ Session with retry created\n");
    
    rbox_session_free(session);
    printf("test_session: PASSED\n\n");
}

int main(void) {
    printf("=== rbox-protocol unit tests ===\n\n");
    
    test_header_validate();
    test_strerror();
    test_checksum();
    test_session();
    
    printf("=== All tests PASSED ===\n");
    return 0;
}
