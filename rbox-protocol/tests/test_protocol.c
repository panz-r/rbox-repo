/*
 * test_protocol.c - Basic test for rbox-protocol
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#include "rbox_protocol.h"
#include "runtime.h"

/* Test header validation - uses canonical library function */
void test_header_validate(void) {
    printf("Testing header validation...\n");
    
    /* Build proper request packet using canonical library function - do once */
    char packet[1024];
    size_t pkt_len;
    const char *args[] = {"test"};
    rbox_build_request(packet, sizeof(packet), &pkt_len, "test", NULL, NULL, 1, args, 0, NULL, NULL);
    
    /* Save original values using explicit offsets */
    uint32_t orig_magic = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC);
    uint32_t orig_version = *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION);
    /* Note: orig_checksum not needed - we test by modifying and checking validation fails */
    
    /* Test 1: Valid header should pass */
    assert(rbox_header_validate(packet, pkt_len) == RBOX_OK);
    printf("  ✓ Valid header passes\n");
    
    /* Test 2: Invalid magic should fail */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC) = 0xDEADBEEF;
    assert(rbox_header_validate(packet, pkt_len) == RBOX_ERR_MAGIC);
    printf("  ✓ Invalid magic detected\n");
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_MAGIC) = orig_magic;  /* Restore */
    
    /* Test 3: Invalid version should fail */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION) = 999;
    assert(rbox_header_validate(packet, pkt_len) == RBOX_ERR_VERSION);
    printf("  ✓ Invalid version detected\n");
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_VERSION) = orig_version;  /* Restore */
    
    /* Test 4: Corrupt checksum should fail */
    *(uint32_t *)(packet + RBOX_HEADER_OFFSET_CHECKSUM) ^= 0xFFFFFFFF;
    assert(rbox_header_validate(packet, pkt_len) == RBOX_ERR_CHECKSUM);
    printf("  ✓ Checksum mismatch detected\n");
    
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

/* Test checksum - tests the checksum function itself */
void test_checksum(void) {
    printf("Testing checksum...\n");
    
    const char *data = "test data";
    uint32_t sum1 = rbox_runtime_crc32(0, data, strlen(data));
    uint32_t sum2 = rbox_runtime_crc32(0, data, strlen(data));
    
    assert(sum1 == sum2);
    printf("  ✓ Checksum is deterministic\n");
    
    /* Different data = different checksum */
    const char *data2 = "other data";
    uint32_t sum3 = rbox_runtime_crc32(0, data2, strlen(data2));
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
    rbox_error_t err = rbox_session_send_request(session, "ls", NULL, NULL, 0, NULL, 0, NULL, NULL);
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
    
    /* Test session with retry */
    session = rbox_session_new("/nonexistent.sock", 10, 3);
    assert(session != NULL);
    assert(rbox_session_state(session) == RBOX_SESSION_DISCONNECTED);
    rbox_session_free(session);
    printf("  ✓ Session with retry created\n");
    
    printf("test_session: PASSED\n\n");
}

int main(void) {
    test_header_validate();
    test_strerror();
    test_checksum();
    test_session();
    
    printf("=== All tests PASSED ===\n");
    return 0;
}
