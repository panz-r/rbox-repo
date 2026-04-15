/*
 * test_errors.c - Unit tests for error handling functions
 *
 * Tests rbox_error_info_t, rbox_strerror_r, and error propagation.
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <errno.h>

#include "rbox_protocol.h"
#include "error_internal.h"
#include "error_messages.h"

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static void test_error_set(void) {
    printf("Testing rbox_error_set...\n");

    rbox_error_info_t err_info;
    memset(&err_info, 0xFF, sizeof(err_info));

    rbox_error_set(&err_info, RBOX_ERR_IO, EINVAL, RBOX_MSG_CONN_REFUSED);

    assert(err_info.code == RBOX_ERR_IO);
    assert(err_info.sys_errno == EINVAL);
    assert(err_info.message == RBOX_MSG_CONN_REFUSED);

    printf("  ✓ Error info correctly set\n");
    printf("test_rbox_error_set: PASSED\n\n");
}

static void test_error_set_null(void) {
    printf("Testing rbox_error_set with NULL...\n");

    rbox_error_set(NULL, RBOX_ERR_INVALID, 0, "test");

    printf("  ✓ No crash with NULL err_info\n");
    printf("test_rbox_error_set_null: PASSED\n\n");
}

static void test_error_propagate(void) {
    printf("Testing rbox_error_propagate...\n");

    rbox_error_info_t src;
    src.code = RBOX_ERR_CHECKSUM;
    src.sys_errno = 0;
    src.message = RBOX_MSG_CHECKSUM_MISMATCH;

    rbox_error_info_t dest;
    memset(&dest, 0xFF, sizeof(dest));

    rbox_error_propagate(&dest, &src);

    assert(dest.code == RBOX_ERR_CHECKSUM);
    assert(dest.sys_errno == 0);
    assert(dest.message == RBOX_MSG_CHECKSUM_MISMATCH);

    printf("  ✓ Error info correctly propagated\n");
    printf("test_rbox_error_propagate: PASSED\n\n");
}

static void test_error_propagate_null(void) {
    printf("Testing rbox_error_propagate with NULL...\n");

    rbox_error_info_t src;
    src.code = RBOX_ERR_CHECKSUM;
    src.sys_errno = 0;
    src.message = RBOX_MSG_CHECKSUM_MISMATCH;

    rbox_error_propagate(NULL, &src);
    rbox_error_propagate(&src, NULL);

    printf("  ✓ No crash with NULL pointers\n");
    printf("test_rbox_error_propagate_null: PASSED\n\n");
}

static void test_strerror_r_basic(void) {
    printf("Testing rbox_strerror_r basic...\n");

    char buf[256];

    char *result = rbox_strerror_r(RBOX_OK, 0, NULL, buf, sizeof(buf));
    assert(result == buf);
    assert(strcmp(buf, "Success") == 0);
    printf("  ✓ RBOX_OK returns 'Success'\n");

    result = rbox_strerror_r(RBOX_ERR_INVALID, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "Invalid parameter") == 0);
    printf("  ✓ RBOX_ERR_INVALID returns 'Invalid parameter'\n");

    result = rbox_strerror_r(RBOX_ERR_IO, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "I/O error") == 0);
    printf("  ✓ RBOX_ERR_IO returns 'I/O error'\n");

    result = rbox_strerror_r(RBOX_ERR_MAGIC, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "Invalid magic number") == 0);
    printf("  ✓ RBOX_ERR_MAGIC returns 'Invalid magic number'\n");

    result = rbox_strerror_r(RBOX_ERR_VERSION, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "Unsupported protocol version") == 0);
    printf("  ✓ RBOX_ERR_VERSION returns 'Unsupported protocol version'\n");

    result = rbox_strerror_r(RBOX_ERR_CHECKSUM, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "Checksum mismatch") == 0);
    printf("  ✓ RBOX_ERR_CHECKSUM returns 'Checksum mismatch'\n");

    result = rbox_strerror_r(RBOX_ERR_TRUNCATED, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "Truncated data") == 0);
    printf("  ✓ RBOX_ERR_TRUNCATED returns 'Truncated data'\n");

    result = rbox_strerror_r(RBOX_ERR_MEMORY, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "Memory allocation failed") == 0);
    printf("  ✓ RBOX_ERR_MEMORY returns 'Memory allocation failed'\n");

    result = rbox_strerror_r(RBOX_ERR_MISMATCH, 0, NULL, buf, sizeof(buf));
    assert(strcmp(buf, "Request/response ID mismatch") == 0);
    printf("  ✓ RBOX_ERR_MISMATCH returns 'Request/response ID mismatch'\n");

    printf("test_rbox_strerror_r_basic: PASSED\n\n");
}

static void test_strerror_r_with_sys_errno(void) {
    printf("Testing rbox_strerror_r with sys_errno...\n");

    char buf[256];

    errno = ENOENT;
    char *result = rbox_strerror_r(RBOX_ERR_IO, errno, NULL, buf, sizeof(buf));
    assert(strstr(buf, "I/O error") != NULL);
    assert(strstr(buf, strerror(errno)) != NULL);
    printf("  ✓ Error message contains sys_errno string\n");

    printf("test_rbox_strerror_r_with_sys_errno: PASSED\n\n");
}

static void test_strerror_r_with_message(void) {
    printf("Testing rbox_strerror_r with message...\n");

    char buf[256];

    char *result = rbox_strerror_r(RBOX_ERR_IO, 0, "custom context", buf, sizeof(buf));
    assert(strstr(buf, "I/O error") != NULL);
    assert(strstr(buf, "custom context") != NULL);
    printf("  ✓ Error message contains custom context\n");

    printf("test_rbox_strerror_r_with_message: PASSED\n\n");
}

static void test_strerror_r_buffer_limits(void) {
    printf("Testing rbox_strerror_r buffer limits...\n");

    char small_buf[16];
    char large_buf[256];

    char *result = rbox_strerror_r(RBOX_ERR_INVALID, 0, NULL, small_buf, sizeof(small_buf));
    assert(result == small_buf);
    printf("  ✓ Returns buffer even when truncated\n");

    result = rbox_strerror_r(RBOX_OK, 0, NULL, large_buf, sizeof(large_buf));
    assert(result == large_buf);
    assert(strcmp(large_buf, "Success") == 0);
    printf("  ✓ Works correctly with large buffer\n");

    result = rbox_strerror_r(RBOX_OK, 0, NULL, NULL, 0);
    assert(result == NULL);
    printf("  ✓ Returns NULL for NULL buffer with 0 size\n");

    printf("test_rbox_strerror_r_buffer_limits: PASSED\n\n");
}

static void test_error_info_struct(void) {
    printf("Testing rbox_error_info_t struct...\n");

    rbox_error_info_t info = {
        .code = RBOX_ERR_TIMEOUT,
        .sys_errno = 0,
        .message = RBOX_MSG_TIMEOUT
    };

    assert(info.code == RBOX_ERR_TIMEOUT);
    assert(info.sys_errno == 0);
    assert(info.message == RBOX_MSG_TIMEOUT);

    printf("  ✓ rbox_error_info_t can be initialized with designated initializers\n");
    printf("test_rbox_info_struct: PASSED\n\n");
}

static void test_error_message_defines(void) {
    printf("Testing error message defines...\n");

    assert(strcmp(RBOX_MSG_CONN_REFUSED, "Connection refused") == 0);
    assert(strcmp(RBOX_MSG_CONN_TIMEOUT, "Connection timed out") == 0);
    assert(strcmp(RBOX_MSG_CONN_FAILED, "Connection failed") == 0);
    assert(strcmp(RBOX_MSG_CONN_CLOSED, "Connection closed") == 0);
    assert(strcmp(RBOX_MSG_READ_FAILED, "Read failed") == 0);
    assert(strcmp(RBOX_MSG_WRITE_FAILED, "Write failed") == 0);
    assert(strcmp(RBOX_MSG_PEER_CLOSED, "Peer closed connection") == 0);
    assert(strcmp(RBOX_MSG_WOULD_BLOCK, "Operation would block") == 0);
    assert(strcmp(RBOX_MSG_TIMEOUT, "Operation timed out") == 0);
    assert(strcmp(RBOX_MSG_HEADER_INVALID, "Invalid packet header") == 0);
    assert(strcmp(RBOX_MSG_MAGIC_INVALID, "Invalid magic number") == 0);
    assert(strcmp(RBOX_MSG_VERSION_INVALID, "Unsupported protocol version") == 0);
    assert(strcmp(RBOX_MSG_CHECKSUM_MISMATCH, "Checksum mismatch") == 0);
    assert(strcmp(RBOX_MSG_TRUNCATED, "Truncated data") == 0);
    assert(strcmp(RBOX_MSG_INVALID_PARAM, "Invalid parameter") == 0);
    assert(strcmp(RBOX_MSG_ID_MISMATCH, "Request/response ID mismatch") == 0);
    assert(strcmp(RBOX_MSG_MEMORY, "Memory allocation failed") == 0);
    assert(strcmp(RBOX_MSG_ALLOC_FAILED, "Allocation failed") == 0);
    assert(strcmp(RBOX_MSG_NOT_CONNECTED, "Not connected") == 0);
    assert(strcmp(RBOX_MSG_ALREADY_CONN, "Already connected") == 0);
    assert(strcmp(RBOX_MSG_STATE_ERROR, "Invalid state") == 0);
    assert(strcmp(RBOX_MSG_BUSY, "Resource busy") == 0);
    assert(strcmp(RBOX_MSG_SERVER_ERROR, "Server error") == 0);
    assert(strcmp(RBOX_MSG_SERVER_FULL, "Server full") == 0);
    assert(strcmp(RBOX_MSG_BAD_RESPONSE, "Malformed response") == 0);
    assert(strcmp(RBOX_MSG_UNKNOWN, "Unknown error") == 0);
    assert(strcmp(RBOX_MSG_SUCCESS, "Success") == 0);

    printf("  ✓ All error message defines are correct\n");
    printf("test_error_message_defines: PASSED\n\n");
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void) {
    printf("=== Error Handling Tests ===\n\n");

    test_error_set();
    test_error_set_null();
    test_error_propagate();
    test_error_propagate_null();
    test_strerror_r_basic();
    test_strerror_r_with_sys_errno();
    test_strerror_r_with_message();
    test_strerror_r_buffer_limits();
    test_error_info_struct();
    test_error_message_defines();

    printf("=== All Error Handling Tests PASSED ===\n");
    return 0;
}
