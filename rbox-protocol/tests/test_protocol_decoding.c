/*
 * test_protocol_decoding.c - Unit tests for protocol decoding functions
 *
 * Tests pure decoding functions with in-memory buffers, no sockets.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "protocol_decoding.h"
#include "protocol_encoding.h"
#include "runtime.h"

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static void test_validate_header_valid(void) {
    printf("Testing rbox_validate_header with valid packet...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_encode_request("test", NULL, NULL, 0, NULL, 0, NULL, NULL,
                        buf, sizeof(buf), &out_len);

    rbox_error_t err = rbox_validate_header(buf, out_len);
    assert(err == RBOX_OK);
    printf("  ✓ Valid header passes validation\n");

    printf("test_validate_header_valid: PASSED\n\n");
}

static void test_validate_header_invalid_magic(void) {
    printf("Testing rbox_validate_header with invalid magic...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_encode_request("test", NULL, NULL, 0, NULL, 0, NULL, NULL,
                        buf, sizeof(buf), &out_len);

    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_MAGIC) = 0xDEADBEEF;

    rbox_error_t err = rbox_validate_header(buf, out_len);
    assert(err == RBOX_ERR_MAGIC);
    printf("  ✓ Invalid magic detected\n");

    printf("test_validate_header_invalid_magic: PASSED\n\n");
}

static void test_validate_header_invalid_version(void) {
    printf("Testing rbox_validate_header with invalid version...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_encode_request("test", NULL, NULL, 0, NULL, 0, NULL, NULL,
                        buf, sizeof(buf), &out_len);

    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_VERSION) = 999;

    rbox_error_t err = rbox_validate_header(buf, out_len);
    assert(err == RBOX_ERR_VERSION);
    printf("  ✓ Invalid version detected\n");

    printf("test_validate_header_invalid_version: PASSED\n\n");
}

static void test_validate_header_checksum_mismatch(void) {
    printf("Testing rbox_validate_header with checksum mismatch...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_encode_request("test", NULL, NULL, 0, NULL, 0, NULL, NULL,
                        buf, sizeof(buf), &out_len);

    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_CHECKSUM) ^= 0xFFFFFFFF;

    rbox_error_t err = rbox_validate_header(buf, out_len);
    assert(err == RBOX_ERR_CHECKSUM);
    printf("  ✓ Checksum mismatch detected\n");

    printf("test_validate_header_checksum_mismatch: PASSED\n\n");
}

static void test_validate_header_truncated(void) {
    printf("Testing rbox_validate_header with truncated header...\n");

    uint8_t buf[64];
    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;

    rbox_error_t err = rbox_validate_header(buf, 50);
    assert(err == RBOX_ERR_TRUNCATED);
    printf("  ✓ Truncated header detected\n");

    printf("test_validate_header_truncated: PASSED\n\n");
}

static void test_decode_header_raw(void) {
    printf("Testing rbox_decode_header_raw...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t expected_request_id[16];

    rbox_encode_request("test", "caller", "syscall", 0, NULL, 0, NULL, NULL,
                        buf, sizeof(buf), &out_len);

    memcpy(expected_request_id, buf + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

    rbox_decoded_header_t header;
    rbox_decode_header_raw(buf, out_len, &header);

    assert(header.valid == 1);
    printf("  ✓ Header marked as valid\n");

    assert(header.magic == RBOX_MAGIC);
    assert(header.version == RBOX_VERSION);
    printf("  ✓ Magic and version correct\n");

    assert(memcmp(header.request_id, expected_request_id, 16) == 0);
    printf("  ✓ Request ID preserved\n");

    assert(header.cmd_type == RBOX_MSG_REQ);
    printf("  ✓ Message type is REQ\n");

    printf("test_decode_header_raw: PASSED\n\n");
}

static void test_decode_response_raw_basic(void) {
    printf("Testing rbox_decode_response_raw basic...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_ALLOW,
                        "OK", 0, 0, NULL,
                        buf, sizeof(buf), &out_len);

    rbox_response_t response;
    rbox_error_t err = rbox_decode_response_raw(buf, out_len, request_id, &response);

    assert(err == RBOX_OK);
    printf("  ✓ Response decoded successfully\n");

    assert(response.decision == RBOX_DECISION_ALLOW);
    printf("  ✓ Decision is ALLOW\n");

    assert(strcmp(response.reason, "OK") == 0);
    printf("  ✓ Reason is 'OK'\n");

    free(response.env_decisions);
    printf("test_decode_response_raw_basic: PASSED\n\n");
}

static void test_decode_response_raw_mismatch(void) {
    printf("Testing rbox_decode_response_raw with request ID mismatch...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t wrong_id[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_ALLOW,
                        "OK", 0, 0, NULL,
                        buf, sizeof(buf), &out_len);

    rbox_response_t response;
    rbox_error_t err = rbox_decode_response_raw(buf, out_len, wrong_id, &response);

    assert(err == RBOX_ERR_MISMATCH);
    printf("  ✓ Request ID mismatch detected\n");

    printf("test_decode_response_raw_mismatch: PASSED\n\n");
}

static void test_decode_response_raw_with_env(void) {
    printf("Testing rbox_decode_response_raw with env decisions...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1};

    uint8_t env_decisions[3] = {0b11110000, 0b00001111, 0b10101010};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_ALLOW,
                        "allowed", 0x12345678, 24, env_decisions,
                        buf, sizeof(buf), &out_len);

    rbox_response_t response;
    rbox_error_t err = rbox_decode_response_raw(buf, out_len, request_id, &response);

    assert(err == RBOX_OK);
    assert(response.env_decision_count == 24);
    printf("  ✓ Env decision count is correct (24)\n");

    assert(response.env_decisions != NULL);
    for (int i = 0; i < 3; i++) {
        assert(response.env_decisions[i] == env_decisions[i]);
    }
    printf("  ✓ Env decisions bitmap is correct\n");

    free(response.env_decisions);
    printf("test_decode_response_raw_with_env: PASSED\n\n");
}

static void test_decode_response_raw_checksum_error(void) {
    printf("Testing rbox_decode_response_raw with body checksum error...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_ALLOW,
                        "OK", 0, 0, NULL,
                        buf, sizeof(buf), &out_len);

    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_BODY_CHECKSUM) ^= 0xFFFF0000;

    rbox_response_t response;
    rbox_error_t err = rbox_decode_response_raw(buf, out_len, request_id, &response);

    assert(err == RBOX_ERR_CHECKSUM);
    printf("  ✓ Body checksum error detected\n");

    printf("test_decode_response_raw_checksum_error: PASSED\n\n");
}

static void test_decode_response_raw_truncated(void) {
    printf("Testing rbox_decode_response_raw with truncated packet...\n");

    uint8_t buf[RBOX_HEADER_SIZE];
    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;
    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_CHUNK_LEN) = 1000;

    rbox_response_t response;
    rbox_error_t err = rbox_decode_response_raw(buf, sizeof(buf), NULL, &response);

    assert(err == RBOX_ERR_TRUNCATED);
    printf("  ✓ Truncated packet detected\n");

    printf("test_decode_response_raw_truncated: PASSED\n\n");
}

static void test_decode_response_details_raw(void) {
    printf("Testing rbox_decode_response_details_raw...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_DENY,
                        "permission denied", 0, 0, NULL,
                        buf, sizeof(buf), &out_len);

    rbox_decoded_header_t header;
    rbox_decode_header_raw(buf, out_len, &header);

    rbox_response_details_t details;
    rbox_error_t err = rbox_decode_response_details_raw(buf, out_len, &header, &details);

    assert(err == RBOX_OK);
    assert(details.valid == 1);
    printf("  ✓ Details marked as valid\n");

    assert(details.decision == RBOX_DECISION_DENY);
    printf("  ✓ Decision is DENY\n");

    assert(strncmp(details.reason, "permission denied", details.reason_len) == 0);
    printf("  ✓ Reason is 'permission denied'\n");

    printf("test_decode_response_details_raw: PASSED\n\n");
}

static void test_decode_env_decisions_raw(void) {
    printf("Testing rbox_decode_env_decisions_raw...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1};

    uint8_t env_decisions[2] = {0b10101010, 0};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_ALLOW,
                        "OK", 0xDEADBEEF, 8, env_decisions,
                        buf, sizeof(buf), &out_len);

    rbox_decoded_header_t header;
    rbox_decode_header_raw(buf, out_len, &header);

    rbox_response_details_t details;
    rbox_decode_response_details_raw(buf, out_len, &header, &details);

    rbox_env_decisions_t env_dec;
    rbox_error_t err = rbox_decode_env_decisions_raw(buf, out_len, &header, &details, &env_dec);

    assert(err == RBOX_OK);
    assert(env_dec.valid == 1);
    printf("  ✓ Env decisions marked as valid\n");

    assert(env_dec.env_count == 8);
    printf("  ✓ Env count is 8\n");

    assert(env_dec.bitmap != NULL);
    assert(env_dec.bitmap[0] == 0b10101010);
    printf("  ✓ Bitmap is correct\n");

    free(env_dec.bitmap);
    printf("test_decode_env_decisions_raw: PASSED\n\n");
}

static void test_decode_response_details_no_reason(void) {
    printf("Testing rbox_decode_response_details_raw with no reason...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_ALLOW,
                        "", 0, 0, NULL,
                        buf, sizeof(buf), &out_len);

    rbox_decoded_header_t header;
    rbox_decode_header_raw(buf, out_len, &header);

    rbox_response_details_t details;
    rbox_error_t err = rbox_decode_response_details_raw(buf, out_len, &header, &details);

    assert(err == RBOX_OK);
    assert(details.valid == 1);
    printf("  ✓ Details marked as valid\n");

    assert(details.decision == RBOX_DECISION_ALLOW);
    printf("  ✓ Decision is ALLOW\n");

    assert(details.reason_len == 0);
    printf("  ✓ Reason length is 0\n");

    printf("test_decode_response_details_no_reason: PASSED\n\n");
}

static void test_decode_env_decisions_empty(void) {
    printf("Testing rbox_decode_env_decisions_raw with empty env decisions...\n");

    uint8_t buf[8192];
    size_t out_len;
    uint8_t request_id[16] = {1};

    rbox_encode_response(request_id, request_id, 0, RBOX_DECISION_ALLOW,
                        "OK", 0, 0, NULL,
                        buf, sizeof(buf), &out_len);

    rbox_decoded_header_t header;
    rbox_decode_header_raw(buf, out_len, &header);

    rbox_response_details_t details;
    rbox_decode_response_details_raw(buf, out_len, &header, &details);

    rbox_env_decisions_t env_dec;
    rbox_error_t err = rbox_decode_env_decisions_raw(buf, out_len, &header, &details, &env_dec);

    assert(err == RBOX_OK);
    assert(env_dec.valid == 1);
    printf("  ✓ Env decisions marked as valid\n");

    assert(env_dec.env_count == 0);
    printf("  ✓ Env count is 0\n");

    assert(env_dec.bitmap == NULL);
    printf("  ✓ Bitmap is NULL\n");

    printf("test_decode_env_decisions_empty: PASSED\n\n");
}

static void test_validate_header_zero_length(void) {
    printf("Testing rbox_validate_header with zero length...\n");

    uint8_t buf[64];
    rbox_error_t err = rbox_validate_header(buf, 0);
    assert(err == RBOX_ERR_TRUNCATED);
    printf("  ✓ Returns ERR_TRUNCATED for zero length\n");

    printf("test_validate_header_zero_length: PASSED\n\n");
}

static void test_decode_header_truncated(void) {
    printf("Testing rbox_decode_header_raw with truncated packet...\n");

    uint8_t buf[RBOX_HEADER_SIZE];
    memset(buf, 0, sizeof(buf));
    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_MAGIC) = RBOX_MAGIC;
    *(uint32_t *)(buf + RBOX_HEADER_OFFSET_VERSION) = RBOX_VERSION;

    rbox_decoded_header_t header;
    rbox_decode_header_raw(buf, sizeof(buf), &header);

    assert(header.valid == 0);
    printf("  ✓ Header marked as invalid for truncated packet\n");

    printf("test_decode_header_truncated: PASSED\n\n");
}

int main(void) {
    printf("=== Protocol Decoding Unit Tests ===\n\n");

    test_validate_header_valid();
    test_validate_header_invalid_magic();
    test_validate_header_invalid_version();
    test_validate_header_checksum_mismatch();
    test_validate_header_truncated();
    test_validate_header_zero_length();
    test_decode_header_raw();
    test_decode_header_truncated();
    test_decode_response_raw_basic();
    test_decode_response_raw_mismatch();
    test_decode_response_raw_with_env();
    test_decode_response_raw_checksum_error();
    test_decode_response_raw_truncated();
    test_decode_response_details_raw();
    test_decode_response_details_no_reason();
    test_decode_env_decisions_raw();
    test_decode_env_decisions_empty();

    printf("=== All Protocol Decoding Tests PASSED ===\n");
    return 0;
}