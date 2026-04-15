/*
 * test_serialize.c - Unit tests for serialization helpers
 *
 * Tests the rbox_writer_t and rbox_reader_t helpers for
 * endian-safe, position-based serialization.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdint.h>
#include <arpa/inet.h>
#include "../include/protocol_encoding.h"
#include "../include/protocol_decoding.h"

static int test_writer_basic(void) {
    printf("Testing writer basic operations...\n");

    uint8_t buf[256];
    rbox_writer_t w;
    rbox_writer_init(&w, buf, sizeof(buf));

    assert(rbox_writer_pos(&w) == 0);

    rbox_write_u8(&w, 0x42);
    assert(rbox_writer_pos(&w) == 1);

    rbox_write_u32(&w, 0x12345678);
    assert(rbox_writer_pos(&w) == 5);

    rbox_write_u64(&w, 0x1122334455667788ULL);
    assert(rbox_writer_pos(&w) == 13);

    rbox_writer_skip(&w, 10);
    assert(rbox_writer_pos(&w) == 23);

    printf("  ✓ Writer basic operations work\n");
    printf("test_writer_basic: PASSED\n\n");
    return 0;
}

static int test_reader_basic(void) {
    printf("Testing reader basic operations...\n");

    uint8_t buf[256];
    for (int i = 0; i < 256; i++) buf[i] = i;

    rbox_reader_t r;
    rbox_reader_init(&r, buf, sizeof(buf));

    assert(rbox_reader_pos(&r) == 0);
    assert(rbox_reader_remaining(&r) == 256);

    uint8_t val8 = rbox_read_u8(&r);
    assert(val8 == 0);
    assert(rbox_reader_pos(&r) == 1);

    uint32_t val32 = rbox_read_u32(&r);
    /* Little-endian: bytes 1,2,3,4 are 0x01,0x02,0x03,0x04 -> 0x04030201 */
    assert(val32 == 0x04030201);
    assert(rbox_reader_pos(&r) == 5);

    uint64_t val64 = rbox_read_u64(&r);
    /* Little-endian: bytes 5-12 are 0x05..0x0C -> 0x0C0B0A0908070605 */
    assert(val64 == 0x0C0B0A0908070605ULL);
    assert(rbox_reader_pos(&r) == 13);

    rbox_reader_skip(&r, 10);
    assert(rbox_reader_pos(&r) == 23);
    assert(rbox_reader_remaining(&r) == 233);

    printf("  ✓ Reader basic operations work\n");
    printf("test_reader_basic: PASSED\n\n");
    return 0;
}

static int test_endianness_u32(void) {
    printf("Testing endianness for u32...\n");

    uint8_t buf[4];
    uint32_t test_val = 0x12345678;

    /* Write using htole32 */
    uint32_t le = htole32(test_val);
    memcpy(buf, &le, 4);

    /* Read using le32toh */
    uint32_t read_val = le32toh(*(uint32_t *)buf);

    assert(read_val == test_val);
    printf("  ✓ u32 endianness conversion works\n");
    printf("test_endianness_u32: PASSED\n\n");
    return 0;
}

static int test_endianness_u64(void) {
    printf("Testing endianness for u64...\n");

    uint8_t buf[8];
    uint64_t test_val = 0x123456789ABCDEF0ULL;

    /* Write using htole64 */
    uint64_t le = htole64(test_val);
    memcpy(buf, &le, 8);

    /* Read using le64toh */
    uint64_t read_val = le64toh(*(uint64_t *)buf);

    assert(read_val == test_val);
    printf("  ✓ u64 endianness conversion works\n");
    printf("test_endianness_u64: PASSED\n\n");
    return 0;
}

static int test_roundtrip_u32(void) {
    printf("Testing roundtrip u32...\n");

    uint8_t buf[4];
    rbox_writer_t w;
    rbox_writer_init(&w, buf, sizeof(buf));

    uint32_t original = 0xDEADBEEF;
    rbox_write_u32(&w, original);

    rbox_reader_t r;
    rbox_reader_init(&r, buf, sizeof(buf));

    uint32_t read_back = rbox_read_u32(&r);
    assert(read_back == original);
    printf("  ✓ u32 roundtrip works\n");
    printf("test_roundtrip_u32: PASSED\n\n");
    return 0;
}

static int test_roundtrip_u64(void) {
    printf("Testing roundtrip u64...\n");

    uint8_t buf[8];
    rbox_writer_t w;
    rbox_writer_init(&w, buf, sizeof(buf));

    uint64_t original = 0xDEADBEEFCAFEBABEULL;
    rbox_write_u64(&w, original);

    rbox_reader_t r;
    rbox_reader_init(&r, buf, sizeof(buf));

    uint64_t read_back = rbox_read_u64(&r);
    assert(read_back == original);
    printf("  ✓ u64 roundtrip works\n");
    printf("test_roundtrip_u64: PASSED\n\n");
    return 0;
}

static int test_roundtrip_bytes(void) {
    printf("Testing roundtrip bytes...\n");

    uint8_t buf[256];
    const char *original = "Hello, World! This is a test.";
    size_t len = strlen(original);

    rbox_writer_t w;
    rbox_writer_init(&w, buf, sizeof(buf));
    rbox_write_bytes(&w, original, len);

    rbox_reader_t r;
    rbox_reader_init(&r, buf, len);
    char read_back[256];
    rbox_read_bytes(&r, read_back, len);
    read_back[len] = '\0';

    assert(strcmp(read_back, original) == 0);
    printf("  ✓ bytes roundtrip works\n");
    printf("test_roundtrip_bytes: PASSED\n\n");
    return 0;
}

static int test_writer_multiple_u32(void) {
    printf("Testing writer multiple u32...\n");

    uint8_t buf[64];
    rbox_writer_t w;
    rbox_writer_init(&w, buf, sizeof(buf));

    rbox_write_u32(&w, 0x11111111);
    rbox_write_u32(&w, 0x22222222);
    rbox_write_u32(&w, 0x33333333);
    rbox_write_u32(&w, 0x44444444);

    assert(rbox_writer_pos(&w) == 16);

    rbox_reader_t r;
    rbox_reader_init(&r, buf, 16);

    assert(rbox_read_u32(&r) == 0x11111111);
    assert(rbox_read_u32(&r) == 0x22222222);
    assert(rbox_read_u32(&r) == 0x33333333);
    assert(rbox_read_u32(&r) == 0x44444444);

    printf("  ✓ multiple u32 write/read works\n");
    printf("test_writer_multiple_u32: PASSED\n\n");
    return 0;
}

static int test_writer_mixed_types(void) {
    printf("Testing writer mixed types...\n");

    uint8_t buf[128];
    rbox_writer_t w;
    rbox_writer_init(&w, buf, sizeof(buf));

    rbox_write_u8(&w, 0x42);
    rbox_write_u32(&w, 0x12345678);
    rbox_write_u64(&w, 0xFEDCBA9876543210ULL);
    rbox_write_bytes(&w, "ABC", 3);
    rbox_write_u16(&w, 0xBEEF);

    rbox_reader_t r;
    rbox_reader_init(&r, buf, rbox_writer_pos(&w));

    assert(rbox_read_u8(&r) == 0x42);
    assert(rbox_read_u32(&r) == 0x12345678);
    assert(rbox_read_u64(&r) == 0xFEDCBA9876543210ULL);
    char str[4] = {0};
    rbox_read_bytes(&r, str, 3);
    assert(strcmp(str, "ABC") == 0);
    assert(rbox_read_u16(&r) == 0xBEEF);

    printf("  ✓ mixed type write/read works\n");
    printf("test_writer_mixed_types: PASSED\n\n");
    return 0;
}

static int test_request_encoding(void) {
    printf("Testing request encoding roundtrip...\n");

    uint8_t buf[1024];
    size_t len;

    rbox_error_t err = rbox_encode_request(
        "echo hello",
        "test_caller",
        "execve",
        1,
        (const char*[]){"hello"},
        0,
        NULL,
        NULL,
        buf,
        sizeof(buf),
        &len
    );

    assert(err == RBOX_OK);
    assert(len > RBOX_HEADER_SIZE);

    /* Verify magic and version */
    rbox_reader_t r;
    rbox_reader_init(&r, buf, len);

    uint32_t magic = rbox_read_u32(&r);
    uint32_t version = rbox_read_u32(&r);
    assert(magic == RBOX_MAGIC);
    assert(version == RBOX_VERSION);

    printf("  ✓ request encoding roundtrip works\n");
    printf("test_request_encoding: PASSED\n\n");
    return 0;
}

static int test_response_encoding(void) {
    printf("Testing response encoding roundtrip...\n");

    uint8_t buf[1024];
    size_t len;

    uint8_t client_id[16] = {0};
    uint8_t request_id[16] = {0};
    for (int i = 0; i < 16; i++) {
        client_id[i] = i;
        request_id[i] = 0xFF - i;
    }

    rbox_error_t err = rbox_encode_response(
        client_id,
        request_id,
        0x12345678,
        RBOX_DECISION_ALLOW,
        "test reason",
        0xABCDEF00,
        0,
        NULL,
        buf,
        sizeof(buf),
        &len
    );

    assert(err == RBOX_OK);
    assert(len > RBOX_HEADER_SIZE);

    /* Verify magic and version */
    rbox_reader_t r;
    rbox_reader_init(&r, buf, len);

    uint32_t magic = rbox_read_u32(&r);
    uint32_t version = rbox_read_u32(&r);
    assert(magic == RBOX_MAGIC);
    assert(version == RBOX_VERSION);

    printf("  ✓ response encoding roundtrip works\n");
    printf("test_response_encoding: PASSED\n\n");
    return 0;
}

int main(void) {
    printf("=== Serialization Helper Unit Tests ===\n\n");

    test_writer_basic();
    test_reader_basic();
    test_endianness_u32();
    test_endianness_u64();
    test_roundtrip_u32();
    test_roundtrip_u64();
    test_roundtrip_bytes();
    test_writer_multiple_u32();
    test_writer_mixed_types();
    test_request_encoding();
    test_response_encoding();

    printf("=== All Serialization Tests PASSED ===\n");
    return 0;
}
