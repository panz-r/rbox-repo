/*
 * test_versioning.c - Unit tests for version and capability functions
 *
 * Tests the new version negotiation and capability API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "rbox_protocol_defs.h"
#include "rbox_protocol.h"
#include "protocol_encoding.h"
#include "runtime.h"

/* ============================================================
 * TEST HELPERS
 * ============================================================ */

static void test_get_protocol_version(void) {
    printf("Testing rbox_get_protocol_major/minor...\n");

    uint16_t major = rbox_get_protocol_major();
    uint16_t minor = rbox_get_protocol_minor();

    assert(major == RBOX_PROTOCOL_MAJOR);
    printf("  ✓ major = %u (expected %u)\n", major, RBOX_PROTOCOL_MAJOR);

    assert(minor == RBOX_PROTOCOL_MINOR);
    printf("  ✓ minor = %u (expected %u)\n", minor, RBOX_PROTOCOL_MINOR);

    printf("test_get_protocol_version: PASSED\n\n");
}

static void test_supported_capabilities(void) {
    printf("Testing rbox_get_supported_capabilities...\n");

    uint32_t caps = rbox_get_supported_capabilities();

    assert(caps == RBOX_DEFAULT_CAPABILITIES);
    printf("  ✓ capabilities = 0x%08x (expected 0x%08x)\n", caps, RBOX_DEFAULT_CAPABILITIES);

    assert(caps & RBOX_CAP_ENV_DECISIONS);
    printf("  ✓ ENV_DECISIONS capability is set\n");

    printf("test_supported_capabilities: PASSED\n\n");
}

static void test_version_is_compatible(void) {
    printf("Testing rbox_version_is_compatible...\n");

    assert(rbox_version_is_compatible(RBOX_PROTOCOL_MAJOR) == 1);
    printf("  ✓ Same major version (%u) is compatible\n", RBOX_PROTOCOL_MAJOR);

    assert(rbox_version_is_compatible(8) == 0);
    printf("  ✓ Different major version (8) is NOT compatible\n");

    assert(rbox_version_is_compatible(10) == 0);
    printf("  ✓ Different major version (10) is NOT compatible\n");

    assert(rbox_version_is_compatible(0) == 0);
    printf("  ✓ Major version 0 is NOT compatible\n");

    printf("test_version_is_compatible: PASSED\n\n");
}

static void test_capability_flags(void) {
    printf("Testing capability flag definitions...\n");

    assert(RBOX_CAP_ENV_DECISIONS == (1 << 0));
    printf("  ✓ RBOX_CAP_ENV_DECISIONS = (1 << 0)\n");

    assert(RBOX_CAP_CHUNKED_STREAM == (1 << 1));
    printf("  ✓ RBOX_CAP_CHUNKED_STREAM = (1 << 1)\n");

    assert(RBOX_CAP_TELEMETRY == (1 << 2));
    printf("  ✓ RBOX_CAP_TELEMETRY = (1 << 2)\n");

    uint32_t all = RBOX_CAP_ENV_DECISIONS | RBOX_CAP_CHUNKED_STREAM | RBOX_CAP_TELEMETRY;
    assert(RBOX_CAP_ALL == all);
    printf("  ✓ RBOX_CAP_ALL = union of all capabilities\n");

    printf("test_capability_flags: PASSED\n\n");
}

static void test_version_info_encoding(void) {
    printf("Testing rbox_version_info_t encoding in server_id...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_version_info_t version_info = {
        .major = RBOX_PROTOCOL_MAJOR,
        .minor = RBOX_PROTOCOL_MINOR,
        .capabilities = RBOX_DEFAULT_CAPABILITIES
    };

    rbox_error_t err = rbox_encode_response(
        NULL, NULL, 0, RBOX_DECISION_ALLOW,
        "OK", 0, 0, NULL,
        buf, sizeof(buf), &out_len,
        &version_info
    );

    assert(err == RBOX_OK);
    printf("  ✓ Response encoded with version info\n");

    uint8_t *server_id = buf + RBOX_HEADER_OFFSET_SERVER_ID;
    uint16_t major = *(uint16_t *)(server_id + 0);
    uint16_t minor = *(uint16_t *)(server_id + 2);
    uint32_t caps = *(uint32_t *)(server_id + 4);

    assert(major == RBOX_PROTOCOL_MAJOR);
    printf("  ✓ Server ID major = %u\n", major);

    assert(minor == RBOX_PROTOCOL_MINOR);
    printf("  ✓ Server ID minor = %u\n", minor);

    assert(caps == RBOX_DEFAULT_CAPABILITIES);
    printf("  ✓ Server ID capabilities = 0x%08x\n", caps);

    printf("test_version_info_encoding: PASSED\n\n");
}

static void test_version_info_without_cap(void) {
    printf("Testing rbox_encode_response without negotiated version...\n");

    uint8_t buf[8192];
    size_t out_len;

    rbox_error_t err = rbox_encode_response(
        NULL, NULL, 0, RBOX_DECISION_ALLOW,
        "OK", 0, 0, NULL,
        buf, sizeof(buf), &out_len,
        NULL
    );

    assert(err == RBOX_OK);
    printf("  ✓ Response encoded without version info (legacy mode)\n");

    uint8_t *server_id = buf + RBOX_HEADER_OFFSET_SERVER_ID;
    assert(server_id[0] == 'S' && server_id[1] == 'S');
    printf("  ✓ Server ID is 'S' repeated (legacy marker)\n");

    printf("test_version_info_without_cap: PASSED\n\n");
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void) {
    printf("=== Versioning Unit Tests ===\n\n");

    test_get_protocol_version();
    test_supported_capabilities();
    test_version_is_compatible();
    test_capability_flags();
    test_version_info_encoding();
    test_version_info_without_cap();

    printf("=== All Versioning Tests PASSED ===\n");
    return 0;
}
