/*
 * protocol_encoding.c - Pure protocol encoding functions
 *
 * No dependencies on sockets, threads, or session state.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>

#include "protocol_encoding.h"
#include "runtime.h"

/* Thread-local seed for request ID generation */
static __thread uint32_t g_rand_seed = 0;

/* Initialize the thread-local seed if not yet initialized */
static void ensure_rand_seed_init(void) {
    if (g_rand_seed == 0) {
        g_rand_seed = rbox_runtime_rand_seed();
    }
}

/* Static client_id - generated once per process */
static uint8_t g_client_id[16] = {0};
static pthread_once_t g_client_id_once = PTHREAD_ONCE_INIT;

static void init_client_id_once(void) {
    ensure_rand_seed_init();

    pid_t pid = getpid();
    pid_t ppid = getppid();

    /* First 8 bytes: pid + ppid */
    uint64_t id_part1 = ((uint64_t)(uint32_t)pid << 32) | (uint32_t)ppid;

    /* Last 8 bytes: random + timestamp */
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t random_part = ((uint64_t)rand_r(&g_rand_seed) << 32) ^ (uint64_t)ts.tv_nsec;

    memcpy(g_client_id, &id_part1, 8);
    memcpy(g_client_id + 8, &random_part, 8);
}

/* ============================================================
 * ID GENERATION
 * ============================================================ */

void rbox_generate_request_id(uint8_t id_out[16]) {
    if (!id_out) return;

    ensure_rand_seed_init();

    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);

    /* Mix bits for uniqueness */
    uint64_t a = (uint64_t)ts.tv_sec ^ ((uint64_t)ts.tv_nsec << 32);
    uint64_t b = (uint64_t)rand_r(&g_rand_seed) ^ ((uint64_t)getpid() << 32);

    memcpy(id_out, &a, 8);
    memcpy(id_out + 8, &b, 8);
}

const uint8_t *rbox_get_client_id(void) {
    pthread_once(&g_client_id_once, init_client_id_once);
    return g_client_id;
}

/* ============================================================
 * COMMAND HASH
 * ============================================================ */

uint64_t rbox_hash64(const char *str, size_t len) {
    if (!str || len == 0) return 0;

    /* Two-step hash with different constants */
    /* Step 1: Mix using FNV-1a like algorithm with different prime */
    uint64_t hash = 14695981039346656037ULL;  /* FNV offset basis */
    for (size_t i = 0; i < len; i++) {
        hash ^= (uint64_t)(unsigned char)str[i];
        hash *= 1099511628211ULL;  /* FNV prime 64-bit */
    }

    /* Step 2: Mix using DJB2-like algorithm with different constants */
    uint64_t hash2 = 5381ULL;
    for (size_t i = 0; i < len; i++) {
        hash2 = ((hash2 << 5) + hash2) + (uint64_t)(unsigned char)str[i];
    }

    /* Combine both hashes */
    return hash ^ (hash2 + 0x9e3779b97f4a7c15ULL);
}

/* ============================================================
 * REQUEST ENCODING
 * ============================================================ */

rbox_error_t rbox_encode_request(
    const char *command,
    const char *caller,
    const char *syscall,
    int argc,
    const char **argv,
    int env_var_count,
    const char **env_var_names,
    const float *env_var_scores,
    uint8_t *out_buf,
    size_t buf_capacity,
    size_t *out_len) {

    if (!out_buf || !out_len || !command) {
        return RBOX_ERR_INVALID;
    }

    /* Estimate required capacity */
    size_t needed = RBOX_HEADER_SIZE;
    size_t addend = strlen(command) + 1;
    if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
    if (caller) {
        addend = strlen(caller) + 1;
        if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
    } else {
        if (__builtin_add_overflow(needed, 1, &needed)) return RBOX_ERR_INVALID;
    }
    if (syscall) {
        addend = strlen(syscall) + 1;
        if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
    } else {
        if (__builtin_add_overflow(needed, 1, &needed)) return RBOX_ERR_INVALID;
    }
    for (int i = 0; i < argc; i++) {
        if (argv[i]) {
            addend = strlen(argv[i]) + 1;
            if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
        }
    }
    if (__builtin_add_overflow(needed, 1, &needed)) return RBOX_ERR_INVALID;
    for (int i = 0; i < env_var_count; i++) {
        if (env_var_names[i]) {
            addend = strlen(env_var_names[i]) + 1 + 4;
            if (__builtin_add_overflow(needed, addend, &needed)) return RBOX_ERR_INVALID;
        }
    }
    if (buf_capacity < needed) {
        *out_len = needed;
        return RBOX_ERR_INVALID;
    }

    memset(out_buf, 0, RBOX_HEADER_SIZE + (needed - RBOX_HEADER_SIZE));

    /* Encode body */
    size_t pos = RBOX_HEADER_SIZE;
    uint8_t *body = out_buf + RBOX_HEADER_SIZE;

    /* command */
    size_t cmd_len = strlen(command);
    memcpy(body + pos - RBOX_HEADER_SIZE, command, cmd_len + 1);
    pos += cmd_len + 1;

    /* caller */
    if (caller && caller[0]) {
        size_t caller_len = strlen(caller);
        memcpy(body + pos - RBOX_HEADER_SIZE, caller, caller_len + 1);
        pos += caller_len + 1;
    } else {
        body[pos - RBOX_HEADER_SIZE] = '\0';
        pos += 1;
    }

    /* syscall */
    if (syscall && syscall[0]) {
        size_t syscall_len = strlen(syscall);
        memcpy(body + pos - RBOX_HEADER_SIZE, syscall, syscall_len + 1);
        pos += syscall_len + 1;
    } else {
        body[pos - RBOX_HEADER_SIZE] = '\0';
        pos += 1;
    }

    /* argv */
    for (int i = 0; i < argc; i++) {
        if (!argv[i]) break;
        size_t arg_len = strlen(argv[i]);
        memcpy(body + pos - RBOX_HEADER_SIZE, argv[i], arg_len + 1);
        pos += arg_len + 1;
    }
    body[pos - RBOX_HEADER_SIZE] = '\0';
    pos += 1;

    /* Environment variables */
    uint32_t fenv_hash = 0;
    for (int i = 0; i < env_var_count; i++) {
        if (!env_var_names[i]) continue;
        size_t name_len = strlen(env_var_names[i]);
        memcpy(body + pos - RBOX_HEADER_SIZE, env_var_names[i], name_len + 1);
        pos += name_len + 1;
        float score = env_var_scores ? env_var_scores[i] : 0.0f;
        memcpy(body + pos - RBOX_HEADER_SIZE, &score, 4);
        pos += 4;

        /* Update fenv_hash (simple djb2) */
        const char *s = env_var_names[i];
        uint32_t h = 5381;
        while (*s) {
            h = ((h << 5) + h) + (uint32_t)(unsigned char)*s++;
        }
        fenv_hash ^= h;
    }

    size_t body_len = pos - RBOX_HEADER_SIZE;

    /* Write header using writer helpers for endian-safe serialization */
    rbox_writer_t w;
    rbox_writer_init(&w, out_buf, RBOX_HEADER_SIZE);

    /* Header fields (v9 format) */
    rbox_write_u32(&w, RBOX_MAGIC);
    rbox_write_u32(&w, RBOX_VERSION);
    const uint8_t *client_id = rbox_get_client_id();
    rbox_write_bytes(&w, client_id, 16);
    uint8_t request_id[16];
    rbox_generate_request_id(request_id);
    rbox_write_bytes(&w, request_id, 16);
    rbox_write_bytes(&w, (uint8_t[16]){0}, 16);  /* server_id reserved (zeros) */
    rbox_write_u32(&w, RBOX_MSG_REQ);
    rbox_write_u32(&w, RBOX_FLAG_FIRST);
    rbox_write_u64(&w, 0);  /* offset */
    rbox_write_u32(&w, body_len);  /* chunk_len */
    rbox_write_u64(&w, body_len);  /* total_len */

    /* cmd_hash and fenv_hash */
    uint32_t cmd_hash = rbox_runtime_crc32(0, command, strlen(command));
    rbox_write_u32(&w, cmd_hash);
    rbox_write_u32(&w, fenv_hash);

    /* Caller/syscall sizes */
    size_t caller_len = caller ? strlen(caller) : 0;
    size_t syscall_len = syscall ? strlen(syscall) : 0;
    if (caller_len > 15) caller_len = 15;
    if (syscall_len > 15) syscall_len = 15;
    uint8_t cs_size = ((syscall_len << 4) & 0xF0) | (caller_len & 0x0F);
    rbox_write_u8(&w, cs_size);
    rbox_write_bytes(&w, caller ? caller : "", caller_len);
    rbox_writer_skip(&w, 15 - caller_len);
    rbox_write_bytes(&w, syscall ? syscall : "", syscall_len);
    rbox_writer_skip(&w, 15 - syscall_len);

    rbox_writer_skip_to(&w, RBOX_HEADER_OFFSET_CHECKSUM);

    /* Header checksum */
    uint32_t checksum = rbox_runtime_crc32(0, out_buf, RBOX_HEADER_OFFSET_CHECKSUM);
    rbox_write_u32(&w, checksum);

    /* Body checksum */
    uint32_t body_checksum = rbox_runtime_crc32(0, out_buf + RBOX_HEADER_SIZE, body_len);
    rbox_write_u32(&w, body_checksum);

    *out_len = RBOX_HEADER_SIZE + body_len;
    return RBOX_OK;
}

/* ============================================================
 * RESPONSE ENCODING
 * ============================================================ */

rbox_error_t rbox_encode_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t cmd_hash,
    uint8_t decision,
    const char *reason,
    uint32_t fenv_hash,
    int env_decision_count,
    const uint8_t *env_decisions,
    uint8_t *out_buf,
    size_t buf_capacity,
    size_t *out_len) {

    if (!out_len) return RBOX_ERR_INVALID;

    if (env_decision_count < 0 || env_decision_count > 4096) return RBOX_ERR_INVALID;

    size_t reason_len = reason ? strlen(reason) : 0;
    if (reason_len > RBOX_RESPONSE_MAX_REASON) reason_len = RBOX_RESPONSE_MAX_REASON;
    size_t bitmap_size = (env_decision_count > 0 && env_decisions) ? (env_decision_count + 7) / 8 : 0;
    size_t body_len = 1 + reason_len + 1 + 4 + 2 + bitmap_size;

    size_t total_len = RBOX_HEADER_SIZE + body_len;
    if (buf_capacity < total_len) {
        *out_len = total_len;
        return RBOX_ERR_INVALID;
    }

    memset(out_buf, 0, total_len);

    /* Write header using writer helpers for endian-safe serialization */
    rbox_writer_t w;
    rbox_writer_init(&w, out_buf, RBOX_HEADER_SIZE);

    rbox_write_u32(&w, RBOX_MAGIC);
    rbox_write_u32(&w, RBOX_VERSION);
    rbox_write_bytes(&w, client_id ? client_id : (uint8_t[16]){0}, 16);
    rbox_write_bytes(&w, request_id ? request_id : (uint8_t[16]){0}, 16);
    rbox_write_bytes(&w, (uint8_t[16]){'S','S','S','S','S','S','S','S','S','S','S','S','S','S','S','S'}, 16);  /* server_id = 'S' */
    rbox_write_u32(&w, 0);  /* type */
    rbox_write_u32(&w, 0);  /* flags */
    rbox_write_u64(&w, 0);  /* offset */
    rbox_write_u32(&w, body_len);  /* chunk_len */
    rbox_write_u64(&w, body_len);  /* total_len */
    rbox_write_u32(&w, cmd_hash);
    rbox_write_u32(&w, fenv_hash);

    rbox_writer_skip_to(&w, RBOX_HEADER_OFFSET_CHECKSUM);

    /* Header checksum */
    uint32_t checksum = rbox_runtime_crc32(0, out_buf, RBOX_HEADER_OFFSET_CHECKSUM);
    rbox_write_u32(&w, checksum);

    /* Body */
    uint8_t *body = out_buf + RBOX_HEADER_SIZE;
    rbox_writer_t bw;
    rbox_writer_init(&bw, body, body_len);
    rbox_write_u8(&bw, decision);
    if (reason_len > 0) {
        rbox_write_bytes(&bw, reason, reason_len);
    }
    rbox_write_u8(&bw, '\0');
    rbox_write_u32(&bw, fenv_hash);
    rbox_write_u16(&bw, (uint16_t)env_decision_count);
    if (bitmap_size > 0 && env_decisions) {
        rbox_write_bytes(&bw, env_decisions, bitmap_size);
    }

    /* Body checksum */
    uint32_t body_checksum = rbox_runtime_crc32(0, body, body_len);
    rbox_write_u32(&w, body_checksum);

    *out_len = total_len;
    return RBOX_OK;
}

char *rbox_encode_telemetry_response(
    const uint8_t *client_id,
    const uint8_t *request_id,
    uint32_t allow_count,
    uint32_t deny_count,
    size_t *out_len) {

    if (!out_len) return NULL;

    char reason[64];
    int snprinted = snprintf(reason, sizeof(reason), "ALLOW:%u DENY:%u\n", allow_count, deny_count);
    size_t reason_len = (snprinted < 0) ? 0 : (size_t)snprinted;
    if (reason_len >= sizeof(reason)) {
        reason_len = sizeof(reason) - 1;
    }
    reason[reason_len] = '\0';

    size_t body_len = 1 + reason_len + 1;

    size_t total_len = RBOX_HEADER_SIZE + body_len;
    uint8_t *pkt = malloc(total_len);
    if (!pkt) return NULL;
    memset(pkt, 0, total_len);

    /* Write header using writer helpers */
    rbox_writer_t w;
    rbox_writer_init(&w, pkt, RBOX_HEADER_SIZE);

    rbox_write_u32(&w, RBOX_MAGIC);
    rbox_write_u32(&w, RBOX_VERSION);
    rbox_write_bytes(&w, client_id ? client_id : (uint8_t[16]){0}, 16);
    rbox_write_bytes(&w, request_id ? request_id : (uint8_t[16]){0}, 16);
    rbox_write_bytes(&w, (uint8_t[16]){'S','S','S','S','S','S','S','S','S','S','S','S','S','S','S','S'}, 16);
    rbox_write_u32(&w, 0);
    rbox_write_u32(&w, 0);
    rbox_write_u64(&w, 0);
    rbox_write_u32(&w, body_len);
    rbox_write_u64(&w, body_len);
    rbox_write_u32(&w, 0);
    rbox_write_u32(&w, 0);

    rbox_writer_skip_to(&w, RBOX_HEADER_OFFSET_CHECKSUM);

    /* Header checksum */
    uint32_t checksum = rbox_runtime_crc32(0, pkt, RBOX_HEADER_OFFSET_CHECKSUM);
    rbox_write_u32(&w, checksum);

    /* Body */
    uint8_t *body = pkt + RBOX_HEADER_SIZE;
    rbox_writer_t bw;
    rbox_writer_init(&bw, body, body_len);
    rbox_write_u8(&bw, RBOX_DECISION_UNKNOWN);
    rbox_write_bytes(&bw, reason, reason_len);
    rbox_write_u8(&bw, '\0');

    /* Body checksum */
    uint32_t body_checksum = rbox_runtime_crc32(0, body, body_len);
    rbox_write_u32(&w, body_checksum);

    *out_len = total_len;
    return (char *)pkt;
}
