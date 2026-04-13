/*
 * session.c - Non-blocking session implementation
 *
 * Extracted from packet.c for better separation of concerns.
 * This module provides a state machine for non-blocking socket communication.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <time.h>
#include <pthread.h>

#include "rbox_protocol.h"
#include "session_internal.h"
#include "socket.h"
#include "runtime.h"

/* Debug flag */
#ifndef RBOX_CLIENT_DEBUG
#define RBOX_CLIENT_DEBUG 0
#endif

#if RBOX_CLIENT_DEBUG
#define CDBG(fmt, ...) fprintf(stderr, "[CLIENT] " fmt "\n", ##__VA_ARGS__)
#else
#define CDBG(fmt, ...) ((void)0)
#endif

/* Get current time in ms */
uint64_t get_time_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Check if we should retry connection */
static int should_retry(rbox_session_t *session) {
    if (session->max_retries == 0) return 1;
    return session->retry_attempt < session->max_retries;
}

/* ============================================================
 * SESSION FUNCTIONS
 * ============================================================ */

rbox_session_t *rbox_session_new(const char *socket_path,
    uint32_t base_delay_ms, uint32_t max_retries) {
    if (!socket_path) return NULL;

    rbox_session_t *session = calloc(1, sizeof(rbox_session_t));
    if (!session) return NULL;

    size_t len = strlen(socket_path);
    if (len >= sizeof(session->socket_path)) len = sizeof(session->socket_path) - 1;
    memcpy(session->socket_path, socket_path, len);
    session->socket_path[len] = '\0';

    session->base_delay_ms = base_delay_ms;
    session->max_retries = max_retries;
    session->retry_seed = rbox_runtime_rand_seed();
    session->state = RBOX_SESSION_DISCONNECTED;

    return session;
}

void rbox_session_free(rbox_session_t *session) {
    if (!session) return;
    rbox_client_close(session->client);
    free(session->send_buf);
    rbox_response_free(&session->response);
    free(session->recv_buf);
    free(session->response_data);
    free(session);
}

int rbox_session_pollfd(const rbox_session_t *session, short *out_events) {
    if (out_events) *out_events = 0;
    if (!session || !session->client) return -1;

    short events = 0;

    switch (session->state) {
        case RBOX_SESSION_DISCONNECTED:
        case RBOX_SESSION_CONNECTING:
            events = POLLOUT;
            break;
        case RBOX_SESSION_CONNECTED:
            break;
        case RBOX_SESSION_SENDING:
            events = POLLOUT;
            break;
        case RBOX_SESSION_WAITING:
            events = POLLIN;
            break;
        case RBOX_SESSION_RESPONSE_READY:
        case RBOX_SESSION_FAILED:
            break;
    }

    if (out_events) *out_events = events;
    return rbox_client_fd(session->client);
}

rbox_session_state_t rbox_session_state(const rbox_session_t *session) {
    return session ? session->state : RBOX_SESSION_DISCONNECTED;
}

rbox_error_t rbox_session_error(const rbox_session_t *session) {
    return session ? session->error : RBOX_ERR_INVALID;
}

rbox_error_t rbox_session_connect(rbox_session_t *session) {
    if (!session) return RBOX_ERR_INVALID;
    if (session->state == RBOX_SESSION_CONNECTING ||
        session->state == RBOX_SESSION_CONNECTED ||
        session->state == RBOX_SESSION_WAITING ||
        session->state == RBOX_SESSION_RESPONSE_READY) {
        return RBOX_ERR_INVALID;
    }

    if (session->client) {
        rbox_client_close(session->client);
        session->client = NULL;
    }

    session->client = rbox_client_connect(session->socket_path);
    if (session->client) {
        session->state = RBOX_SESSION_CONNECTED;
        session->retry_attempt = 0;
        return RBOX_OK;
    }

    if (session->base_delay_ms == 0) {
        session->state = RBOX_SESSION_FAILED;
        session->error = RBOX_ERR_IO;
        return RBOX_ERR_IO;
    }

    if (!should_retry(session)) {
        session->state = RBOX_SESSION_FAILED;
        session->error = RBOX_ERR_IO;
        return RBOX_ERR_IO;
    }

    session->retry_attempt++;
    uint32_t delay = rbox_calculate_retry_delay(session->base_delay_ms, session->retry_attempt, RBOX_MAX_RETRY_DELAY_MS, &session->retry_seed);
    session->next_retry_time = get_time_ms() + delay;
    session->state = RBOX_SESSION_CONNECTING;

    return RBOX_ERR_IO;
}

rbox_error_t rbox_session_send_request(rbox_session_t *session,
    const char *command, const char *caller, const char *syscall,
    int argc, const char **argv,
    int env_var_count, const char **env_var_names, const float *env_var_scores) {
    if (!session || !command) return RBOX_ERR_INVALID;
    if (session->state != RBOX_SESSION_CONNECTED) return RBOX_ERR_INVALID;

    char tmp[65536];
    size_t tmp_len;
    rbox_error_t err = rbox_build_request(tmp, sizeof(tmp), &tmp_len,
        command, caller, syscall, argc, argv,
        env_var_count, env_var_names, env_var_scores);
    if (err != RBOX_OK) {
        if (err == RBOX_ERR_INVALID && tmp_len > sizeof(tmp)) {
            char *buf = malloc(tmp_len);
            if (!buf) {
                session->state = RBOX_SESSION_FAILED;
                session->error = RBOX_ERR_MEMORY;
                return RBOX_ERR_MEMORY;
            }
            err = rbox_build_request(buf, tmp_len, &tmp_len,
                command, caller, syscall, argc, argv,
                env_var_count, env_var_names, env_var_scores);
            if (err != RBOX_OK) {
                free(buf);
                session->state = RBOX_SESSION_FAILED;
                session->error = err;
                return err;
            }
            memcpy(session->request_id, buf + RBOX_HEADER_OFFSET_REQUEST_ID, 16);
            session->send_buf = buf;
            session->send_len = tmp_len;
            session->send_offset = 0;
            session->state = RBOX_SESSION_SENDING;
            return RBOX_OK;
        }
        session->state = RBOX_SESSION_FAILED;
        session->error = err;
        return err;
    }

    memcpy(session->request_id, tmp + RBOX_HEADER_OFFSET_REQUEST_ID, 16);

    session->send_buf = malloc(tmp_len);
    if (!session->send_buf) {
        session->state = RBOX_SESSION_FAILED;
        session->error = RBOX_ERR_MEMORY;
        return RBOX_ERR_MEMORY;
    }
    memcpy(session->send_buf, tmp, tmp_len);
    session->send_len = tmp_len;
    session->send_offset = 0;

    session->state = RBOX_SESSION_SENDING;
    return RBOX_OK;
}

rbox_error_t rbox_session_send_raw(rbox_session_t *session, const char *data, size_t len) {
    if (!session || !data || len == 0) return RBOX_ERR_INVALID;
    if (session->state != RBOX_SESSION_CONNECTED) return RBOX_ERR_INVALID;

    free(session->send_buf);
    session->send_buf = malloc(len);
    if (!session->send_buf) {
        session->state = RBOX_SESSION_FAILED;
        return RBOX_ERR_MEMORY;
    }
    memcpy(session->send_buf, data, len);
    session->send_len = len;
    session->send_offset = 0;

    session->state = RBOX_SESSION_SENDING;
    return RBOX_OK;
}

rbox_session_state_t rbox_session_heartbeat(rbox_session_t *session, short events) {
    if (!session) return RBOX_SESSION_FAILED;

    CDBG("heartbeat: state=%d events=0x%x", session->state, events);

    switch (session->state) {
        case RBOX_SESSION_DISCONNECTED:
            if (events & POLLOUT) {
                CDBG("disconnected -> connecting");
                rbox_session_connect(session);
            }
            break;

        case RBOX_SESSION_CONNECTING:
            if (events & POLLOUT) {
                int fd = rbox_client_fd(session->client);
                int so_error;
                socklen_t optlen = sizeof(so_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen) == 0 && so_error == 0) {
                    CDBG("connecting -> connected");
                    session->state = RBOX_SESSION_CONNECTED;
                    session->retry_attempt = 0;
                } else {
                    CDBG("connecting failed");
                    rbox_client_close(session->client);
                    session->client = NULL;
                    if (session->base_delay_ms > 0 && should_retry(session)) {
                        session->retry_attempt++;
                        uint32_t delay = rbox_calculate_retry_delay(session->base_delay_ms, session->retry_attempt, RBOX_MAX_RETRY_DELAY_MS, &session->retry_seed);
                        session->next_retry_time = get_time_ms() + delay;
                        CDBG("connecting retry scheduled, attempt %d", session->retry_attempt);
                    } else {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                        CDBG("connecting -> failed (no retries)");
                    }
                    break;
                }
            }

            if (!session->client && session->base_delay_ms > 0) {
                if (get_time_ms() < session->next_retry_time) {
                    break;
                }
                CDBG("connecting timeout, retrying connection");
                session->client = rbox_client_connect(session->socket_path);
                if (!session->client) {
                    if (!should_retry(session)) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                        CDBG("connecting -> failed (no retries left)");
                    } else {
                        session->retry_attempt++;
                        uint32_t delay = rbox_calculate_retry_delay(session->base_delay_ms, session->retry_attempt, RBOX_MAX_RETRY_DELAY_MS, &session->retry_seed);
                        session->next_retry_time = get_time_ms() + delay;
                        CDBG("connecting retry attempt %d", session->retry_attempt);
                    }
                } else {
                    session->state = RBOX_SESSION_CONNECTED;
                    session->retry_attempt = 0;
                    CDBG("connecting -> connected");
                }
            }
            break;

        case RBOX_SESSION_CONNECTED:
            CDBG("connected, idle");
            break;

        case RBOX_SESSION_SENDING:
            if (events & POLLOUT) {
                int fd = rbox_client_fd(session->client);
                ssize_t n = rbox_write_nonblocking(fd,
                    session->send_buf, session->send_len, &session->send_offset);
                if (n < 0) {
                    CDBG("sending: write error");
                    rbox_client_close(session->client);
                    session->client = NULL;
                    if (session->base_delay_ms > 0 && should_retry(session)) {
                        session->retry_attempt = 1;
                        uint32_t delay = rbox_calculate_retry_delay(session->base_delay_ms, session->retry_attempt, RBOX_MAX_RETRY_DELAY_MS, &session->retry_seed);
                        session->next_retry_time = get_time_ms() + delay;
                        session->state = RBOX_SESSION_CONNECTING;
                        CDBG("sending -> connecting (retry)");
                    } else {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                        CDBG("sending -> failed");
                    }
                    break;
                }
                if (session->send_offset == session->send_len) {
                    free(session->send_buf);
                    session->send_buf = NULL;
                    session->state = RBOX_SESSION_WAITING;
                    CDBG("sending -> waiting");
                }
            }
            break;

        case RBOX_SESSION_WAITING:
            CDBG("waiting: events=0x%x", events);
            if (events & POLLIN) {
                int fd = rbox_client_fd(session->client);

                if (!session->recv_buf) {
                    session->recv_capacity = 4096;
                    session->recv_buf = malloc(session->recv_capacity);
                    if (!session->recv_buf) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_MEMORY;
                        CDBG("waiting: malloc failed -> failed");
                        break;
                    }
                    session->recv_len = 0;
                }

                size_t space = session->recv_capacity - session->recv_len;
                ssize_t n = rbox_read_nonblocking(fd,
                                session->recv_buf + session->recv_len, space);
                CDBG("waiting: read_nonblocking returned %zd", n);
                if (n == -2) {
                    if (session->recv_len < RBOX_HEADER_SIZE) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                        CDBG("waiting: EOF without enough data -> failed");
                        break;
                    }
                    CDBG("waiting: EOF but have data, will validate");
                } else if (n < 0) {
                    session->state = RBOX_SESSION_FAILED;
                    session->error = RBOX_ERR_IO;
                    CDBG("waiting: read error -> failed");
                    break;
                } else if (n == 0) {
                    CDBG("waiting: no data");
                    break;
                } else {
                    session->recv_len += n;
                    CDBG("waiting: received %zd bytes, total %zu", n, session->recv_len);
                }

                if (session->recv_len >= RBOX_HEADER_SIZE) {
                    rbox_decoded_header_t hdr;
                    rbox_decode_header(session->recv_buf, session->recv_len, &hdr);
                    if (!hdr.valid) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_INVALID;
                        CDBG("waiting: invalid header -> failed");
                        break;
                    }
                    size_t total_needed = RBOX_HEADER_SIZE + hdr.chunk_len;
                    if (total_needed > session->recv_capacity) {
                        char *new_buf = realloc(session->recv_buf, total_needed);
                        if (!new_buf) {
                            free(session->recv_buf);
                            session->recv_buf = NULL;
                            session->state = RBOX_SESSION_FAILED;
                            session->error = RBOX_ERR_MEMORY;
                            CDBG("waiting: realloc failed -> failed");
                            break;
                        }
                        session->recv_buf = new_buf;
                        session->recv_capacity = total_needed;
                    }
                    if (session->recv_len >= total_needed) {
                        rbox_response_t resp;
                        rbox_error_t err = validate_response(session->recv_buf,
                                            session->recv_len, session->request_id, &resp);
                        if (err == RBOX_OK) {
                            session->response = resp;
                            session->response_data = session->recv_buf;
                            session->response_len = session->recv_len;
                            session->recv_buf = NULL;
                            session->recv_len = 0;
                            session->recv_capacity = 0;
                            session->state = RBOX_SESSION_RESPONSE_READY;
                            CDBG("waiting: response ready");
                        } else if (err == RBOX_ERR_MISMATCH || err == RBOX_ERR_IO) {
                            free(session->recv_buf);
                            session->recv_buf = NULL;
                            session->state = RBOX_SESSION_FAILED;
                            session->error = err;
                            CDBG("waiting: validation error (%d) -> failed", err);
                        } else {
                            free(session->recv_buf);
                            session->recv_buf = NULL;
                            session->state = RBOX_SESSION_FAILED;
                            session->error = err;
                            CDBG("waiting: validation error (%d) -> failed", err);
                        }
                        break;
                    }
                }
            } else if (events & (POLLHUP | POLLERR)) {
                CDBG("waiting: POLLHUP/POLLERR -> failed");
                session->state = RBOX_SESSION_FAILED;
                session->error = RBOX_ERR_IO;
                break;
            } else {
                int fd = rbox_client_fd(session->client);
                int so_error = 0;
                socklen_t optlen = sizeof(so_error);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_error, &optlen) == 0 && so_error != 0) {
                    CDBG("waiting: SO_ERROR=%d -> failed", so_error);
                    session->state = RBOX_SESSION_FAILED;
                    session->error = RBOX_ERR_IO;
                } else {
                    char buf;
                    ssize_t r = recv(fd, &buf, 1, MSG_PEEK | MSG_DONTWAIT);
                    CDBG("waiting: manual EOF check returned %zd (errno=%d)", r, errno);
                    if (r == 0) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                        CDBG("waiting: manual EOF -> failed");
                    } else if (r < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                        session->state = RBOX_SESSION_FAILED;
                        session->error = RBOX_ERR_IO;
                        CDBG("waiting: manual recv error -> failed");
                    }
                }
            }
            break;

        case RBOX_SESSION_RESPONSE_READY:
        case RBOX_SESSION_FAILED:
            CDBG("state %d, no action", session->state);
            break;
    }

    return session->state;
}

const rbox_response_t *rbox_session_response(const rbox_session_t *session) {
    if (!session || session->state != RBOX_SESSION_RESPONSE_READY) {
        return NULL;
    }
    return &session->response;
}

void rbox_session_reset(rbox_session_t *session) {
    if (!session) return;
    if (session->state == RBOX_SESSION_RESPONSE_READY) {
        session->state = RBOX_SESSION_CONNECTED;
        rbox_response_free(&session->response);
        free(session->response_data);
        session->response_data = NULL;
        session->response_len = 0;
        free(session->recv_buf);
        session->recv_buf = NULL;
        session->recv_len = 0;
        session->recv_capacity = 0;
        CDBG("reset: ready -> connected");
    }
}

void rbox_session_disconnect(rbox_session_t *session) {
    if (!session) return;
    if (session->client) {
        rbox_client_close(session->client);
        session->client = NULL;
    }
    session->state = RBOX_SESSION_DISCONNECTED;
    CDBG("disconnect");
}
