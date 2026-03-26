/*
 * packet_stream.h - Chunked transfer streaming for rbox-protocol
 *
 * Layer 4: Chunked transfer - client and server stream management
 */

#ifndef RBOX_PACKET_STREAM_H
#define RBOX_PACKET_STREAM_H

#include <stdint.h>
#include <stddef.h>
#include <rbox_protocol.h>

/* Stream state for client sending chunks */
struct rbox_stream {
    uint8_t  client_id[16];
    uint8_t  request_id[16];
    uint64_t offset;
    uint64_t total_len;
    int      is_server;
    char    *buffer;
    size_t   buf_capacity;
    size_t   buf_len;
};

/* Create a new stream for chunked sending (client side) */
rbox_stream_t *rbox_stream_new(const uint8_t *client_id, const uint8_t *request_id);

/* Create stream state for incoming chunks (server side) */
rbox_stream_t *rbox_server_stream_new(const uint8_t *client_id, const uint8_t *request_id,
                                       uint64_t total_len);

/* Free stream */
void rbox_stream_free(rbox_stream_t *stream);

/* Get current stream offset */
uint64_t rbox_stream_offset(const rbox_stream_t *stream);

/* Send chunk to server */
rbox_error_t rbox_stream_send_chunk(rbox_client_t *client, rbox_stream_t *stream,
                                     const void *data, size_t len,
                                     uint32_t flags, uint64_t total_len);

/* Read ACK from server */
rbox_error_t rbox_stream_read_ack(rbox_client_t *client, rbox_stream_t *stream);

/* Server: Receive a chunk */
rbox_error_t rbox_server_stream_recv(rbox_client_t *client, rbox_stream_t *stream,
                                      void *buffer, size_t buf_size,
                                      size_t *out_chunk_len);

/* Server: Send ACK to client */
rbox_error_t rbox_server_stream_ack(rbox_client_t *client, rbox_stream_t *stream,
                                     int32_t status, const char *reason);

/* Server: Complete stream and get final request data */
rbox_error_t rbox_server_stream_complete(rbox_stream_t *stream,
                                         rbox_request_t *out_request);

#endif /* RBOX_PACKET_STREAM_H */
