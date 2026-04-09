/*
 * packet.h - Packet parsing and building internals for rbox-protocol
 *
 * Internal header - not for library users
 */

#ifndef RBOX_PACKET_H
#define RBOX_PACKET_H

#include <stdint.h>
#include <stddef.h>

/* 64-bit command hash - two-step hash with different constants */
uint64_t rbox_hash64(const char *str, size_t len);

#endif /* RBOX_PACKET_H */
