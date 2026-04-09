/*
 * runtime.h - Library runtime initialization for rbox-protocol
 *
 * Uses constructor/destructor attributes to automatically initialize
 * and clean up library state before/after application use.
 */

#ifndef RBOX_RUNTIME_H
#define RBOX_RUNTIME_H

#include <stdint.h>
#include <stddef.h>

/* Initialize library runtime - called automatically before main()
 * Uses constructor attribute for automatic initialization */
void rbox_runtime_init(void);

/* Clean up library runtime - called automatically after exit()
 * Uses destructor attribute for automatic cleanup */
void rbox_runtime_shutdown(void);

/* Thread-local random seed management */
uint32_t rbox_runtime_rand_seed(void);

/* CRC32 checksum - composable, takes previous CRC value
 * If prev_crc is 0, starts fresh (initial CRC = 0xFFFFFFFF).
 * Otherwise continues from prev_crc (expects pre-xored value). */
uint32_t rbox_runtime_crc32(uint32_t prev_crc, const void *data, size_t len);

#endif /* RBOX_RUNTIME_H */
