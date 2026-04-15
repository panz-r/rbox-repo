/*
 * error_internal.h - Internal error handling helpers
 *
 * Helper functions for filling rbox_error_info_t without memory allocation.
 * These are static inline to allow compiler optimization and inlining.
 */

#ifndef RBOX_ERROR_INTERNAL_H
#define RBOX_ERROR_INTERNAL_H

#include "rbox_protocol.h"

/* Set error info if err pointer is non-NNULL.
 * This is the primary helper for propagating errors. */
static inline void rbox_error_set(rbox_error_info_t *err,
                                  rbox_error_t code,
                                  int sys_errno,
                                  const char *message) {
    if (err) {
        err->code = code;
        err->sys_errno = sys_errno;
        err->message = message;
    }
}

/* Propagate an error from a lower-level function.
 * Copies the error info if both pointers are non-NULL. */
static inline void rbox_error_propagate(rbox_error_info_t *err,
                                        const rbox_error_info_t *src) {
    if (err && src) {
        err->code = src->code;
        err->sys_errno = src->sys_errno;
        err->message = src->message;
    }
}

#endif /* RBOX_ERROR_INTERNAL_H */
