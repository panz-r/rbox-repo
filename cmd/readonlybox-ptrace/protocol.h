/*
 * readonlybox-ptrace protocol definitions
 *
 * Protocol for communication between ptrace client and server.
 * Based on the LD_PRELOAD client protocol.
 */

#ifndef READONLYBOX_PTRACE_PROTOCOL_H
#define READONLYBOX_PTRACE_PROTOCOL_H

#include <stdint.h>
#include <stddef.h>

/* Protocol magic bytes - "ROBO" = ReadOnlyBox */
#define ROBO_MAGIC      0x524F424F
#define ROBO_VERSION    4  /* Protocol version for ptrace client */

/* Protocol constants */
#define ROBO_MAX_CMD    4096
#define ROBO_MAX_ARGS   128
#define ROBO_MAX_ENV    256
#define ROBO_MAX_PATH   1024

/* Message types */
#define ROBO_MSG_LOG    0  /* Log message from client */
#define ROBO_MSG_REQ    1  /* Command request from client */

/* Decision codes */
#define ROBO_DECISION_UNKNOWN  0
#define ROBO_DECISION_ALLOW    2
#define ROBO_DECISION_DENY     3
#define ROBO_DECISION_ERROR    4

/* Default socket path */
#define ROBO_DEFAULT_SOCKET "/tmp/readonlybox.sock"

/* Environment variable names */
#define ROBO_ENV_SOCKET     "READONLYBOX_SOCKET"
#define ROBO_ENV_CALLER     "READONLYBOX_CALLER"
#define ROBO_ENV_SYSCALL    "READONLYBOX_SYSCALL"
#define ROBO_ENV_CWD        "READONLYBOX_CWD"

#endif /* READONLYBOX_PTRACE_PROTOCOL_H */
