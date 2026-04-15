/*
 * error_messages.h - Static error message strings
 *
 * All error messages are static string literals - no memory allocation needed.
 * Users must NOT free these strings.
 */

#ifndef RBOX_ERROR_MESSAGES_H
#define RBOX_ERROR_MESSAGES_H

/* Connection errors */
#define RBOX_MSG_CONN_REFUSED       "Connection refused"
#define RBOX_MSG_CONN_TIMEOUT      "Connection timed out"
#define RBOX_MSG_CONN_FAILED        "Connection failed"
#define RBOX_MSG_CONN_CLOSED       "Connection closed"

/* I/O errors */
#define RBOX_MSG_READ_FAILED       "Read failed"
#define RBOX_MSG_WRITE_FAILED      "Write failed"
#define RBOX_MSG_PEER_CLOSED       "Peer closed connection"
#define RBOX_MSG_WOULD_BLOCK       "Operation would block"
#define RBOX_MSG_TIMEOUT           "Operation timed out"

/* Packet validation errors */
#define RBOX_MSG_HEADER_INVALID     "Invalid packet header"
#define RBOX_MSG_MAGIC_INVALID     "Invalid magic number"
#define RBOX_MSG_VERSION_INVALID   "Unsupported protocol version"
#define RBOX_MSG_CHECKSUM_MISMATCH "Checksum mismatch"
#define RBOX_MSG_TRUNCATED         "Truncated data"
#define RBOX_MSG_INVALID_PARAM     "Invalid parameter"
#define RBOX_MSG_ID_MISMATCH       "Request/response ID mismatch"

/* Memory errors */
#define RBOX_MSG_MEMORY             "Memory allocation failed"
#define RBOX_MSG_ALLOC_FAILED      "Allocation failed"

/* State errors */
#define RBOX_MSG_NOT_CONNECTED     "Not connected"
#define RBOX_MSG_ALREADY_CONN     "Already connected"
#define RBOX_MSG_STATE_ERROR       "Invalid state"
#define RBOX_MSG_BUSY             "Resource busy"

/* Server errors */
#define RBOX_MSG_SERVER_ERROR      "Server error"
#define RBOX_MSG_SERVER_FULL       "Server full"
#define RBOX_MSG_BAD_RESPONSE      "Malformed response"

/* General */
#define RBOX_MSG_UNKNOWN           "Unknown error"
#define RBOX_MSG_SUCCESS           "Success"

#endif /* RBOX_ERROR_MESSAGES_H */
