#ifndef READONLYBOX_DFA_H
#define READONLYBOX_DFA_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#if defined(__GNUC__) || defined(__clang__)
#define DFA_PACKED __attribute__((packed))
#else
#define DFA_PACKED
#endif

#define DFA_MAGIC     0xDFA1DFA1
#define DFA_VERSION   1
#define DFA_CHAR_ANY  0x00

typedef enum {
    DFA_CMD_UNKNOWN = 0,
    DFA_CMD_READONLY_SAFE,
    DFA_CMD_READONLY_CAUTION,
    DFA_CMD_MODIFYING,
    DFA_CMD_DANGEROUS,
    DFA_CMD_NETWORK,
    DFA_CMD_ADMIN,
} dfa_command_category_t;

typedef struct {
    uint32_t transitions_offset;
    uint16_t transition_count;
    uint16_t flags;
} dfa_state_t;

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t state_count;
    uint32_t initial_state;
    uint32_t accepting_mask;
} dfa_header_t;

typedef struct DFA_PACKED {
    uint8_t character;
    uint32_t next_state_offset;
} dfa_transition_t;

typedef struct {
    dfa_command_category_t category;
    uint32_t final_state;
    bool matched;
    size_t matched_length;
} dfa_result_t;

extern const unsigned char readonlybox_dfa_data[];
extern const size_t readonlybox_dfa_size;

bool dfa_init(void);
bool dfa_evaluate(const char* input, size_t length, dfa_result_t* result);
int dfa_should_allow(const char* cmd);

#endif
