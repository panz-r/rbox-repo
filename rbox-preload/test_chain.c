#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include "dfa.h"

extern const unsigned char mini_data[];
extern const size_t mini_size;

static const dfa_header_t* g_header = NULL;
static const dfa_state_t* g_states = NULL;
static size_t g_trans_start = 0;
static const uint8_t* g_alpha_map = NULL;

static int char_to_symbol(unsigned char c) {
    if (g_alpha_map != NULL && c < 256) {
        return g_alpha_map[c];
    }
    return -1;
}

static int init_dfa() {
    if (mini_size < sizeof(dfa_header_t)) {
        fprintf(stderr, "DFA too small\n");
        return 0;
    }
    g_header = (dfa_header_t*)mini_data;
    if (g_header->magic != DFA_MAGIC) {
        fprintf(stderr, "Invalid DFA magic\n");
        return 0;
    }
    
    g_states = (dfa_state_t*)(mini_data + g_header->initial_state);
    g_alpha_map = (uint8_t*)(mini_data + sizeof(dfa_header_t));
    g_trans_start = g_header->initial_state + g_header->state_count * 8;
    
    return 1;
}

static int evaluate(const char* input, int debug) {
    if (!g_header) return 0;
    
    const dfa_state_t* state = g_states;
    size_t len = strlen(input);
    
    if (debug) printf("EVAL: '%s'\n", input);
    
    for (size_t pos = 0; pos < len; pos++) {
        unsigned char c = (unsigned char)input[pos];
        int symbol = char_to_symbol(c);
        
        if (debug) printf("  [%zu] '%c'(0x%02x) -> symbol=%d, trans_count=%d\n",
               pos, c >= 32 ? c : '?', c, symbol, state->transition_count);
        
        if (symbol < 0) {
            if (debug) printf("    Unknown symbol, REJECT\n");
            return 0;
        }
        
        if (state->transition_count == 0) {
            if (debug) printf("    No transitions, REJECT\n");
            return 0;
        }
        
        int found = 0;
        for (int i = 0; i < state->transition_count; i++) {
            uint8_t trans_char = mini_data[g_trans_start + state->transitions_offset + i * 5];
            uint32_t next = *(uint32_t*)&mini_data[g_trans_start + state->transitions_offset + i * 5 + 1];
            if (debug) printf("    trans[%d]: trans_char=%d (0x%02x), symbol=%d (0x%02x), next=%d, match=%d\n", 
                   i, trans_char, trans_char, symbol, symbol, next, trans_char == symbol);
            if (trans_char == symbol) {
                state = (dfa_state_t*)(mini_data + next);
                found = 1;
                if (debug) printf("    -> MATCH, new state at offset %d\n", next);
                break;
            }
        }
        
        if (!found) {
            if (debug) printf("    No matching transition, REJECT\n");
            return 0;
        }
    }
    
    int accepting = (state->flags & DFA_STATE_ACCEPTING) ? 1 : 0;
    if (debug) printf("  Final: accepting=%d -> %s\n\n", accepting, accepting ? "ACCEPT" : "REJECT");
    return accepting;
}

int main() {
    printf("=== DFA Chain Test ===\n\n");
    
    if (!init_dfa()) {
        fprintf(stderr, "DFA init failed\n");
        return 1;
    }
    
    printf("DFA: %d states, alphabet_size=%d, transitions_start=%zu\n\n",
           g_header->state_count, g_header->alphabet_size, g_trans_start);
    
    // Show alphabet mapping for some key characters
    printf("Alphabet mappings:\n");
    printf("  'g' -> %d, 'i' -> %d, ' ' -> %d\n", 
           g_alpha_map[0x67], g_alpha_map[0x69], g_alpha_map[0x20]);
    printf("  'l' -> %d, 's' -> %d, 'p' -> %d\n",
           g_alpha_map[0x6c], g_alpha_map[0x73], g_alpha_map[0x70]);
    printf("  'd' -> %d, 'H' -> %d, 'E' -> %d, 'A' -> %d\n\n",
           g_alpha_map[0x64], g_alpha_map[0x48], g_alpha_map[0x45], g_alpha_map[0x41]);
    
    // Test cases - SHOULD ACCEPT (40 tests)
    printf("=== Should ACCEPT (40 tests) ===\n");
    const char* accept_tests[] = {
        // Basic patterns (4)
        "git log",
        "git status",
        "ls",
        "pwd",

        // Normalizing whitespace variations (6)
        "git diff HEAD",
        "git diff  HEAD",       // double space
        "git diff\tHEAD",       // tab
        "git diff\t HEAD",      // tab then space
        "git diff \tHEAD",      // space then tab
        "git diff \t \t  HEAD", // mixed multiple

        // Long options with -- (5)
        "git log --oneline",
        "git diff --cached HEAD",
        "git log --oneline\t--graph",  // multiple --options with whitespace
        "git diff --stat\t--no-color HEAD",  // multiple --options
        "git status --short -b",  // mixed -- and - options

        // Short options with - (7)
        "git status -s",
        "ls -la",
        "pwd -L",
        "wc -l file.txt",
        "head -n 10 file.txt",
        "tail -f /var/log/syslog",

        // Quoted strings (2)
        "echo \"hello world\"",
        "tar -cvf archive.tar /path",

        // Wildcard patterns (1)
        "ps aux",

        // NEW: Complex git commands (8)
        "git remote -v",
        "git log --all --oneline --graph --decorate",
        "git diff --stat --numstat HEAD~5..HEAD",
        "git show --stat --pretty=format:%h HEAD",
        "git stash list",
        "git tag -l v*",
        "git branch -a",
        "git remote get-url origin",

        // NEW: Complex file operations (4)
        "ls -lahR /var/log",
        "cat /etc/hostname",
        "head -c 100 /dev/urandom | xxd",
        "tail -n +0 -F /var/log/syslog",

        // NEW: Safe pipelines and redirections (4)
        "ls -la | head -20",
        "cat /etc/os-release | grep PRETTY_NAME",
        "wc -l /etc/passwd /etc/hosts /etc/group",
        "tail -f /var/log/*.log 2>/dev/null",

        // NEW: Git with options (2)
        "git log --since=2024-01-01",
        "git log --until=2024-12-31",
        "git diff --word-diff=color HEAD~1",

        // NEW: Simple patterns with spaces (2)
        "echo test",
        "echo test 123",
    };
    int num_accept = sizeof(accept_tests) / sizeof(accept_tests[0]);

    for (int i = 0; i < num_accept; i++) {
        int result = evaluate(accept_tests[i], 0);
        const char* status = result ? "PASS" : "FAIL";
        printf("[%s] '%s'\n", status, accept_tests[i]);
        if (!result) evaluate(accept_tests[i], 1);  // Debug on failure
    }

    // Test cases - SHOULD REJECT (77 tests)
    printf("\n=== Should REJECT (77 tests) ===\n");
    const char* reject_tests[] = {
        // Too short / incomplete (10)
        "git",
        "g",
        "gi",
        "git ",          // incomplete
        "ls ",           // incomplete
        "pwd ",          // incomplete
        "git dif",       // incomplete
        "git diff",      // missing HEAD
        "git diff ",     // incomplete
        "head -n",       // missing argument

        // Wrong suffix (10)
        "git logg",
        "git loggg",
        "gitlog",
        "git logx",
        "git logs",
        "git logs ",
        "git statusx",
        "lsx",
        "pwdx",
        "tail -f",       // missing path

        // Wrong case (3)
        "GIT LOG",
        "Git Log",
        "git LOG",

        // Missing/extra elements (15)
        "git diff HEADx",       // extra char after HEAD
        "git diff head",        // lowercase HEAD
        "git diffHEAD",         // no space
        "git diff HEAD extra",  // extra argument
        "git status -sx",       // wrong option
        "ls -lx",               // wrong option
        "pwd -P",               // wrong option
        "head -n 10",           // missing file
        "tail -f /var/log",     // missing extension
        "echo hello world",     // unquoted, wrong
        "echo \"hello\" world", // extra after quoted
        "ps auxx",              // extra suffix
        "tar -cvf",             // missing arguments
        "kill -9",              // missing PID
        "chmod 644",            // missing file

        // Wrong first character (5)
        "xgit log",
        "agit log",
        "ggit log",
        "lsx",
        "pwdy",

        // Wrong internal elements (10)
        "git log --onelinex",   // wrong option suffix
        "git diff --cach HEAD", // typo in option
        "git status -ss",       // duplicate option
        "ls -a -a",             // duplicate short option
        "pwd -L -L",            // duplicate option
        "head -nn 10 file.txt", // wrong option format
        "tail -f -f /var/log",  // duplicate -f
        "wc -l -l file.txt",    // duplicate -l
        "grep -r pattern /path", // wrong option order
        "find . -namename \"*.go\"", // typo in option

        // Empty and whitespace (4)
        "",                     // empty string
        "   ",                  // only whitespace
        "\t",                   // only tab
        "  \t  ",               // mixed whitespace only

        // NEW: Complex negative tests - wrong git subcommands (10)
        "git push origin main",     // push is dangerous
        "git commit -m \"msg\"",    // commit is dangerous
        "git checkout -b branch",   // checkout is dangerous
        "git merge feature",        // merge is dangerous
        "git reset --hard HEAD",    // reset is dangerous
        "git rebase main",          // rebase is dangerous
        "git cherry-pick abc123",   // cherry-pick is dangerous
        "git revert HEAD",          // revert is dangerous
        "git tag -a v1.0 -m msg",   // tag create is dangerous
        "git fetch --all",          // fetch can be dangerous

        // NEW: Complex negative tests - wrong options/arguments (10)
        "git remote add origin url",    // modify remotes
        "git remote remove origin",     // modify remotes
        "git remote set-url origin url", // modify remotes
        "git config --global user.name", // modify config
        "git config --unset user.email", // modify config
        "git clean -fd",                // clean is dangerous
        "git stash push -m \"msg\"",    // stash create
        "ls -la /etc/shadow",           // access shadow file
        "cat /etc/shadow",              // access shadow file
        "tail -f /etc/shadow",          // access shadow file

        // NEW: Complex negative tests - shell injection patterns (10)
        "git log; rm -rf /",            // semicolon injection
        "git log && rm -rf /",          // AND injection
        "git log || echo pwned",        // OR injection
        "git log `whoami`",             // command substitution
        "git log $(whoami)",            // command substitution
        "git log | cat",                // pipe to read command
        "echo hello > /etc/passwd",     // write to passwd
        "ls -la > /dev/null",           // redirect to null
        "head -n 1 /etc/passwd | cat",  // read passwd
        "tail -f /var/log/../etc/shadow", // path traversal
    };
    int num_reject = sizeof(reject_tests) / sizeof(reject_tests[0]);

    for (int i = 0; i < num_reject; i++) {
        int result = evaluate(reject_tests[i], 0);
        const char* status = result ? "FAIL" : "PASS";
        printf("[%s] '%s'\n", status, reject_tests[i]);
        if (result) evaluate(reject_tests[i], 1);  // Debug on unexpected accept
    }

    printf("\n=== Test Complete ===\n");
    return 0;
}
