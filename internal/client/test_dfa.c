#include <stdio.h>
#include <string.h>
#include "dfa.h"

int main(void) {
    printf("DFA Validation Tests\n");
    printf("=====================\n\n");

    struct {
        const char* cmd;
        int should_match;
        const char* reason;
    } tests[] = {
        // ========================================
        // POSITIVE TESTS: Should match safe patterns
        // ========================================
        {"git log", 1, "exact match: git log"},
        {"git log --oneline", 1, "exact match: git log --oneline"},
        {"git log --graph", 1, "exact match: git log --graph"},
        {"git log --oneline --decorate", 1, "exact match: git log --oneline --decorate"},
        {"git status", 1, "exact match: git status"},
        {"git show", 1, "exact match: git show"},
        {"git diff", 1, "exact match: git diff"},
        {"git diff HEAD", 1, "exact match: git diff HEAD"},
        {"git blame file.txt", 1, "exact match: git blame file.txt"},
        {"git grep pattern", 1, "exact match: git grep pattern"},
        {"git ls-files", 1, "exact match: git ls-files"},
        {"git tag", 1, "exact match: git tag"},
        {"git tag -l", 1, "exact match: git tag -l"},
        {"git branch", 1, "exact match: git branch"},
        {"git branch -a", 1, "exact match: git branch -a"},
        {"git remote -v", 1, "exact match: git remote -v"},
        {"git config --list", 1, "exact match: git config --list"},
        {"git rev-parse HEAD", 1, "exact match: git rev-parse HEAD"},
        {"git rev-parse --short abc123", 1, "exact match: git rev-parse --short with hash"},
        {"cat file.txt", 1, "exact match: cat file.txt"},
        {"head -n 10 file", 1, "exact match: head -n 10 file"},
        {"tail -f log", 1, "exact match: tail -f log"},
        {"wc -l file", 1, "exact match: wc -l file"},
        {"grep pattern file", 1, "exact match: grep pattern file"},
        {"ls", 1, "exact match: ls"},
        {"ls -la", 1, "exact match: ls -la"},
        {"pwd", 1, "exact match: pwd"},
        {"ps aux", 1, "exact match: ps aux"},
        {"df -h", 1, "exact match: df -h"},
        {"du -sh .", 1, "exact match: du -sh ."},
        {"uname -a", 1, "exact match: uname -a"},
        {"whoami", 1, "exact match: whoami"},
        {"date", 1, "exact match: date"},
        {"uptime", 1, "exact match: uptime"},
        {"echo hello", 1, "exact match: echo hello"},
        {"echo $PATH", 1, "exact match: echo with variable"},
        {"find . -name *.txt", 1, "exact match: find . -name *.txt"},
        {"find . -type f", 1, "exact match: find . -type f"},
        {"sort file.txt", 1, "exact match: sort file.txt"},
        {"cut -d',' -f1 file.csv", 1, "exact match: cut with options"},
        {"basename /path/file", 1, "exact match: basename"},
        {"dirname /path/file", 1, "exact match: dirname"},
        {"stat file.txt", 1, "exact match: stat file.txt"},
        {"file file.txt", 1, "exact match: file file.txt"},
        {"env", 1, "exact match: env"},
        {"printenv", 1, "exact match: printenv"},
        {"id", 1, "exact match: id"},
        {"hostname", 1, "exact match: hostname"},
        {"free", 1, "exact match: free"},
        {"tr 'a-z' 'A-Z'", 1, "exact match: tr"},
        {"cat file.txt | grep pattern", 1, "exact match: cat pipe grep"},
        {"cat file.txt | head -10", 1, "exact match: cat pipe head"},
        {"git log --oneline | head -10", 1, "exact match: git log pipe head"},
        {"ps aux | grep process", 1, "exact match: ps pipe grep"},

        // ========================================
        // NEGATIVE TESTS: Should NOT match any safe pattern
        // ========================================
        {"git checkout", 0, "no matching pattern for git checkout"},
        {"git checkout -b", 0, "no matching pattern for git checkout -b"},
        {"git commit", 0, "no matching pattern for git commit"},
        {"git commit -m", 0, "no matching pattern for git commit -m"},
        {"git push", 0, "no matching pattern for git push"},
        {"git push origin", 0, "no matching pattern for git push origin"},
        {"git pull", 0, "no matching pattern for git pull"},
        {"git add", 0, "no matching pattern for git add"},
        {"git add .", 0, "no matching pattern for git add ."},
        {"git reset", 0, "no matching pattern for git reset"},
        {"git reset --hard", 0, "no matching pattern for git reset --hard"},
        {"git merge", 0, "no matching pattern for git merge"},
        {"git rebase", 0, "no matching pattern for git rebase"},
        {"git stash", 0, "no matching pattern for git stash"},
        {"git clean", 0, "no matching pattern for git clean"},
        {"git rm", 0, "no matching pattern for git rm"},
        {"rm", 0, "no matching pattern for bare rm"},
        {"rm file.txt", 0, "no matching pattern for rm file.txt"},
        {"rm -rf", 0, "no matching pattern for rm -rf"},
        {"rm -r", 0, "no matching pattern for rm -r"},
        {"mv", 0, "no matching pattern for bare mv"},
        {"mv file1 file2", 0, "no matching pattern for mv file1 file2"},
        {"cp", 0, "no matching pattern for bare cp"},
        {"cp file1 file2", 0, "no matching pattern for cp file1 file2"},
        {"mkdir", 0, "no matching pattern for bare mkdir"},
        {"mkdir newdir", 0, "no matching pattern for mkdir newdir"},
        {"touch", 0, "no matching pattern for bare touch"},
        {"touch newfile", 0, "no matching pattern for touch newfile"},
        {"chmod", 0, "no matching pattern for chmod"},
        {"chmod 755 file", 0, "no matching pattern for chmod 755 file"},
        {"chown", 0, "no matching pattern for chown"},
        {"chown user file", 0, "no matching pattern for chown user file"},
        {"curl", 0, "no matching pattern for curl"},
        {"wget", 0, "no matching pattern for wget"},
        {"ssh", 0, "no matching pattern for ssh"},
        {"sudo", 0, "no matching pattern for sudo"},
        {"eval", 0, "no matching pattern for eval"},
        {"eval echo hello", 0, "no matching pattern for eval echo hello"},
        {"bash -c", 0, "no matching pattern for bash -c"},
        {"sh -c", 0, "no matching pattern for sh -c"},
        {"shopt", 0, "no matching pattern for shopt"},
        {"shopt -s extglob", 0, "no matching pattern for shopt -s extglob"},
        {"tar -cf", 0, "no matching pattern for tar -cf"},
        {"gzip", 0, "no matching pattern for gzip (no -l)"},
        {"unknown_command", 0, "no matching pattern for unknown_command"},
        {"custom_tool args", 0, "no matching pattern for custom_tool"},
        {"some_random_cmd with args", 0, "no matching pattern"},
        {"echo > file.txt", 0, "no matching pattern for echo with redirect"},
        {"cat < input.txt", 0, "no matching pattern for cat with input redirect"},
        {"git log --oneline > output.txt", 0, "no matching pattern with redirect"},
        {"cat >> file.txt", 0, "no matching pattern for append redirect"},
    };

    int pos_passed = 0, pos_failed = 0;
    int neg_passed = 0, neg_failed = 0;

    printf("POSITIVE TESTS (should match patterns):\n");
    printf("---------------------------------------\n");
    for (int i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
        if (tests[i].should_match) {
            int result = dfa_should_allow(tests[i].cmd);
            if (result == 1) {
                printf("[PASS] %s\n", tests[i].cmd);
                pos_passed++;
            } else {
                printf("[FAIL] '%s' -> %s (expected: ALLOW)\n       %s\n",
                       tests[i].cmd, result ? "ALLOW" : "SEND TO SERVER", tests[i].reason);
                pos_failed++;
            }
        }
    }

    printf("\nNEGATIVE TESTS (should NOT match patterns):\n");
    printf("---------------------------------------------\n");
    for (int i = 0; i < (int)(sizeof(tests) / sizeof(tests[0])); i++) {
        if (!tests[i].should_match) {
            int result = dfa_should_allow(tests[i].cmd);
            if (result == 0) {
                printf("[PASS] %s\n", tests[i].cmd);
                neg_passed++;
            } else {
                printf("[FAIL] '%s' -> %s (expected: SEND TO SERVER)\n       %s\n",
                       tests[i].cmd, result ? "ALLOW" : "SEND TO SERVER", tests[i].reason);
                neg_failed++;
            }
        }
    }

    printf("\n=====================\n");
    printf("RESULTS:\n");
    printf("  Positive: %d passed, %d failed\n", pos_passed, pos_failed);
    printf("  Negative: %d passed, %d failed\n", neg_passed, neg_failed);
    printf("  Total:    %d passed, %d failed\n",
           pos_passed + neg_passed, pos_failed + neg_failed);

    if (pos_failed == 0 && neg_failed == 0) {
        printf("\nALL TESTS PASSED - DFA is ready for use!\n");
        return 0;
    } else {
        printf("\nSOME TESTS FAILED - DFA needs fixes before use!\n");
        return 1;
    }
}
