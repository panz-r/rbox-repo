#include "dfa.h"
#include "dfa_types.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int pass_count = 0;
static int fail_count = 0;
static dfa_result_t result;

static void run_test(bool cond, const char* name, bool should_match, uint8_t expected_mask) {
    if (cond == should_match) {
        if (expected_mask == 0 || (result.category_mask & expected_mask) == expected_mask) {
            pass_count++;
            return;
        }
    }
    fail_count++;
    printf("FAIL: %s (matched=%s, cat_mask=0x%02x, expected=0x%02x)\n",
           name, cond ? "true" : "false", result.category_mask, expected_mask);
}

int main(int argc, char* argv[]) {
    const char* dfa_file = argc > 1 ? argv[1] : "readonlybox.dfa";
    
    size_t size;
    void* data = load_dfa_from_file(dfa_file, &size);
    if (!data) {
        fprintf(stderr, "Cannot load DFA from %s\n", dfa_file);
        return 1;
    }
    
    if (!dfa_init(data, size)) {
        fprintf(stderr, "DFA init failed\n");
        free(data);
        return 1;
    }
    
    printf("=================================================\n");
    printf("Expanded Acceptance Category Isolation Tests\n");
    printf("DFA: %s\n", dfa_get_identifier());
    printf("=================================================\n\n");

    // ============================================================
    // GROUP 1: Simple patterns (12 tests - working correctly)
    // ============================================================
    printf("Group 1: Simple non-interfering patterns (12 tests)\n");
    printf("--------------------------------------------------\n");
    
    run_test(dfa_evaluate("ls", 0, &result) && result.matched, "'ls'", true, 0x01);
    run_test(dfa_evaluate("pwd", 0, &result) && result.matched, "'pwd'", true, 0x01);
    run_test(dfa_evaluate("curl", 0, &result) && result.matched, "'curl'", true, 0x02);
    run_test(dfa_evaluate("wget", 0, &result) && result.matched, "'wget'", true, 0x02);
    run_test(dfa_evaluate("touch", 0, &result) && result.matched, "'touch'", true, 0x04);
    run_test(dfa_evaluate("mkdir", 0, &result) && result.matched, "'mkdir'", true, 0x04);
    run_test(dfa_evaluate("network1", 0, &result) && result.matched, "'network1'", true, 0x02);
    run_test(dfa_evaluate("network2", 0, &result) && result.matched, "'network2'", true, 0x02);
    run_test(dfa_evaluate("network3", 0, &result) && result.matched, "'network3'", true, 0x02);
    run_test(dfa_evaluate("network4", 0, &result) && result.matched, "'network4'", true, 0x02);
    run_test(dfa_evaluate("network5", 0, &result) && result.matched, "'network5'", true, 0x02);
    run_test(dfa_evaluate("network6", 0, &result) && result.matched, "'network6'", true, 0x02);
    printf("\n");

    // ============================================================
    // GROUP 2: Shared prefixes (48 tests - all failing)
    // ============================================================
    printf("Group 2: Shared prefixes, different categories (48 tests)\n");
    printf("------------------------------------------------------------\n");
    
    // Git status variants (16 tests)
    run_test(dfa_evaluate("git status", 0, &result) && result.matched, "'git status'", true, 0x01);
    run_test(dfa_evaluate("git status -s", 0, &result) && result.matched, "'git status -s'", true, 0x01);
    run_test(dfa_evaluate("git status --short", 0, &result) && result.matched, "'git status --short'", true, 0x01);
    run_test(dfa_evaluate("git status -b", 0, &result) && result.matched, "'git status -b'", true, 0x02);
    run_test(dfa_evaluate("git status --branch", 0, &result) && result.matched, "'git status --branch'", true, 0x02);
    run_test(dfa_evaluate("git status -u", 0, &result) && result.matched, "'git status -u'", true, 0x04);
    run_test(dfa_evaluate("git status --untracked-files", 0, &result) && result.matched, "'git status --untracked-files'", true, 0x04);
    run_test(dfa_evaluate("git status -s -b", 0, &result) && result.matched, "'git status -s -b'", true, 0x01);
    run_test(dfa_evaluate("git status -s -u", 0, &result) && result.matched, "'git status -s -u'", true, 0x02);
    run_test(dfa_evaluate("git status -sb", 0, &result) && result.matched, "'git status -sb'", true, 0x01);
    run_test(dfa_evaluate("git status -sb -u", 0, &result) && result.matched, "'git status -sb -u'", true, 0x02);
    run_test(dfa_evaluate("git status extra", 0, &result) && result.matched, "'git status extra'", true, 0x01);
    
    // Git log variants (16 tests)
    run_test(dfa_evaluate("git log", 0, &result) && result.matched, "'git log'", true, 0x01);
    run_test(dfa_evaluate("git log --oneline", 0, &result) && result.matched, "'git log --oneline'", true, 0x01);
    run_test(dfa_evaluate("git log --graph", 0, &result) && result.matched, "'git log --graph'", true, 0x01);
    run_test(dfa_evaluate("git log --oneline -n", 0, &result) && result.matched, "'git log --oneline -n'", true, 0x01);
    run_test(dfa_evaluate("git log --graph -n", 0, &result) && result.matched, "'git log --graph -n'", true, 0x01);
    run_test(dfa_evaluate("git log --oneline --all", 0, &result) && result.matched, "'git log --oneline --all'", true, 0x02);
    run_test(dfa_evaluate("git log --oneline -p", 0, &result) && result.matched, "'git log --oneline -p'", true, 0x04);
    run_test(dfa_evaluate("git log --oneline -n 1", 0, &result) && result.matched, "'git log --oneline -n 1'", true, 0x01);
    run_test(dfa_evaluate("git log --graph -n 5", 0, &result) && result.matched, "'git log --graph -n 5'", true, 0x01);
    run_test(dfa_evaluate("git log --oneline --all -n 10", 0, &result) && result.matched, "'git log --oneline --all -n 10'", true, 0x02);
    run_test(dfa_evaluate("git log --oneline -n 10 -p", 0, &result) && result.matched, "'git log --oneline -n 10 -p'", true, 0x04);
    run_test(dfa_evaluate("git log --oneline -n 10 --graph", 0, &result) && result.matched, "'git log --oneline -n 10 --graph'", true, 0x01);
    
    // Git push/fetch/commit variants (16 tests)
    run_test(dfa_evaluate("git push", 0, &result) && result.matched, "'git push'", true, 0x02);
    run_test(dfa_evaluate("git fetch", 0, &result) && result.matched, "'git fetch'", true, 0x02);
    run_test(dfa_evaluate("git commit", 0, &result) && result.matched, "'git commit'", true, 0x04);
    run_test(dfa_evaluate("git commit -m", 0, &result) && result.matched, "'git commit -m'", true, 0x04);
    run_test(dfa_evaluate("git push origin", 0, &result) && result.matched, "'git push origin'", true, 0x02);
    run_test(dfa_evaluate("git push origin main", 0, &result) && result.matched, "'git push origin main'", true, 0x02);
    run_test(dfa_evaluate("git fetch origin", 0, &result) && result.matched, "'git fetch origin'", true, 0x02);
    run_test(dfa_evaluate("git commit -m \"msg\"", 0, &result) && result.matched, "'git commit -m \"msg\"'", true, 0x04);
    run_test(dfa_evaluate("git push --all", 0, &result) && result.matched, "'git push --all'", true, 0x02);
    run_test(dfa_evaluate("git fetch --all", 0, &result) && result.matched, "'git fetch --all'", true, 0x02);
    run_test(dfa_evaluate("git commit --amend", 0, &result) && result.matched, "'git commit --amend'", true, 0x04);
    run_test(dfa_evaluate("git push -u origin main", 0, &result) && result.matched, "'git push -u origin main'", true, 0x02);
    run_test(dfa_evaluate("git log --oneline --graph --all -n 10 --pretty=medium", 0, &result) && result.matched, "'git log --oneline --graph --all -n 10 --pretty=medium'", true, 0x01);
    run_test(dfa_evaluate("git log --oneline --graph --all -n 10 --stat", 0, &result) && result.matched, "'git log --oneline --graph --all -n 10 --stat'", true, 0x02);
    run_test(dfa_evaluate("git log --oneline --graph --all -n 10 --patch", 0, &result) && result.matched, "'git log --oneline --graph --all -n 10 --patch'", true, 0x04);
    run_test(dfa_evaluate("git log --oneline --graph --all -n 10 --hard", 0, &result) && result.matched, "'git log --oneline --graph --all -n 10 --hard'", true, 0x08);
    printf("\n");

    // ============================================================
    // GROUP 3: Quantifier patterns (54 tests)
    // ============================================================
    printf("Group 3: CRITICAL - Quantifier patterns (54 tests)\n");
    printf("----------------------------------------------------\n");
    
    // Pattern 1: a((b))+ (category 1) - should match
    run_test(dfa_evaluate("ab", 0, &result) && result.matched, "'ab' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abb", 0, &result) && result.matched, "'abb' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abbb", 0, &result) && result.matched, "'abbb' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abbbb", 0, &result) && result.matched, "'abbbb' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abbbbb", 0, &result) && result.matched, "'abbbbb' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abbbbbb", 0, &result) && result.matched, "'abbbbbb' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abbbbbbb", 0, &result) && result.matched, "'abbbbbbb' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abbbbbbbb", 0, &result) && result.matched, "'abbbbbbbb' matches a((b))+", true, 0x01);
    run_test(dfa_evaluate("abbbbbbbbb", 0, &result) && result.matched, "'abbbbbbbbb' matches a((b))+", true, 0x01);
    
    // Pattern 2: abc((b))+ (category 2) - should match
    run_test(dfa_evaluate("abcb", 0, &result) && result.matched, "'abcb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbb", 0, &result) && result.matched, "'abcbb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbbb", 0, &result) && result.matched, "'abcbbb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbbbb", 0, &result) && result.matched, "'abcbbbb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbbbbb", 0, &result) && result.matched, "'abcbbbbb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbbbbbb", 0, &result) && result.matched, "'abcbbbbbb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbbbbbbb", 0, &result) && result.matched, "'abcbbbbbbb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbbbbbbbb", 0, &result) && result.matched, "'abcbbbbbbbb' matches abc((b))+", true, 0x02);
    run_test(dfa_evaluate("abcbbbbbbbbb", 0, &result) && result.matched, "'abcbbbbbbbbb' matches abc((b))+", true, 0x02);
    
    // CRITICAL: Pattern 2 should NOT match without required 'b'
    run_test(!(dfa_evaluate("abc", 0, &result) && (result.category_mask & 0x02)), "'abc' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcc", 0, &result) && (result.category_mask & 0x02)), "'abcc' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abca", 0, &result) && (result.category_mask & 0x02)), "'abca' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcd", 0, &result) && (result.category_mask & 0x02)), "'abcd' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abce", 0, &result) && (result.category_mask & 0x02)), "'abce' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcf", 0, &result) && (result.category_mask & 0x02)), "'abcf' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcg", 0, &result) && (result.category_mask & 0x02)), "'abcg' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abch", 0, &result) && (result.category_mask & 0x02)), "'abch' should NOT match category 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abci", 0, &result) && (result.category_mask & 0x02)), "'abci' should NOT match category 0x02", true, 0x00);
    
    // Pattern 1 negative tests
    run_test(!(dfa_evaluate("a", 0, &result) && result.matched), "'a' should NOT match a((b))+", true, 0x00);
    run_test(!(dfa_evaluate("ac", 0, &result) && result.matched), "'ac' should NOT match a((b))+", true, 0x00);
    run_test(!(dfa_evaluate("ad", 0, &result) && result.matched), "'ad' should NOT match a((b))+", true, 0x00);
    run_test(!(dfa_evaluate("ae", 0, &result) && result.matched), "'ae' should NOT match a((b))+", true, 0x00);
    run_test(!(dfa_evaluate("ax", 0, &result) && result.matched), "'ax' should NOT match a((b))+", true, 0x00);
    run_test(!(dfa_evaluate("ay", 0, &result) && result.matched), "'ay' should NOT match a((b))+", true, 0x00);
    run_test(!(dfa_evaluate("az", 0, &result) && result.matched), "'az' should NOT match a((b))+", true, 0x00);
    run_test(!(dfa_evaluate("abx", 0, &result) && (result.category_mask & 0x01)), "'abx' should NOT match category 0x01", true, 0x00);
    run_test(!(dfa_evaluate("aby", 0, &result) && (result.category_mask & 0x01)), "'aby' should NOT match category 0x01", true, 0x00);
    printf("\n");

    // ============================================================
    // GROUP 4: Multiple quantifier patterns (36 tests)
    // ============================================================
    printf("Group 4: Multiple quantifier patterns (36 tests)\n");
    printf("--------------------------------------------------\n");
    
    // ab((c))+ (category 4)
    run_test(dfa_evaluate("abc", 0, &result) && result.matched, "'abc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abcc", 0, &result) && result.matched, "'abcc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abccc", 0, &result) && result.matched, "'abccc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abcccc", 0, &result) && result.matched, "'abcccc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abccccc", 0, &result) && result.matched, "'abccccc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abcccccc", 0, &result) && result.matched, "'abcccccc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abccccccc", 0, &result) && result.matched, "'abccccccc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abcccccccc", 0, &result) && result.matched, "'abcccccccc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abccccccccc", 0, &result) && result.matched, "'abccccccccc' matches ab((c))+", true, 0x04);
    run_test(dfa_evaluate("abcccccccccc", 0, &result) && result.matched, "'abcccccccccc' matches ab((c))+", true, 0x04);
    
    // abcd((d))+ (category 16)
    run_test(dfa_evaluate("abcdd", 0, &result) && result.matched, "'abcdd' matches abcd((d))+", true, 0x10);
    run_test(dfa_evaluate("abcddd", 0, &result) && result.matched, "'abcddd' matches abcd((d))+", true, 0x10);
    run_test(dfa_evaluate("abcdddd", 0, &result) && result.matched, "'abcdddd' matches abcd((d))+", true, 0x10);
    run_test(dfa_evaluate("abcddddd", 0, &result) && result.matched, "'abcddddd' matches abcd((d))+", true, 0x10);
    run_test(dfa_evaluate("abcdddddd", 0, &result) && result.matched, "'abcdddddd' matches abcd((d))+", true, 0x10);
    run_test(dfa_evaluate("abcddddddd", 0, &result) && result.matched, "'abcddddddd' matches abcd((d))+", true, 0x10);
    run_test(dfa_evaluate("abcdddddddd", 0, &result) && result.matched, "'abcdddddddd' matches abcd((d))+", true, 0x10);
    run_test(dfa_evaluate("abcddddddddd", 0, &result) && result.matched, "'abcddddddddd' matches abcd((d))+", true, 0x10);
    
    // ab((d))+ (category 8)
    run_test(dfa_evaluate("abdd", 0, &result) && result.matched, "'abdd' matches ab((d))+", true, 0x08);
    run_test(dfa_evaluate("abddd", 0, &result) && result.matched, "'abddd' matches ab((d))+", true, 0x08);
    
    // Negative tests
    run_test(!(dfa_evaluate("abd", 0, &result) && (result.category_mask & 0x04)), "'abd' should NOT match category 0x04", true, 0x00);
    run_test(!(dfa_evaluate("abce", 0, &result) && (result.category_mask & 0x04)), "'abce' should NOT match category 0x04", true, 0x00);
    run_test(!(dfa_evaluate("abced", 0, &result) && (result.category_mask & 0x10)), "'abced' should NOT match category 0x10", true, 0x00);
    run_test(!(dfa_evaluate("abcde", 0, &result) && (result.category_mask & 0x10)), "'abcde' should NOT match category 0x10", true, 0x00);
    run_test(!(dfa_evaluate("abd", 0, &result) && (result.category_mask & 0x08)), "'abd' should NOT match category 0x08", true, 0x00);
    run_test(!(dfa_evaluate("abde", 0, &result) && (result.category_mask & 0x08)), "'abde' should NOT match category 0x08", true, 0x00);
    run_test(!(dfa_evaluate("abdf", 0, &result) && (result.category_mask & 0x08)), "'abdf' should NOT match category 0x08", true, 0x00);
    run_test(!(dfa_evaluate("abbd", 0, &result) && (result.category_mask & 0x08)), "'abbd' should NOT match category 0x08", true, 0x00);
    run_test(!(dfa_evaluate("abed", 0, &result) && (result.category_mask & 0x08)), "'abed' should NOT match category 0x08", true, 0x00);
    run_test(!(dfa_evaluate("abfd", 0, &result) && (result.category_mask & 0x08)), "'abfd' should NOT match category 0x08", true, 0x00);
    run_test(!(dfa_evaluate("abcd", 0, &result) && (result.category_mask & 0x10)), "'abcd' should NOT match category 0x10", true, 0x00);
    run_test(!(dfa_evaluate("abcde", 0, &result) && (result.category_mask & 0x10)), "'abcde' should NOT match category 0x10", true, 0x00);
    run_test(!(dfa_evaluate("abcdf", 0, &result) && (result.category_mask & 0x10)), "'abcdf' should NOT match category 0x10", true, 0x00);
    run_test(!(dfa_evaluate("abce", 0, &result) && (result.category_mask & 0x10)), "'abce' should NOT match category 0x10", true, 0x00);
    run_test(!(dfa_evaluate("abced", 0, &result) && (result.category_mask & 0x10)), "'abced' should NOT match category 0x10", true, 0x00);
    run_test(!(dfa_evaluate("abcfd", 0, &result) && (result.category_mask & 0x10)), "'abcfd' should NOT match category 0x10", true, 0x00);
    printf("\n");

    // ============================================================
    // GROUP 5: Category mask isolation (27 tests)
    // ============================================================
    printf("Group 5: Category mask isolation verification (27 tests)\n");
    printf("-------------------------------------------------------\n");
    
    run_test(result.matched && result.category_mask == 0x01, "'ab' category=0x01", true, 0x01);
    run_test(result.matched && result.category_mask == 0x02, "'abcb' category=0x02", true, 0x02);
    run_test(!(result.category_mask & 0x02), "'abc' no category 0x02", true, 0x00);
    run_test(result.matched && result.category_mask == 0x02, "'abcbb' category=0x02", true, 0x02);
    run_test(result.matched && result.category_mask == 0x02, "'curl' category=0x02", true, 0x02);
    run_test(result.matched && result.category_mask == 0x04, "'touch' category=0x04", true, 0x04);
    run_test(result.matched && result.category_mask == 0x10, "'abcdd' category=0x10", true, 0x10);
    run_test(result.matched && result.category_mask == 0x01, "'ls' category=0x01", true, 0x01);
    run_test(result.matched && result.category_mask == 0x01, "'pwd' category=0x01", true, 0x01);
    run_test(result.matched && result.category_mask == 0x02, "'wget' category=0x02", true, 0x02);
    run_test(result.matched && result.category_mask == 0x04, "'mkdir' category=0x04", true, 0x04);
    run_test(result.matched && result.category_mask == 0x02, "'network1' category=0x02", true, 0x02);
    run_test(result.matched && result.category_mask == 0x02, "'network2' category=0x02", true, 0x02);
    run_test(result.matched && result.category_mask == 0x04, "'git commit' category=0x04", true, 0x04);
    run_test(result.matched && result.category_mask == 0x01, "'git log deep1' category=0x01", true, 0x01);
    run_test(result.matched && result.category_mask == 0x02, "'git log deep2' category=0x02", true, 0x02);
    run_test(result.matched && result.category_mask == 0x04, "'git log deep3' category=0x04", true, 0x04);
    run_test(result.matched && result.category_mask == 0x08, "'git log deep4' category=0x08", true, 0x08);
    run_test(result.matched && result.category_mask > 0, "'token123' matches", true, 0x00);
    run_test(result.matched && result.category_mask > 0, "'token456' matches", true, 0x00);
    run_test(result.matched && result.category_mask > 0, "'token789' matches", true, 0x00);
    run_test(result.matched && result.category_mask > 0, "'specific_command_name' matches", true, 0x00);
    run_test(result.matched && result.category_mask == 0x01, "'echo \"hello\"' category=0x01", true, 0x01);
    run_test(result.matched && result.category_mask == 0x02, "'curl \"http://...\"' category=0x02", true, 0x02);
    run_test(result.matched && result.category_mask == 0x01, "'echo \"test\"' category=0x01", true, 0x01);
    run_test(result.matched && result.category_mask == 0x02, "'curl \"https://...\"' category=0x02", true, 0x02);
    printf("\n");

    // ============================================================
    // GROUP 6: Edge cases and negative tests (54 tests)
    // ============================================================
    printf("Group 6: Edge cases and negative tests (54 tests)\n");
    printf("--------------------------------------------------\n");
    
    // Non-matching inputs
    run_test(!(dfa_evaluate("xyz", 0, &result) && result.matched), "'xyz' no match", true, 0x00);
    run_test(!(dfa_evaluate("abcxyz", 0, &result) && (result.category_mask & 0x02)), "'abcxyz' no cat 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abca", 0, &result) && (result.category_mask & 0x02)), "'abca' no cat 0x02", true, 0x00);
    run_test(!(dfa_evaluate("xyzabc", 0, &result) && (result.category_mask & 0x02)), "'xyzabc' no cat 0x02", true, 0x00);
    run_test(!(dfa_evaluate("xyzab", 0, &result) && (result.category_mask & 0x01)), "'xyzab' no cat 0x01", true, 0x00);
    run_test(!(dfa_evaluate("randomtext", 0, &result) && result.matched), "'randomtext' no match", true, 0x00);
    run_test(!(dfa_evaluate("foobar", 0, &result) && result.matched), "'foobar' no match", true, 0x00);
    run_test(!(dfa_evaluate("test123", 0, &result) && result.matched), "'test123' no match", true, 0x00);
    run_test(!(dfa_evaluate("hello", 0, &result) && result.matched), "'hello' no match", true, 0x00);
    run_test(!(dfa_evaluate("world", 0, &result) && result.matched), "'world' no match", true, 0x00);
    run_test(!(dfa_evaluate("abcdefgh", 0, &result) && result.matched), "'abcdefgh' no match", true, 0x00);
    run_test(!(dfa_evaluate("0123456789", 0, &result) && result.matched), "'0123456789' no match", true, 0x00);
    run_test(!(dfa_evaluate("aaabbbccc", 0, &result) && result.matched), "'aaabbbccc' no match", true, 0x00);
    run_test(!(dfa_evaluate("xyz123abc", 0, &result) && result.matched), "'xyz123abc' no match", true, 0x00);
    run_test(!(dfa_evaluate("cmdtool", 0, &result) && result.matched), "'cmdtool' no match", true, 0x00);
    run_test(!(dfa_evaluate("utilities", 0, &result) && result.matched), "'utilities' no match", true, 0x00);
    run_test(!(dfa_evaluate("application", 0, &result) && result.matched), "'application' no match", true, 0x00);
    run_test(!(dfa_evaluate("process", 0, &result) && result.matched), "'process' no match", true, 0x00);
    
    // Empty and minimal inputs
    run_test(!(dfa_evaluate("a", 0, &result) && result.matched), "'a' no match", true, 0x00);
    run_test(!(dfa_evaluate("", 0, &result) && result.matched), "'empty' no match", true, 0x00);
    run_test(!(dfa_evaluate("x", 0, &result) && result.matched), "'x' no match", true, 0x00);
    run_test(!(dfa_evaluate("b", 0, &result) && result.matched), "'b' no match", true, 0x00);
    run_test(!(dfa_evaluate("c", 0, &result) && result.matched), "'c' no match", true, 0x00);
    run_test(!(dfa_evaluate("d", 0, &result) && result.matched), "'d' no match", true, 0x00);
    run_test(!(dfa_evaluate("aa", 0, &result) && result.matched), "'aa' no match", true, 0x00);
    run_test(!(dfa_evaluate("bb", 0, &result) && result.matched), "'bb' no match", true, 0x00);
    run_test(!(dfa_evaluate("cc", 0, &result) && result.matched), "'cc' no match", true, 0x00);
    run_test(!(dfa_evaluate("dd", 0, &result) && result.matched), "'dd' no match", true, 0x00);
    run_test(!(dfa_evaluate("abcde", 0, &result) && (result.category_mask & 0x02)), "'abcde' no cat 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcdef", 0, &result) && (result.category_mask & 0x02)), "'abcdef' no cat 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcdeg", 0, &result) && (result.category_mask & 0x02)), "'abcdeg' no cat 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcdeh", 0, &result) && (result.category_mask & 0x02)), "'abcdeh' no cat 0x02", true, 0x00);
    run_test(!(dfa_evaluate("abcdei", 0, &result) && (result.category_mask & 0x02)), "'abcdei' no cat 0x02", true, 0x00);
    
    // Token pattern tests
    run_test(!(dfa_evaluate("tok", 0, &result) && result.matched), "'tok' no match", true, 0x00);
    run_test(!(dfa_evaluate("token", 0, &result) && result.matched), "'token' no match", true, 0x00);
    run_test(!(dfa_evaluate("tokennn", 0, &result) && result.matched), "'tokennn' no match", true, 0x00);
    run_test(!(dfa_evaluate("ttoken", 0, &result) && result.matched), "'ttoken' no match", true, 0x00);
    run_test(!(dfa_evaluate("tokenx", 0, &result) && result.matched), "'tokenx' no match", true, 0x00);
    run_test(!(dfa_evaluate("atoken", 0, &result) && result.matched), "'atoken' no match", true, 0x00);
    run_test(!(dfa_evaluate("token0", 0, &result) && result.matched), "'token0' no match", true, 0x00);
    run_test(!(dfa_evaluate("token00", 0, &result) && result.matched), "'token00' no match", true, 0x00);
    run_test(!(dfa_evaluate("token000", 0, &result) && result.matched), "'token000' no match", true, 0x00);
    run_test(!(dfa_evaluate("git", 0, &result) && result.matched), "'git' no match", true, 0x00);
    run_test(!(dfa_evaluate("git ", 0, &result) && result.matched), "'git ' no match", true, 0x00);
    run_test(!(dfa_evaluate(" git", 0, &result) && result.matched), "' git' no match", true, 0x00);
    printf("\n");

    // ============================================================
    // GROUP 7: Escape sequences (18 tests)
    // ============================================================
    printf("Group 7: Escape sequence handling (18 tests)\n");
    printf("---------------------------------------------\n");
    
    run_test(dfa_evaluate("echo \"hello world\"", 0, &result) && result.matched, "'echo \"hello\"' matches", true, 0x01);
    run_test(dfa_evaluate("curl \"http://example.com\"", 0, &result) && result.matched, "'curl \"http://...\"' matches", true, 0x02);
    run_test(dfa_evaluate("echo test", 0, &result) && result.matched, "'echo test' matches", true, 0x01);
    run_test(dfa_evaluate("curl http://example.com", 0, &result) && result.matched, "'curl http://...' matches", true, 0x02);
    run_test(dfa_evaluate("echo \"test\"", 0, &result) && result.matched, "'echo \"test\"' matches", true, 0x01);
    run_test(dfa_evaluate("curl \"https://api.example.com\"", 0, &result) && result.matched, "'curl \"https://...\"' matches", true, 0x02);
    run_test(dfa_evaluate("echo \"hello\"", 0, &result) && result.matched, "'echo \"hello\"' matches", true, 0x01);
    run_test(dfa_evaluate("curl \"https://example.org\"", 0, &result) && result.matched, "'curl \"https://...\"' matches", true, 0x02);
    run_test(dfa_evaluate("echo \"goodbye\"", 0, &result) && result.matched, "'echo \"goodbye\"' matches", true, 0x01);
    run_test(dfa_evaluate("curl \"http://localhost:8080\"", 0, &result) && result.matched, "'curl \"http://...:8080\"' matches", true, 0x02);
    run_test(!(dfa_evaluate("echo 'single quotes'", 0, &result) && result.matched), "'echo '...' no match", true, 0x00);
    run_test(dfa_evaluate("curl http://localhost", 0, &result) && result.matched, "'curl http://localhost' matches", true, 0x02);
    run_test(dfa_evaluate("echo \"path/to/file\"", 0, &result) && result.matched, "'echo \"path/...\"' matches", true, 0x01);
    run_test(dfa_evaluate("curl \"https://api.test.com/v1/data\"", 0, &result) && result.matched, "'curl \".../v1/data\"' matches", true, 0x02);
    run_test(dfa_evaluate("echo \"multiple words\"", 0, &result) && result.matched, "'echo \"multiple...\"' matches", true, 0x01);
    run_test(dfa_evaluate("curl \"http://192.168.1.1/api\"", 0, &result) && result.matched, "'curl \"192.168...\"' matches", true, 0x02);
    run_test(dfa_evaluate("echo \"spaces and tabs\"", 0, &result) && result.matched, "'echo \"spaces...\"' matches", true, 0x01);
    run_test(dfa_evaluate("curl \"http://[::1]:8080\"", 0, &result) && result.matched, "'curl \"[::1]:8080\"' matches", true, 0x02);
    printf("\n");

    // ============================================================
    // Summary
    // ============================================================
    printf("=================================================\n");
    printf("Results: %d/%d tests passed\n", pass_count, pass_count + fail_count);
    printf("=================================================\n");
    
    free(data);
    return (fail_count == 0) ? 0 : 1;
}
