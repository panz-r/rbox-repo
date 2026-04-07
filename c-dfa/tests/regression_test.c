/**
 * regression_test.c - Pattern Regression Tests
 *
 * Tests for specific bug fixes to ensure they don't regress.
 * Uses the same pattern as other test suites.
 */

#include "../include/pipeline.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

static int total_tests = 0;
static int passed_tests = 0;

typedef struct {
    const char* input;
    bool should_match;
    int expected_category;
} TestCase;

typedef struct {
    const char* name;
    const char* pattern;
    TestCase* cases;
    int case_count;
} TestGroup;

static const char* PATTERNS_FILE = "/tmp/regression_patterns.txt";

static void run_group(const char* group_name, const char* pattern, TestCase* cases, int case_count) {
    printf("\n=== %s ===\n", group_name);
    
    FILE* f = fopen(PATTERNS_FILE, "w");
    if (!f) { printf("  [ERROR] Cannot create temp file\n"); return; }
    fprintf(f, "%s", pattern);
    fclose(f);
    
    pipeline_config_t config = {0};
    config.minimize_algo = PIPELINE_MIN_MOORE;
    config.optimize_layout = true;
    
    pipeline_t* p = pipeline_create(&config);
    if (!p) { printf("  [ERROR] Cannot create pipeline\n"); return; }
    
    pipeline_error_t err = pipeline_run(p, PATTERNS_FILE);
    if (err != PIPELINE_OK) { 
        printf("  [ERROR] Pipeline failed: %s\n", pipeline_error_string(err)); 
        pipeline_destroy(p); 
        return; 
    }
    
    size_t size = 0;
    const uint8_t* binary = pipeline_get_binary(p, &size);
    if (!binary || size == 0) { printf("  [ERROR] No binary\n"); pipeline_destroy(p); return; }
    
    dfa_evaluator_t* eval = dfa_eval_create(binary, size);
    if (!eval) { printf("  [ERROR] Cannot create evaluator\n"); pipeline_destroy(p); return; }
    
    for (int i = 0; i < case_count; i++) {
        total_tests++;
        dfa_result_t result = dfa_eval_evaluate(eval, cases[i].input);
        bool match_ok = (result.matched == cases[i].should_match);
        bool cat_ok = (!cases[i].should_match || result.matched == false || 
                      (result.category_mask & cases[i].expected_category) != 0);
        
        if (match_ok && cat_ok) {
            passed_tests++;
            printf("  [PASS] '%s' %s match\n", cases[i].input, cases[i].should_match ? "should" : "should not");
        } else {
            printf("  [FAIL] '%s' %s match (got matched=%d category=0x%02X)\n", 
                   cases[i].input, cases[i].should_match ? "should" : "should not",
                   result.matched, result.category_mask);
        }
    }
    
    dfa_eval_destroy(eval);
    pipeline_destroy(p);
}

int main(void) {
    printf("C-DFA Pattern Regression Tests\n");
    printf("==============================\n");
    
    // Bug #6: = followed by fragment reference in optional group
    // Pattern: ls( =)?((safe::x)) where safe::x=a
    // ( =)? means space-then-equals is optional
    // ((safe::x)) means fragment is REQUIRED
    // Matches: "lsa" (ls + nothing + a), "ls =a" (ls + space + = + a)
    TestCase eq_frag_cases[] = {
        { "lsa", true, 0x01 },    // ls + nothing + a
        { "ls =a", true, 0x01 },  // ls + space + = + a
        { "ls=a", false, 0 },     // no space before =
        { "ls", false, 0 },      // fragment required
        { "ls x", false, 0 },    // x not =
    };
    run_group("BUG #6: = followed by fragment (FIXED)", 
             "ACCEPTANCE_MAPPING [safe] -> 0\n[fragment:safe::x] a\n[safe] ls( =)?((safe::x))",
             eq_frag_cases, 5);
    
    // Bug #6 control: other chars before fragment work
    TestCase other_char_cases[] = {
        { "lsza", true, 0x01 },   // ls + z + a
        { "lsa", true, 0x01 },    // ls + a
        { "ls", false, 0 },      // fragment required
    };
    run_group("BUG #6: Control - other chars before fragment",
             "ACCEPTANCE_MAPPING [safe] -> 0\n[fragment:safe::x] a\n[safe] ls(z)?((safe::x))",
             other_char_cases, 3);
    
    // Bug #6: literal = at end of pattern (space before = required)
    TestCase eq_end_cases[] = {
        { "ls x=", true, 0x01 },  // ls + space + x + =
        { "ls=", false, 0 },     // no space before =
        { "ls", false, 0 },      // = required
    };
    run_group("BUG #6: literal = at end of pattern",
             "ACCEPTANCE_MAPPING [safe] -> 0\n[safe] ls x=",
             eq_end_cases, 3);
    
    // Bug #7/#8: nfa2dfa_advanced crashes with optional groups containing 3+ chars + space
    // Pattern: ls( (abc )?) = ls + (space + (abc)? + space) - optional group with 3+ chars + space
    TestCase opt_group_3_cases[] = {
        { "ls ", true, 0x01 },       // ls + space (optional abc empty, trailing space)
        { "ls abc ", true, 0x01 },   // ls + space + abc + space
        { "lsabc", false, 0 },       // no space after ls
        { "lsab", false, 0 },        // partial match
    };
    run_group("BUG #7/#8: Optional group with 3+ chars (FIXED)",
             "ACCEPTANCE_MAPPING [safe] -> 0\n[safe] ls( (abc )?)",
             opt_group_3_cases, 4);
    
    // Bug #8: Complex nested optional groups
    // Pattern: ls( (--color=auto )?(-(la|l|a) )?((x))* )?
    // The outer group requires: space + content + space (all three optionals must leave trailing space)
    // So "ls " alone doesn't work (needs trailing space after optional content)
    TestCase complex_opt_cases[] = {
        { "ls", true, 0x01 },              // ls + nothing (outer optional skipped)
        { "ls x ", true, 0x01 },           // ls + space + x + space (x matches ((x))*)
        { "ls -la x ", true, 0x01 },       // ls + space + -la + space + x + space
        { "ls --color=auto -a x ", true, 0x01 },  // full optional content
    };
    run_group("BUG #8: Complex nested optional groups (FIXED)",
             "ACCEPTANCE_MAPPING [safe] -> 0\n[safe] ls( (--color=auto )?(-(la|l|a) )?((x))* )?",
             complex_opt_cases, 4);
    
    // Bug #8 full pattern: Complex nested optional groups with fragment reference
    // Pattern: ls( (--color=auto )?(-(la|l|a) )?((safe::filename))* )?
    // Fragment safe::filename=/tmp|file|a, matches /tmp, file, or a
    // Note: outer group requires trailing space after optional content
    TestCase full_pattern_cases[] = {
        { "ls", true, 0x01 },              // ls + nothing (outer optional skipped)
        { "ls -la /tmp ", true, 0x01 },    // ls + space + -la + space + /tmp + space
        { "ls --color=auto -l /tmp ", true, 0x01 },  // full optional content + trailing space
    };
    run_group("BUG #8 Full: ls with --color, -l, and filename fragment",
             "ACCEPTANCE_MAPPING [safe] -> 0\n[fragment:safe::filename] /tmp|file|a\n[safe] ls( (--color=auto )?(-(la|l|a) )?((safe::filename))* )?",
             full_pattern_cases, 3);
    
    // Working optional group patterns (control tests)
    // Pattern: ls( (ab )?) = ls + (space + (ab)? + space)
    TestCase opt_group_cases[] = {
        { "ls ", true, 0x01 },     // ls + space (optional ab empty, trailing space)
        { "ls ab ", true, 0x01 },  // ls + space + ab + space
        { "lsabc", false, 0 },     // no space after ls
    };
    run_group("Optional group (control - no crash)",
             "ACCEPTANCE_MAPPING [safe] -> 0\n[safe] ls( (ab )?)",
             opt_group_cases, 3);
    
    printf("\n========================================\n");
    printf("SUMMARY: %d/%d passed\n", passed_tests, total_tests);
    printf("========================================\n");
    
    return (passed_tests == total_tests) ? 0 : 1;
}
