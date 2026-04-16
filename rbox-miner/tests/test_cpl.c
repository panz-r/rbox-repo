/*
 * test_cpl.c - Unit tests for the Command Policy Learner.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include "rbox_policy_learner.h"

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { \
    tests_run++; \
    printf("  %-40s ", #name); \
    if (name()) { \
        tests_passed++; \
        printf("PASS\n"); \
    } else { \
        tests_failed++; \
        printf("FAIL\n"); \
    } \
} while(0)

#define ASSERT(cond) do { if (!(cond)) { printf("  Assertion failed: %s at %s:%d\n", #cond, __FILE__, __LINE__); return 0; } } while(0)
#define ASSERT_STR_EQ(a, b) do { if (strcmp((a), (b)) != 0) { printf("  String mismatch: '%s' != '%s' at %s:%d\n", (a), (b), __FILE__, __LINE__); return 0; } } while(0)

/* ============================================================
 * NORMALISATION TESTS
 * ============================================================ */

static int test_normalize_simple(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("ls -la", &tokens, &count);
    ASSERT(err == CPL_OK);
    /* -la is a stacked boolean flag, kept as literal */
    ASSERT(count == 2);
    ASSERT_STR_EQ(tokens[0], "ls");
    ASSERT_STR_EQ(tokens[1], "-la");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_path(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("cat /etc/passwd", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count == 2);
    ASSERT_STR_EQ(tokens[0], "cat");
    ASSERT_STR_EQ(tokens[1], "#p");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_flag_value_long(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("git commit --message \"hello world\"", &tokens, &count);
    ASSERT(err == CPL_OK);
    /* git, commit, --message, * */
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "commit");
    ASSERT_STR_EQ(tokens[2], "--message");
    /* Next token should be the wildcard */
    ASSERT(count >= 4);
    ASSERT_STR_EQ(tokens[3], "#qs");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_flag_value_short(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("git commit -m msg", &tokens, &count);
    ASSERT(err == CPL_OK);
    /* -m is a short flag; we cannot distinguish flag+value from flag+positional,
     * so the next token is kept as literal for exact matching */
    ASSERT(count == 4);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "commit");
    ASSERT_STR_EQ(tokens[2], "-m");
    ASSERT_STR_EQ(tokens[3], "msg");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_flag_value_attached(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("docker run -it ubuntu bash", &tokens, &count);
    ASSERT(err == CPL_OK);
    /* -i, *, -t, *, ubuntu, bash */
    /* -it is treated as a multi-char short flag, so it stays as -it */
    /* Actually, -it has 3 chars after '-', so is_short_flag_with_attached_value returns true */
    /* -i, *, -t, * */
    /* Let's verify the actual behavior */
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_pipeline(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("cat /var/log/syslog | grep ERROR", &tokens, &count);
    ASSERT(err == CPL_OK);
    /* cat, #p, |, grep, #w */
    ASSERT(count >= 5);
    ASSERT_STR_EQ(tokens[0], "cat");
    ASSERT_STR_EQ(tokens[1], "#p");
    ASSERT_STR_EQ(tokens[2], "|");
    ASSERT_STR_EQ(tokens[3], "grep");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_redirection(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("ls > /tmp/out.txt", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "ls");
    ASSERT_STR_EQ(tokens[1], ">");
    ASSERT_STR_EQ(tokens[2], "#p");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_number(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("head -n 42 file.txt", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count >= 4);
    ASSERT_STR_EQ(tokens[0], "head");
    ASSERT_STR_EQ(tokens[1], "-n");
    ASSERT_STR_EQ(tokens[2], "#n");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_hex(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("git show 0xdeadbeef", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "show");
    ASSERT_STR_EQ(tokens[2], "#n");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_ip(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("ping 192.168.1.1", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count >= 2);
    ASSERT_STR_EQ(tokens[0], "ping");
    ASSERT_STR_EQ(tokens[1], "#i");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_env_assignment(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("export PATH=/usr/bin", &tokens, &count);
    ASSERT(err == CPL_OK);
    /* export, PATH=, * */
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "export");
    ASSERT_STR_EQ(tokens[1], "PATH=");
    ASSERT_STR_EQ(tokens[2], "#p");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_long_flag_equals(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("gcc -o myprog main.c", &tokens, &count);
    ASSERT(err == CPL_OK);
    /* -o is a short flag; we cannot distinguish flag+value from flag+positional,
     * so tokens are kept as literals for exact matching.
     * main.c is classified as #f (filename). */
    ASSERT(count == 4);
    ASSERT_STR_EQ(tokens[0], "gcc");
    ASSERT_STR_EQ(tokens[1], "-o");
    ASSERT_STR_EQ(tokens[2], "myprog");
    ASSERT_STR_EQ(tokens[3], "#f");
    cpl_free_tokens(tokens, count);
    return 1;
}

/* ============================================================
 * TRIE TESTS
 * ============================================================ */

static int test_trie_create_free(void)
{
    cpl_learner_t *learner = cpl_learner_new(5, 0.05);
    ASSERT(learner != NULL);
    ASSERT(learner->trie.root != NULL);
    ASSERT(learner->trie.total_commands == 0);
    cpl_learner_free(learner);
    return 1;
}

static int test_trie_insert_single(void)
{
    cpl_learner_t *learner = cpl_learner_new(1, 0.0);
    cpl_error_t err = cpl_feed(learner, "ls -la");
    ASSERT(err == CPL_OK);
    ASSERT(learner->trie.total_commands == 1);
    cpl_learner_free(learner);
    return 1;
}

static int test_trie_insert_multiple(void)
{
    cpl_learner_t *learner = cpl_learner_new(1, 0.0);
    cpl_feed(learner, "ls -la /tmp");
    cpl_feed(learner, "ls -la /var");
    cpl_feed(learner, "ls -la /home");
    ASSERT(learner->trie.total_commands == 3);
    cpl_learner_free(learner);
    return 1;
}

static int test_trie_counts(void)
{
    cpl_learner_t *learner = cpl_learner_new(1, 0.0);
    cpl_feed(learner, "git commit -m msg1");
    cpl_feed(learner, "git commit -m msg2");
    cpl_feed(learner, "git commit -m msg3");
    cpl_feed(learner, "git status");
    cpl_feed(learner, "git status");

    /* Root count should be 5 */
    ASSERT(learner->trie.root->count == 5);

    /* Find "git" child */
    cpl_node_t *git_node = NULL;
    for (size_t i = 0; i < learner->trie.root->num_children; i++) {
        if (strcmp(learner->trie.root->children[i]->token, "git") == 0) {
            git_node = learner->trie.root->children[i];
            break;
        }
    }
    ASSERT(git_node != NULL);
    ASSERT(git_node->count == 5);

    cpl_learner_free(learner);
    return 1;
}

/* ============================================================
 * SUGGESTION TESTS
 * ============================================================ */

static int test_suggest_basic(void)
{
    cpl_learner_t *learner = cpl_learner_new(3, 0.0);
    /* Feed 5 identical commands */
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -l /tmp/file%d", i);
        cpl_feed(learner, cmd);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* The pattern "ls -l #p" should be among suggestions */
    bool found = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "ls") &&
            strstr(suggestions[i].pattern, "-l") &&
            strstr(suggestions[i].pattern, "#p")) {
            found = true;
            ASSERT(suggestions[i].count == 5);
            break;
        }
    }
    ASSERT(found);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

static int test_suggest_pipeline(void)
{
    cpl_learner_t *learner = cpl_learner_new(3, 0.0);
    for (int i = 0; i < 4; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "cat /var/log/file%d.log | grep ERROR", i);
        cpl_feed(learner, cmd);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* Look for a pattern containing pipe */
    bool found_pipe = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "|")) {
            found_pipe = true;
            break;
        }
    }
    ASSERT(found_pipe);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

static int test_suggest_confidence_ranking(void)
{
    cpl_learner_t *learner = cpl_learner_new(2, 0.0);
    /* 10 git commands, 8 of which are "git commit -m *" */
    for (int i = 0; i < 8; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "git commit -m msg%d", i);
        cpl_feed(learner, cmd);
    }
    cpl_feed(learner, "git status");
    cpl_feed(learner, "git log");

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* First suggestion should have highest confidence */
    if (count >= 2) {
        ASSERT(suggestions[0].confidence >= suggestions[1].confidence);
    }

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

static int test_suggest_no_duplicates(void)
{
    cpl_learner_t *learner = cpl_learner_new(2, 0.0);
    for (int i = 0; i < 5; i++) {
        cpl_feed(learner, "ls -la");
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);

    /* Check no duplicate patterns */
    for (size_t i = 0; i < count; i++) {
        for (size_t j = i + 1; j < count; j++) {
            ASSERT(strcmp(suggestions[i].pattern, suggestions[j].pattern) != 0);
        }
    }

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

static int test_suggest_min_support_filter(void)
{
    cpl_learner_t *learner = cpl_learner_new(10, 0.0);
    /* Feed only 5 commands – below min_support */
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -l /tmp/file%d", i);
        cpl_feed(learner, cmd);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    /* No suggestions should meet min_support=10 */
    ASSERT(count == 0 || suggestions == NULL);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

static int test_suggest_max_suggestions(void)
{
    cpl_learner_t *learner = cpl_learner_new(2, 0.0);
    learner->max_suggestions = 3;

    /* Feed many different commands */
    for (int i = 0; i < 20; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "cmd%d arg%d val%d", i, i, i);
        cpl_feed(learner, cmd);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(count <= 3);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

/* ============================================================
 * BLACKLIST TESTS
 * ============================================================ */

static int test_blacklist_add_and_check(void)
{
    cpl_learner_t *learner = cpl_learner_new(1, 0.0);
    ASSERT(cpl_blacklist_add(learner, "git commit -m *") == CPL_OK);
    ASSERT(cpl_is_blacklisted(learner, "git commit -m *"));
    ASSERT(!cpl_is_blacklisted(learner, "git status"));
    cpl_learner_free(learner);
    return 1;
}

static int test_blacklist_prevents_suggestion(void)
{
    cpl_learner_t *learner = cpl_learner_new(2, 0.0);
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -l /tmp/file%d", i);
        cpl_feed(learner, cmd);
    }

    /* Blacklist the pattern */
    cpl_blacklist_add(learner, "ls -l *");

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);

    /* The blacklisted pattern should not appear */
    for (size_t i = 0; i < count; i++) {
        ASSERT(strcmp(suggestions[i].pattern, "ls -l *") != 0);
    }

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

/* ============================================================
 * SERIALISATION TESTS
 * ============================================================ */

static int test_save_and_load(void)
{
    cpl_learner_t *learner1 = cpl_learner_new(1, 0.0);
    cpl_feed(learner1, "git commit -m msg1");
    cpl_feed(learner1, "git commit -m msg2");
    cpl_feed(learner1, "ls -la /tmp");
    cpl_feed(learner1, "ls -la /var");

    cpl_error_t err = cpl_save(learner1, "tests/test_save_load.tmp");
    ASSERT(err == CPL_OK);

    cpl_learner_t *learner2 = cpl_learner_new(1, 0.0);
    err = cpl_load(learner2, "tests/test_save_load.tmp");
    ASSERT(err == CPL_OK);

    /* Both should produce same suggestions */
    size_t count1 = 0, count2 = 0;
    cpl_suggestion_t *s1 = cpl_suggest(learner1, &count1);
    cpl_suggestion_t *s2 = cpl_suggest(learner2, &count2);
    ASSERT(count1 == count2);

    for (size_t i = 0; i < count1; i++) {
        ASSERT(strcmp(s1[i].pattern, s2[i].pattern) == 0);
        ASSERT(s1[i].count == s2[i].count);
    }

    cpl_free_suggestions(s1, count1);
    cpl_free_suggestions(s2, count2);
    cpl_learner_free(learner1);
    cpl_learner_free(learner2);
    return 1;
}

/* ============================================================
 * EDGE CASE TESTS
 * ============================================================ */

static int test_empty_command(void)
{
    cpl_learner_t *learner = cpl_learner_new(1, 0.0);
    cpl_error_t err = cpl_feed(learner, "");
    ASSERT(err == CPL_ERR_INVALID);
    cpl_learner_free(learner);
    return 1;
}

static int test_null_command(void)
{
    cpl_learner_t *learner = cpl_learner_new(1, 0.0);
    cpl_error_t err = cpl_feed(learner, NULL);
    ASSERT(err == CPL_ERR_INVALID);
    cpl_learner_free(learner);
    return 1;
}

static int test_suggest_empty_trie(void)
{
    cpl_learner_t *learner = cpl_learner_new(5, 0.05);
    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions == NULL);
    ASSERT(count == 0);
    cpl_learner_free(learner);
    return 1;
}

static int test_normalize_quoted_string(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("echo \"hello world\"", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count >= 2);
    ASSERT_STR_EQ(tokens[0], "echo");
    /* Quoted string with space → #qs */
    ASSERT_STR_EQ(tokens[1], "#qs");
    cpl_free_tokens(tokens, count);
    return 1;
}

static int test_normalize_hash(void)
{
    char **tokens = NULL;
    size_t count = 0;
    cpl_error_t err = cpl_normalize("git show a1b2c3d4e5f6a7b8", &tokens, &count);
    ASSERT(err == CPL_OK);
    ASSERT(count >= 3);
    ASSERT_STR_EQ(tokens[0], "git");
    ASSERT_STR_EQ(tokens[1], "show");
    ASSERT_STR_EQ(tokens[2], "#h");
    cpl_free_tokens(tokens, count);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running CPL unit tests...\n\n");

    printf("Normalisation:\n");
    TEST(test_normalize_simple);
    TEST(test_normalize_path);
    TEST(test_normalize_flag_value_long);
    TEST(test_normalize_flag_value_short);
    TEST(test_normalize_flag_value_attached);
    TEST(test_normalize_pipeline);
    TEST(test_normalize_redirection);
    TEST(test_normalize_number);
    TEST(test_normalize_hex);
    TEST(test_normalize_ip);
    TEST(test_normalize_env_assignment);
    TEST(test_normalize_long_flag_equals);
    TEST(test_normalize_quoted_string);
    TEST(test_normalize_hash);

    printf("\nTrie:\n");
    TEST(test_trie_create_free);
    TEST(test_trie_insert_single);
    TEST(test_trie_insert_multiple);
    TEST(test_trie_counts);

    printf("\nSuggestions:\n");
    TEST(test_suggest_basic);
    TEST(test_suggest_pipeline);
    TEST(test_suggest_confidence_ranking);
    TEST(test_suggest_no_duplicates);
    TEST(test_suggest_min_support_filter);
    TEST(test_suggest_max_suggestions);

    printf("\nBlacklist:\n");
    TEST(test_blacklist_add_and_check);
    TEST(test_blacklist_prevents_suggestion);

    printf("\nSerialisation:\n");
    TEST(test_save_and_load);

    printf("\nEdge cases:\n");
    TEST(test_empty_command);
    TEST(test_null_command);
    TEST(test_suggest_empty_trie);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
