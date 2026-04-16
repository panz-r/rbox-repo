/*
 * test_cpl_integration.c - Integration tests for the Command Policy Learner.
 *
 * Tests realistic command sets and incremental learning scenarios.
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

/* ============================================================
 * REALISTIC COMMAND SET TESTS
 * ============================================================ */

static int test_realistic_git_workflow(void)
{
    cpl_learner_t *learner = cpl_learner_new(3, 0.0);

    /* Simulate a git workflow */
    const char *commands[] = {
        "git commit -m Initial commit",
        "git commit -m Fix bug",
        "git commit -m Add feature",
        "git commit -m Update docs",
        "git commit -m Refactor code",
        "git status",
        "git status",
        "git status",
        "git log",
        "git log",
        "git push origin main",
        "git push origin main",
        "git pull origin main",
    };

    for (size_t i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
        cpl_feed(learner, commands[i]);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* "git commit -m *" should be the top suggestion */
    bool found_commit = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "git") &&
            strstr(suggestions[i].pattern, "commit") &&
            strstr(suggestions[i].pattern, "-m")) {
            found_commit = true;
            ASSERT(suggestions[i].count == 5);
            break;
        }
    }
    ASSERT(found_commit);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

static int test_realistic_file_operations(void)
{
    cpl_learner_t *learner = cpl_learner_new(3, 0.0);

    const char *commands[] = {
        "cat /var/log/syslog | grep ERROR",
        "cat /var/log/auth.log | grep FAILED",
        "cat /var/log/kern.log | grep WARN",
        "cat /var/log/dmesg | grep error",
        "ls -la /tmp",
        "ls -la /var",
        "ls -la /home",
        "ls -la /etc",
        "ls -la /opt",
        "find /home -name *.c",
        "find /home -name *.h",
        "find /home -name *.txt",
    };

    for (size_t i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
        cpl_feed(learner, commands[i]);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* Look for pipeline pattern */
    bool found_pipeline = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "cat") &&
            strstr(suggestions[i].pattern, "|") &&
            strstr(suggestions[i].pattern, "grep")) {
            found_pipeline = true;
            ASSERT(suggestions[i].count == 4);
            break;
        }
    }
    ASSERT(found_pipeline);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

static int test_realistic_docker_commands(void)
{
    cpl_learner_t *learner = cpl_learner_new(3, 0.0);

    const char *commands[] = {
        "docker run -it ubuntu bash",
        "docker run -it alpine sh",
        "docker run -it nginx bash",
        "docker run -it python python3",
        "docker ps",
        "docker ps",
        "docker ps",
        "docker images",
        "docker images",
    };

    for (size_t i = 0; i < sizeof(commands)/sizeof(commands[0]); i++) {
        cpl_feed(learner, commands[i]);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* "docker run -it * *" pattern should exist */
    bool found_run = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "docker") &&
            strstr(suggestions[i].pattern, "run")) {
            found_run = true;
            break;
        }
    }
    ASSERT(found_run);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

/* ============================================================
 * INCREMENTAL LEARNING TESTS
 * ============================================================ */

static int test_incremental_learning(void)
{
    cpl_learner_t *learner = cpl_learner_new(3, 0.0);

    /* Batch 1: 3 commands */
    cpl_feed(learner, "ls -l /tmp/a");
    cpl_feed(learner, "ls -l /tmp/b");
    cpl_feed(learner, "ls -l /tmp/c");

    size_t count1 = 0;
    cpl_suggestion_t *s1 = cpl_suggest(learner, &count1);
    /* With min_support=3, we should see "ls -l *" */
    bool found_batch1 = false;
    for (size_t i = 0; i < count1; i++) {
        if (strstr(s1[i].pattern, "ls") &&
            strstr(s1[i].pattern, "-l")) {
            found_batch1 = true;
            break;
        }
    }
    ASSERT(found_batch1);
    cpl_free_suggestions(s1, count1);

    /* Batch 2: 3 more commands */
    cpl_feed(learner, "ls -l /tmp/d");
    cpl_feed(learner, "ls -l /tmp/e");
    cpl_feed(learner, "ls -l /tmp/f");

    size_t count2 = 0;
    cpl_suggestion_t *s2 = cpl_suggest(learner, &count2);

    /* The pattern should now have count=6 */
    bool found_batch2 = false;
    for (size_t i = 0; i < count2; i++) {
        if (strstr(s2[i].pattern, "ls") &&
            strstr(s2[i].pattern, "-l")) {
            found_batch2 = true;
            ASSERT(s2[i].count == 6);
            break;
        }
    }
    ASSERT(found_batch2);

    cpl_free_suggestions(s2, count2);
    cpl_learner_free(learner);
    return 1;
}

static int test_incremental_new_pattern(void)
{
    cpl_learner_t *learner = cpl_learner_new(3, 0.0);

    /* Batch 1: only ls commands */
    for (int i = 0; i < 5; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -l /tmp/f%d", i);
        cpl_feed(learner, cmd);
    }

    /* Batch 2: add git commands */
    for (int i = 0; i < 4; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "git commit -m msg%d", i);
        cpl_feed(learner, cmd);
    }

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);

    /* Both "ls" and "git" patterns should appear */
    bool found_ls = false, found_git = false;
    for (size_t i = 0; i < count; i++) {
        if (strstr(suggestions[i].pattern, "ls")) found_ls = true;
        if (strstr(suggestions[i].pattern, "git") &&
            strstr(suggestions[i].pattern, "commit")) found_git = true;
    }
    ASSERT(found_ls);
    ASSERT(found_git);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

/* ============================================================
 * LARGE DATASET TEST
 * ============================================================ */

static int test_large_dataset(void)
{
    cpl_learner_t *learner = cpl_learner_new(5, 0.01);

    /* Generate 100 commands across multiple patterns */
    for (int i = 0; i < 30; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "grep -r \"pattern%d\" /home/user/project", i);
        cpl_feed(learner, cmd);
    }
    for (int i = 0; i < 20; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "find /var/log -name \"*.log.%d\"", i);
        cpl_feed(learner, cmd);
    }
    for (int i = 0; i < 25; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "cat /tmp/output_%d.txt | wc -l", i);
        cpl_feed(learner, cmd);
    }
    for (int i = 0; i < 15; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "docker run -it image%d bash", i);
        cpl_feed(learner, cmd);
    }
    for (int i = 0; i < 10; i++) {
        char cmd[128];
        snprintf(cmd, sizeof(cmd), "systemctl restart service%d", i);
        cpl_feed(learner, cmd);
    }

    ASSERT(learner->trie.total_commands == 100);

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    /* Top suggestion should be grep (count=30) */
    ASSERT(suggestions[0].count == 30);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

/* ============================================================
 * SERIALISATION INTEGRATION TEST
 * ============================================================ */

static int test_save_load_large_dataset(void)
{
    cpl_learner_t *learner1 = cpl_learner_new(5, 0.01);

    /* Feed 50 commands */
    for (int i = 0; i < 25; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "git commit -m commit%d", i);
        cpl_feed(learner1, cmd);
    }
    for (int i = 0; i < 25; i++) {
        char cmd[64];
        snprintf(cmd, sizeof(cmd), "ls -la /path/to/dir%d", i);
        cpl_feed(learner1, cmd);
    }

    /* Save */
    cpl_error_t err = cpl_save(learner1, "tests/test_large_save.tmp");
    ASSERT(err == CPL_OK);

    /* Load into new learner */
    cpl_learner_t *learner2 = cpl_learner_new(5, 0.01);
    err = cpl_load(learner2, "tests/test_large_save.tmp");
    ASSERT(err == CPL_OK);

    /* Total commands should match */
    ASSERT(learner2->trie.total_commands == learner1->trie.total_commands);

    /* Suggestions should match */
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
 * CLI-STYLE FILE INPUT TEST
 * ============================================================ */

static int test_feed_from_file(void)
{
    /* Create a test input file */
    FILE *fp = fopen("tests/test_input.tmp", "w");
    ASSERT(fp != NULL);
    fprintf(fp, "ls -la /tmp\n");
    fprintf(fp, "ls -la /var\n");
    fprintf(fp, "ls -la /home\n");
    fprintf(fp, "ls -la /etc\n");
    fprintf(fp, "ls -la /opt\n");
    fprintf(fp, "cat /var/log/syslog\n");
    fprintf(fp, "cat /var/log/auth.log\n");
    fprintf(fp, "cat /var/log/kern.log\n");
    fclose(fp);

    cpl_learner_t *learner = cpl_learner_new(3, 0.0);

    fp = fopen("tests/test_input.tmp", "r");
    ASSERT(fp != NULL);
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        size_t len = strlen(line);
        while (len > 0 && (line[len-1] == '\n' || line[len-1] == '\r')) line[--len] = '\0';
        if (len == 0) continue;
        cpl_feed(learner, line);
    }
    fclose(fp);

    ASSERT(learner->trie.total_commands == 8);

    size_t count = 0;
    cpl_suggestion_t *suggestions = cpl_suggest(learner, &count);
    ASSERT(suggestions != NULL);
    ASSERT(count > 0);

    cpl_free_suggestions(suggestions, count);
    cpl_learner_free(learner);
    return 1;
}

/* ============================================================
 * MAIN
 * ============================================================ */

int main(void)
{
    printf("Running CPL integration tests...\n\n");

    printf("Realistic workloads:\n");
    TEST(test_realistic_git_workflow);
    TEST(test_realistic_file_operations);
    TEST(test_realistic_docker_commands);

    printf("\nIncremental learning:\n");
    TEST(test_incremental_learning);
    TEST(test_incremental_new_pattern);

    printf("\nLarge dataset:\n");
    TEST(test_large_dataset);

    printf("\nSerialisation:\n");
    TEST(test_save_load_large_dataset);

    printf("\nFile input:\n");
    TEST(test_feed_from_file);

    printf("\n========================================\n");
    printf("Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
