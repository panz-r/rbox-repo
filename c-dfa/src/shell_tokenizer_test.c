#include "shell_tokenizer.h"
#include "shell_processor.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;

#define TEST_ASSERT(cond, msg) do { \
    tests_run++; \
    if (cond) { \
        tests_passed++; \
        printf("  [PASS] %s\n", msg); \
    } else { \
        printf("  [FAIL] %s\n", msg); \
    } \
} while(0)

static void test_simple_command(void) {
    printf("\nTest: Simple Command\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("git status", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");
    TEST_ASSERT(cmd_count == 1, "Single command parsed");
    TEST_ASSERT(commands != NULL, "Commands array allocated");

    if (cmd_count >= 1 && commands[0].token_count > 0) {
        TEST_ASSERT(commands[0].tokens[0].type == TOKEN_COMMAND, "First token is COMMAND");
        TEST_ASSERT(strncmp(commands[0].tokens[0].start, "git", 3) == 0, "First token is 'git'");
    }

    shell_free_commands(commands, cmd_count);
}

static void test_pipeline(void) {
    printf("\nTest: Pipeline (pipe operator)\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("cat file.txt | head -n 5", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");
    TEST_ASSERT(cmd_count == 2, "Two commands in pipeline");

    shell_free_commands(commands, cmd_count);
}

static void test_semicolon_separator(void) {
    printf("\nTest: Semicolon Separator\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("git status; echo done", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");
    TEST_ASSERT(cmd_count == 2, "Two commands separated by semicolon");

    shell_free_commands(commands, cmd_count);
}

static void test_logical_and(void) {
    printf("\nTest: Logical AND (&&)\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("git status && echo ok", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");
    TEST_ASSERT(cmd_count == 2, "Two commands with &&");

    shell_free_commands(commands, cmd_count);
}

static void test_logical_or(void) {
    printf("\nTest: Logical OR (||)\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("git branch || echo no branches", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");
    TEST_ASSERT(cmd_count == 2, "Two commands with ||");

    shell_free_commands(commands, cmd_count);
}

static void test_quoted_arguments(void) {
    printf("\nTest: Quoted Arguments\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("git commit -m \"hello world\"", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");
    TEST_ASSERT(cmd_count == 1, "Single command with quoted args");

    shell_free_commands(commands, cmd_count);
}

static void test_redirection(void) {
    printf("\nTest: Output Redirection\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("cat file.txt > output.txt", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");

    shell_free_commands(commands, cmd_count);
}

static void test_empty_command(void) {
    printf("\nTest: Empty Command\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("", &commands, &cmd_count);
    TEST_ASSERT(result == false || cmd_count == 0, "Empty command returns false or empty");
}

static void test_complex_pipeline(void) {
    printf("\nTest: Complex Pipeline\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    bool result = shell_tokenize_commands("cat file.txt | grep pattern | head -n 10", &commands, &cmd_count);
    TEST_ASSERT(result == true, "shell_tokenize_commands returns true");
    TEST_ASSERT(cmd_count == 3, "Three commands in pipeline");

    shell_free_commands(commands, cmd_count);
}

static void test_token_type_names(void) {
    printf("\nTest: Token Type Names\n");

    TEST_ASSERT(strcmp(shell_token_type_name(TOKEN_COMMAND), "COMMAND") == 0, "TOKEN_COMMAND name");
    TEST_ASSERT(strcmp(shell_token_type_name(TOKEN_PIPE), "PIPE") == 0, "TOKEN_PIPE name");
    TEST_ASSERT(strcmp(shell_token_type_name(TOKEN_SEMICOLON), "SEMICOLON") == 0, "TOKEN_SEMICOLON name");
    TEST_ASSERT(strcmp(shell_token_type_name(TOKEN_END), "END") == 0, "TOKEN_END name");
}

static void test_whitespace_handling(void) {
    printf("\nTest: Whitespace Handling\n");

    shell_command_t* commands = NULL;
    size_t cmd_count = 0;

    /* Multiple spaces */
    bool result = shell_tokenize_commands("git   status", &commands, &cmd_count);
    TEST_ASSERT(result == true && cmd_count == 1, "Multiple spaces handled");

    /* Leading/trailing spaces */
    result = shell_tokenize_commands("  git status  ", &commands, &cmd_count);
    TEST_ASSERT(result == true && cmd_count == 1, "Leading/trailing spaces handled");

    shell_free_commands(commands, cmd_count);
}

int main(int argc, char* argv[]) {
    printf("=================================================\n");
    printf("Shell Tokenizer Unit Tests\n");
    printf("=================================================\n");

    test_simple_command();
    test_pipeline();
    test_semicolon_separator();
    test_logical_and();
    test_logical_or();
    test_quoted_arguments();
    test_redirection();
    test_empty_command();
    test_complex_pipeline();
    test_token_type_names();
    test_whitespace_handling();

    printf("\n=================================================\n");
    printf("Results: %d/%d tests passed\n", tests_passed, tests_run);
    printf("=================================================\n");

    return (tests_passed == tests_run) ? 0 : 1;
}
