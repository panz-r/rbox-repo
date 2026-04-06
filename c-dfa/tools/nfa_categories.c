/**
 * nfa_categories.c - Category system for NFA builder
 *
 * Manages dynamic category names, acceptance mappings,
 * and category parsing/lookup used during pattern processing.
 */

#define _DEFAULT_SOURCE
#include "nfa_builder.h"
#include "../include/dfa_errors.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Default category names
static const char* default_category_names[CAT_COUNT] = {
    "safe", "caution", "modifying", "dangerous",
    "network", "admin", "build", "container"
};

void nfa_category_init_defaults(nfa_builder_context_t* ctx) {
    if (ctx->categories_defined) return;

    for (int i = 0; i < CAT_COUNT; i++) {
        strlcpy(ctx->dynamic_category_names[i], default_category_names[i], MAX_CATEGORY_NAME);
    }
    ctx->dynamic_category_count = CAT_COUNT;
    ctx->categories_defined = true;
}

void nfa_category_parse_definition(nfa_builder_context_t* ctx, const char* line) {
    if (line[0] < '0' || line[0] > '7') return;
    if (line[1] != ':') return;

    int idx = line[0] - '0';
    const char* name_start = line + 2;
    while (*name_start == ' ' || *name_start == '\t') name_start++;

    if (*name_start == '\0' || *name_start == '\n' || *name_start == '#') return;

    char name[MAX_CATEGORY_NAME];
    int name_len = 0;
    const char* p = name_start;
    while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '#' && name_len < MAX_CATEGORY_NAME - 1) {
        name[name_len++] = *p;
        p++;
    }
    name[name_len] = '\0';

    snprintf(ctx->dynamic_category_names[idx], MAX_CATEGORY_NAME, "%s", name);

    if (idx >= ctx->dynamic_category_count) {
        ctx->dynamic_category_count = idx + 1;
    }

    ctx->categories_defined = true;

    // Also add an ACCEPTANCE_MAPPING entry so lookup can find this category
    nfa_category_add_mapping(ctx, name, "", "", idx);
}

int nfa_category_parse(nfa_builder_context_t* ctx, const char* name) {
    const char* names_to_use[CAT_COUNT];
    int count_to_use;

    if (ctx->categories_defined) {
        for (int i = 0; i < ctx->dynamic_category_count && i < CAT_COUNT; i++) {
            names_to_use[i] = ctx->dynamic_category_names[i];
        }
        count_to_use = ctx->dynamic_category_count;
    } else {
        for (int i = 0; i < CAT_COUNT; i++) {
            names_to_use[i] = default_category_names[i];
        }
        count_to_use = CAT_COUNT;
    }

    for (int i = 0; i < count_to_use; i++) {
        if (strcmp(name, names_to_use[i]) == 0) {
            return i;
        }
    }

    ERROR("Unknown category '%s'. Please define all categories in [CATEGORIES] section.", name);
    return -1;
}

void nfa_category_add_mapping(nfa_builder_context_t* ctx, const char* category,
                               const char* subcategory, const char* operations, int acceptance_cat) {
    // Check for duplicate
    for (int i = 0; i < ctx->category_mapping_count; i++) {
        if (strcmp(ctx->category_mappings[i].category, category) == 0 &&
            strcmp(ctx->category_mappings[i].subcategory, subcategory) == 0 &&
            strcmp(ctx->category_mappings[i].operations, operations) == 0) {
            ctx->category_mappings[i].acceptance_category = acceptance_cat;
            return;
        }
    }

    if (ctx->category_mapping_count < MAX_CATEGORY_MAPPINGS) {
        category_mapping_t* m = &ctx->category_mappings[ctx->category_mapping_count++];
        strlcpy(m->category, category, sizeof(m->category));
        strlcpy(m->subcategory, subcategory, sizeof(m->subcategory));
        strlcpy(m->operations, operations, sizeof(m->operations));
        m->acceptance_category = acceptance_cat;
    }
}

int nfa_category_lookup(nfa_builder_context_t* ctx, const char* category,
                        const char* subcategory, const char* operations) {
    for (int i = 0; i < ctx->category_mapping_count; i++) {
        category_mapping_t* m = &ctx->category_mappings[i];
        if (strcmp(m->category, category) != 0) continue;
        if (m->subcategory[0] != '\0' && subcategory[0] != '\0' &&
            strcmp(m->subcategory, subcategory) != 0) continue;
        if (m->operations[0] != '\0' && operations[0] != '\0' &&
            strcmp(m->operations, operations) != 0) continue;
        return m->acceptance_category;
    }
    return -1;
}

void nfa_category_parse_mapping(nfa_builder_context_t* ctx, const char* line) {
    const char* arrow = strstr(line, "->");
    if (arrow == NULL) {
        WARNING("Invalid ACCEPTANCE_MAPPING syntax (no ->): %s", line);
        return;
    }

    const char* bracket_open = strchr(line, '[');
    const char* bracket_close = strchr(line, ']');
    if (bracket_open == NULL || bracket_close == NULL || bracket_close > arrow) {
        WARNING("Invalid ACCEPTANCE_MAPPING syntax (bad brackets): %s", line);
        return;
    }

    char category_str[512];
    size_t cat_len = bracket_close - bracket_open - 1;
    strncpy(category_str, bracket_open + 1, cat_len);
    category_str[cat_len] = '\0';

    char* end;
    long acceptance_cat_long = strtol(arrow + 2, &end, 10);
    if (end == arrow + 2 || acceptance_cat_long < 0 || acceptance_cat_long > 7) {
        WARNING("Invalid acceptance category: %s", line);
        return;
    }
    int acceptance_cat = (int)acceptance_cat_long;

    char category[64] = "";
    char subcategory[64] = "";
    char operations[256] = "";

    char* tok = strtok(category_str, ":");
    if (tok != NULL) {
        strlcpy(category, tok, sizeof(category));
    }
    tok = strtok(NULL, ":");
    if (tok != NULL) {
        strlcpy(subcategory, tok, sizeof(subcategory));
    }
    tok = strtok(NULL, ":");
    if (tok != NULL) {
        strlcpy(operations, tok, sizeof(operations));
    }

    nfa_category_add_mapping(ctx, category, subcategory, operations, acceptance_cat);

    if (ctx->flag_verbose) {
        fprintf(stderr, "ACCEPTANCE_MAPPING: [%s:%s:%s] -> %d\n",
                category, subcategory, operations, acceptance_cat);
    }
}
