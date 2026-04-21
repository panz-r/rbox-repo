#include "rule_engine.h"

soft_ruleset_t *user_fs_rules = NULL;
soft_ruleset_t *hard_fallthrough_fs_rules = NULL;

soft_ruleset_t *get_user_fs_rules(void) {
    return user_fs_rules;
}

soft_ruleset_t *get_hard_fallthrough_fs_rules(void) {
    return hard_fallthrough_fs_rules;
}

soft_ruleset_t *get_effective_fs_rules(void) {
    if (user_fs_rules && hard_fallthrough_fs_rules) {
        soft_ruleset_merge(user_fs_rules, hard_fallthrough_fs_rules);
        soft_ruleset_free(hard_fallthrough_fs_rules);
        hard_fallthrough_fs_rules = NULL;
        return user_fs_rules;
    }
    if (hard_fallthrough_fs_rules) {
        return hard_fallthrough_fs_rules;
    }
    return user_fs_rules;
}
