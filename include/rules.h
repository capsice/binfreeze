#ifndef BF_RULES
#define BF_RULES

#include <stddef.h>

enum { BF_RULE_ALLOW, BF_RULE_DENY };

typedef struct bf_rule bf_rule_t;
typedef struct bf_rule_store bf_rule_store_t;

struct bf_rule {
  char *key;
  int type;
  bf_rule_t *next;
};

struct bf_rule_store {
  size_t length;
  size_t capacity;
  bf_rule_t **rules;
};

int bf_rules_create(bf_rule_store_t **rule_store);
int bf_rules_set(bf_rule_store_t *rule_store, const char *key, int value);
int bf_rules_get(bf_rule_store_t *rule_store, const char *key);
int bf_rules_load_from_path(bf_rule_store_t *rule_store, const char *path,
                            const int type);

#endif