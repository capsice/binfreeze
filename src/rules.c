#include "binfreeze.h"

#include "rules.h"

#include <ctype.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static inline size_t djb2(const char *key, size_t capacity) {
  size_t hash = 5381;
  int i = 0;
  char c;

  while ((c = key[i])) {
    hash = ((hash << 5) + hash) + c;
    i++;
  }

  return hash % capacity;
}

int bf_rules_create(bf_rule_store_t **rule_store) {

  enum { RULES_MAP_CAPACITY = 4096 };

  bf_rule_store_t *new_rule_store;
  new_rule_store = calloc(1, sizeof(bf_rule_store_t));

  if (new_rule_store == NULL)
    return BF_ERRNO;

  new_rule_store->rules = calloc(RULES_MAP_CAPACITY, sizeof(bf_rule_t *));

  if (new_rule_store->rules == NULL) {
    free(new_rule_store);
    return BF_ERRNO;
  }

  new_rule_store->length = 0;
  new_rule_store->capacity = RULES_MAP_CAPACITY;

  *rule_store = new_rule_store;

  return 0;
}

int bf_rules_set(bf_rule_store_t *rule_store, const char *key, int value) {
  size_t index = djb2(key, rule_store->capacity);
  bf_rule_t *iter_item = rule_store->rules[index];

  if (iter_item != NULL) {
    for (; iter_item->next != NULL; iter_item = iter_item->next) {
      if (strcmp(iter_item->key, key) == 0) {
        iter_item->type = value;
        return BF_OK;
      }
    }
  }

  bf_rule_t *new_item = calloc(1, sizeof(bf_rule_t));

  if (new_item == NULL)
    return BF_ERRNO;

  new_item->next = NULL;
  new_item->type = value;
  new_item->key = strdup(key);

  if (new_item->key == NULL) {
    free(new_item);
    return BF_ERRNO;
  }

  if (iter_item != NULL)
    iter_item->next = new_item;
  else
    rule_store->rules[index] = new_item;

  return BF_OK;
}

int bf_rules_get(bf_rule_store_t *rule_store, const char *key) {
  size_t index = djb2(key, rule_store->capacity);

  bf_rule_t *iter_item = rule_store->rules[index];

  if (iter_item == NULL)
    return BF_NOTFOUND;

  do {
    if (strcmp(iter_item->key, key) == 0)
      return iter_item->type;

    iter_item = iter_item->next;
  } while (iter_item);

  return BF_NOTFOUND;
}

int bf_rules_load_from_path(bf_rule_store_t *rule_store, const char *path,
                            const int type) {
  char line[PATH_MAX];

  FILE *fptr = fopen(path, "r");
  if (fptr == NULL)
    return BF_ERRNO;

  while (fgets(line, PATH_MAX, fptr) != NULL) {
    size_t len = strlen(line);
    char *end = strchr(line, '#');
    char *start = line;

    if (end == start)
      continue;

    if (end == NULL)
      end = line + len;

    end -= 1;

    if (len == 1 && isspace(*start))
      continue;

    while (isspace(*start) && start != end)
      start++;

    while (end > start && isspace(*end))
      end--;

    if (end == start)
      continue;

    *(end + 1) = '\0';

    int result = bf_rules_set(rule_store, start, type);

    if (result != BF_OK) {
      fclose(fptr);
      return result;
    }

    rule_store->length++;
  }

  return BF_OK;
}