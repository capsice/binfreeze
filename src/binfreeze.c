/*
 * Copyright (c) 2023 Félix Picón <felix@iceca.ps>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"

typedef struct {
  size_t ln_rules;
  size_t sz_rules;
  bool sorted;
  char **buf;
} rule_vec_t;

enum MODE { ALLOW, BLOCK, GENERATING };

static bool block_on_change = true;
static bool is_generating = false;
static char *allow_conf = NULL;
static char *block_conf = NULL;

static void print_usage(int exit_code) {

  char usage[] =
      "usage: %s [options]\n"
      "options:\n"
      "\t-g              generate config to stdout\n"
      "\t-a <conf>       specify configuration file for programs to allow\n"
      "\t-b <conf>       specify configuration file for programs to block\n"
      "\t-n              do not block executables if they change\n"
      "\t-h              show this usage information\n"
      "\t-v              show version\n";

  printf(usage, BF_NAME);
  exit(exit_code);
}

static void print_version(void) {
  printf("%s %s\n", BF_NAME, BF_VERSION);
  exit(EXIT_SUCCESS);
}

static int cmp_rules(const void *a, const void *b) {
  return strcmp(*(char **)a, *(char **)b);
}

static int add_rule(rule_vec_t *rules, char *path) {

  if (rules->ln_rules == rules->sz_rules) {
    char **tmp = realloc(rules->buf, rules->sz_rules * 2 * sizeof(char *));

    if (tmp == NULL) {
      return -1;
    }

    rules->sz_rules *= 2;
    rules->buf = tmp;
  }

  for (size_t i = 0; i < rules->ln_rules; i++) {
    if (strcmp(path, rules->buf[i]) == 0) {
      return 0;
    }
  }

  char *dup = strdup(path);
  if (dup == NULL) {
    return -1;
  }

  rules->buf[rules->ln_rules++] = dup;
  rules->sorted = false;

  return 0;
}

static ssize_t load_rules(rule_vec_t *rules, const char *filepath) {
  char line[PATH_MAX];
  ssize_t rules_loaded = 0;

  FILE *fptr = fopen(filepath, "r");

  if (fptr == NULL) {
    return -1;
  }

  while (fgets(line, PATH_MAX, fptr) != NULL) {
    size_t len = strlen(line);
    char *end = strchr(line, '#');
    char *start = line;

    if (end == start) {
      continue;
    }

    if (end == NULL) {
      end = line + len;
    }

    end -= 1;

    if (len == 1 && isspace(*start)) {
      continue;
    }

    while (isspace(*start) && start != end) {
      start++;
    }

    while (end > start && isspace(*end)) {
      end--;
    }

    if (end == start) {
      continue;
    }

    *(end + 1) = '\0';

    rules_loaded++;

    puts(start);

    if (add_rule(rules, start) == -1) {
      fclose(fptr);
      return -1;
    }
  }

  qsort(rules->buf, rules->ln_rules, sizeof(char *), cmp_rules);
  rules->sorted = true;

  return rules_loaded;
}

static rule_vec_t *init_rules(const char *filepath) {

  rule_vec_t *rules = malloc(sizeof(rule_vec_t));

  if (rules == NULL) {
    return NULL;
  }

  char **rulebuf = malloc(4096 * sizeof(char *));

  if (rulebuf == NULL) {
    free(rules);
    return NULL;
  }

  rules->ln_rules = 0;
  rules->sz_rules = 4096;
  rules->sorted = false;
  rules->buf = rulebuf;

  if (filepath != NULL && load_rules(rules, filepath) == -1) {
    free(rules->buf);
    free(rules);
    return NULL;
  }

  return rules;
}

static char *get_rule(rule_vec_t *rules, const char *path) {
  if (!rules->sorted) {
    qsort(rules->buf, rules->ln_rules, sizeof(char *), cmp_rules);
    rules->sorted = true;
  }

  char **result =
      bsearch(&path, rules->buf, rules->ln_rules, sizeof(char *), cmp_rules);

  if (result != NULL) {
    return *result;
  }

  return NULL;
}

static int add_mounts(int fan) {
  FILE *mounts = setmntent("/proc/self/mounts", "r");

  if (mounts == NULL) {
    err(EXIT_FAILURE, "setmntent");
  }

  int rc = 0;
  struct mntent *mount = NULL;
  uint64_t fan_flags = FAN_MARK_ADD | FAN_MARK_MOUNT;
  uint64_t fan_mask = FAN_OPEN_EXEC_PERM | FAN_CLOSE_WRITE;

  while ((mount = getmntent(mounts)) != NULL) {

    if (mount->mnt_fsname == NULL || access(mount->mnt_dir, F_OK) == -1 ||
        strcmp(mount->mnt_type, "proc") == 0) {
      continue;
    }

    rc = fanotify_mark(fan, fan_flags, fan_mask, AT_FDCWD, mount->mnt_dir);

    // errno is set to EINVAL if the mount type is unsupported
    // in this case, we simply ignore it
    if (rc < 0) {

      if (errno != EINVAL) {
        perror("fanotify_mark");
        break;
      }

      rc = 0;
    }
  }

  endmntent(mounts);
  return rc;
}

static ssize_t get_fan_ev_path(const struct fanotify_event_metadata *metadata,
                               char *path, size_t sz_path) {
  char procfd_path[PATH_MAX];

  if (path == NULL || metadata == NULL) {
    errno = EINVAL;
    return -1;
  }

  snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", metadata->fd);

  ssize_t len = readlink(procfd_path, path, sz_path - 1);

  if (len == -1) {
    perror("readlink");
    return -1;
  }

  path[len] = '\0';

  return len;
}

static bool should_block_file(const char *path, rule_vec_t *allowed_rules) {
  if (!block_on_change) {
    return false;
  }

  if (allowed_rules == NULL) {
    return false;
  }

  return get_rule(allowed_rules, path) != NULL;
}

static int handle_fan_ev(int fan,
                         const struct fanotify_event_metadata *metadata,
                         rule_vec_t *rules[3]) {

  struct fanotify_response response;
  char path[PATH_MAX];
  ssize_t ln_path;

  response.response = FAN_ALLOW; // allow by default

  ln_path = get_fan_ev_path(metadata, path, PATH_MAX);

  if (ln_path == -1) {
    close(metadata->fd);
    return -1;
  }

  // A file has been updated
  if (!(metadata->mask & FAN_OPEN_EXEC_PERM)) {

    if (should_block_file(path, rules[ALLOW])) {
      add_rule(rules[BLOCK], path);
    }

    close(metadata->fd);
    return 0;
  }

  response.fd = metadata->fd;

  if (is_generating) {
    bool rule_exists = get_rule(rules[GENERATING], path) != NULL;

    if (!rule_exists) {
      fprintf(stdout, "%s\n", path);
      add_rule(rules[GENERATING], path);
    }

    response.response = FAN_ALLOW;
    goto write_response;
  }

  bool is_path_blocked = get_rule(rules[BLOCK], path) != NULL;

  if (is_path_blocked) {
    syslog(LOG_NOTICE, "blocked execution attempt by pid %d: %s", metadata->pid,
           path);

    response.response = FAN_DENY;
    goto write_response;
  }

  if (rules[ALLOW] != NULL) {
    bool is_path_allowed = get_rule(rules[ALLOW], path) != NULL;

    if (!is_path_allowed) {
      syslog(LOG_NOTICE, "blocked execution attempt by pid %d: %s",
             metadata->pid, path);
      response.response = FAN_DENY;
    }
  }

write_response:
  write(fan, &response, sizeof(response));
  close(metadata->fd);
  return 0;
}

static void parse_opt(int argc, char *const *argv) {
  int opt;

  while ((opt = getopt(argc, argv, "hgvna:b:")) != -1) {
    switch (opt) {
    case 'g':
      is_generating = true;
      break;
    case 'a':
      allow_conf = strdup(optarg);
      if (allow_conf == NULL) {
        err(EXIT_FAILURE, "strdup");
      }
      break;
    case 'b':
      block_conf = strdup(optarg);
      if (block_conf == NULL) {
        err(EXIT_FAILURE, "strdup");
      }
      break;
    case 'h':
      print_usage(EXIT_SUCCESS);
      break;
    case 'v':
      print_version();
      break;
    case 'n':
      block_on_change = false;
      break;
    case '?':
    default:
      print_usage(EXIT_FAILURE);
    }
  }

  // there's nothing for us to do
  if (allow_conf == NULL && block_conf == NULL && is_generating == false) {
    print_usage(EXIT_FAILURE);
  }

  if (is_generating && (allow_conf != NULL || block_conf != NULL)) {
    fprintf(stderr, "-g flag may not be used with -a or -b.\n");
    print_usage(EXIT_FAILURE);
  }
}

int main(int argc, char *const *argv) {

  parse_opt(argc, argv);
  const struct fanotify_event_metadata *metadata, buf[200];
  rule_vec_t *rules[3] = {[ALLOW] = NULL, [BLOCK] = NULL, [GENERATING] = NULL};

  int fan = fanotify_init(FAN_CLOEXEC | FAN_CLASS_CONTENT, O_RDONLY);

  if (fan == -1) {
    if (errno == EPERM) {
      errx(EXIT_FAILURE, "you need to run this program as root.");
    } else {
      err(EXIT_FAILURE, "fanotify_init");
    }
  }

  if (add_mounts(fan) == -1) {
    err(EXIT_FAILURE, "add_mounts");
  }

  // We initialize this one regardless of block_conf being null
  // because we will use it to block executables that have changed after the
  // program started running
  rules[BLOCK] = init_rules(block_conf);
  if (rules[BLOCK] == NULL) {
    err(EXIT_FAILURE, "init_rules");
  }

  if (is_generating) {
    rules[GENERATING] = init_rules(NULL);
    if (rules[GENERATING] == NULL) {
      err(EXIT_FAILURE, "init_rules");
    }
  }

  if (allow_conf != NULL) {
    rules[ALLOW] = init_rules(allow_conf);
    if (rules[ALLOW] == NULL) {
      err(EXIT_FAILURE, "init_rules");
    }
  }

  for (;;) {
    ssize_t rc = read(fan, (void *)buf, sizeof(buf));

    if (rc == -1) {
      err(EXIT_FAILURE, "read");
    }

    if (rc == 0) {
      errx(EXIT_FAILURE, "fanotify file descriptor was closed");
    }

    metadata = buf;

    while (FAN_EVENT_OK(metadata, rc)) {
      if (metadata->vers != FANOTIFY_METADATA_VERSION) {
        errx(EXIT_FAILURE, "mismatch of fanotify metadata version: %d & %d.",
             metadata->vers, FANOTIFY_METADATA_VERSION);
      }

      if (metadata->fd < 0) {
        metadata = FAN_EVENT_NEXT(metadata, rc);
        continue;
      }

      if (handle_fan_ev(fan, metadata, rules) == -1) {
        err(EXIT_FAILURE, "handle_fan_ev");
      }

      metadata = FAN_EVENT_NEXT(metadata, rc);
    }
  }

  return 0;
}