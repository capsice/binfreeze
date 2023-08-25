#include "binfreeze.h"

#include "config.h"
#include "rules.h"

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mntent.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/fanotify.h>
#include <sys/poll.h>
#include <syslog.h>
#include <unistd.h>

static bool is_verbose = false;
static char *allow_conf = NULL;
static char *deny_conf = NULL;

static const char *blocked_exec_fmt =
    "blocking execution attempt of %s by pid %d\n";

static const char *blocked_update_fmt = "blocking file '%s' due to changes\n";

static void parse_opt(int argc, char *const *argv);

static void event_loop(struct pollfd *pfds, int nfds,
                       bf_rule_store_t *rule_store);

static int mark_all_mounts(int fanotify_fd, int flags, uint64_t mask);

int main(int argc, char *const *argv) {

  enum { NFDS = 2 };

  parse_opt(argc, argv);

  int result = BF_OK;
  struct pollfd pfds[NFDS];
  bf_rule_store_t *rule_store;

  int watch_fd = fanotify_init(
      FAN_CLASS_NOTIF | FAN_REPORT_DFID_NAME | FAN_NONBLOCK, O_RDONLY);

  if (watch_fd == -1)
    err(EXIT_FAILURE, "fanotify_init");

  int intercept_fd = fanotify_init(FAN_CLASS_CONTENT | FAN_NONBLOCK, O_RDONLY);

  if (intercept_fd == -1)
    err(EXIT_FAILURE, "fanotify_init");

  pfds[0].events = pfds[1].events = POLLIN;
  pfds[0].fd = watch_fd;
  pfds[1].fd = intercept_fd;

  if (bf_rules_create(&rule_store) != BF_OK)
    err(EXIT_FAILURE, "bf_rules_create");

  if (allow_conf != NULL)
    result = bf_rules_load_from_path(rule_store, allow_conf, BF_RULE_ALLOW);

  if (result == BF_OK && deny_conf != NULL)
    result = bf_rules_load_from_path(rule_store, deny_conf, BF_RULE_DENY);

  if (result != BF_OK)
    err(EXIT_FAILURE, "bf_rules_load_from_path");

  result = mark_all_mounts(watch_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                           FAN_CREATE | FAN_MODIFY | FAN_MOVE);

  if (result == BF_OK)
    result = mark_all_mounts(intercept_fd, FAN_MARK_ADD | FAN_MARK_FILESYSTEM,
                             FAN_OPEN_EXEC_PERM);

  if (result != BF_OK)
    err(EXIT_FAILURE, "bf_mounts_mark_all");

  event_loop(pfds, NFDS, rule_store);

  return EXIT_SUCCESS;
}

static void print_usage(int exit_code) {

  if (exit_code != EXIT_FAILURE)
    puts(BF_NAME " " BF_VERSION);

  char usage[] = "usage: %s [options]\n"
                 "options:\n"
                 "\t-v              run in verbose mode\n"
                 "\t-h              show this usage information\n"
                 "\t-a <conf>       specify a configuration file to allow the "
                 "execution of programs\n"
                 "\t-d <conf>       specify a configuration file to deny the "
                 "execution of programs\n";

  FILE *buf = exit_code == EXIT_FAILURE ? stderr : stdout;

  fprintf(buf, usage, BF_NAME);
  exit(exit_code);
}

static void parse_opt(int argc, char *const *argv) {
  int opt;

  while ((opt = getopt(argc, argv, "hva:d:")) != -1) {
    switch (opt) {

    case 'a':
      allow_conf = strdup(optarg);

      if (allow_conf == NULL)
        err(EXIT_FAILURE, "strdup");

      break;

    case 'd':
      deny_conf = strdup(optarg);

      if (deny_conf == NULL)
        err(EXIT_FAILURE, "strdup");

      break;

    case 'h':
      print_usage(EXIT_SUCCESS);
      break;

    case 'v':
      is_verbose = true;
      break;

    case '?':
    default:
      print_usage(EXIT_FAILURE);
    }
  }

  if (allow_conf == NULL && deny_conf == NULL) {
    fprintf(stderr, "please specify rules with -a and -d\n");
    print_usage(EXIT_FAILURE);
  }
}

static int mark_all_mounts(int fanotify_fd, int flags, uint64_t mask) {
  FILE *mounts = setmntent("/proc/self/mounts", "r");

  if (mounts == NULL)
    return BF_ERRNO;

  struct mntent *mount = NULL;

  while ((mount = getmntent(mounts)) != NULL) {
    if (mount->mnt_fsname == NULL || access(mount->mnt_dir, F_OK) == -1)
      continue;

    int result =
        fanotify_mark(fanotify_fd, flags, mask, AT_FDCWD, mount->mnt_dir);

    if (result < 0 && errno != EINVAL && errno != ENODEV) {
      endmntent(mounts);
      return BF_ERRNO;
    }
  }

  endmntent(mounts);

  return BF_OK;
}

static int get_event_path(int fd, char *path, size_t sz_path) {
  char procfd_path[PATH_MAX];

  if (path == NULL) {
    errno = EINVAL;
    return -1;
  }

  snprintf(procfd_path, sizeof(procfd_path), "/proc/self/fd/%d", fd);
  if (realpath(procfd_path, path) == NULL)
    return BF_ERRNO;

  return BF_OK;
}

static int get_fid_event_fd(const struct fanotify_event_info_fid *fid) {

  int event_fd = open_by_handle_at(AT_FDCWD, (struct file_handle *)fid->handle,
                                   O_RDONLY | O_PATH);

  if (event_fd < 0)
    return BF_ERRNO;

  return event_fd;
}

static int
handle_fan_exec_perm_event(int fanotify_fd,
                           const struct fanotify_event_metadata *metadata,
                           bf_rule_store_t *rule_store) {
  struct fanotify_response response;
  response.fd = metadata->fd;
  char event_path[PATH_MAX];

  if (get_event_path(metadata->fd, event_path, PATH_MAX) == -1) {
    close(metadata->fd);
    return BF_ERRNO;
  }

  int type = bf_rules_get(rule_store, event_path);

  response.response = FAN_ALLOW;

  if (type == BF_RULE_DENY || (type == BF_NOTFOUND && allow_conf != NULL)) {

    response.response = FAN_DENY;

    syslog(LOG_NOTICE, blocked_exec_fmt, event_path, metadata->pid);

    if (is_verbose)
      printf(blocked_exec_fmt, event_path, metadata->pid);
  }

  write(fanotify_fd, &response, sizeof(response));
  close(metadata->fd);
  return BF_OK;
}

static int
handle_fan_change_event(int fanotify_fd,
                        const struct fanotify_event_metadata *metadata,
                        bf_rule_store_t *rule_store) {

  struct fanotify_event_info_fid *fid =
      (struct fanotify_event_info_fid *)(metadata + 1);

  if (fid->hdr.info_type == FAN_EVENT_INFO_TYPE_FID ||
      fid->hdr.info_type == FAN_EVENT_INFO_TYPE_DFID)
    return BF_OK;

  int event_fd = get_fid_event_fd(fid);

  if (event_fd == BF_ERRNO) {
    if (errno == ESTALE)
      return BF_OK;

    return event_fd;
  }

  size_t ln_event_path;
  char event_path[PATH_MAX];

  if (get_event_path(event_fd, event_path, PATH_MAX) != BF_OK) {
    close(event_fd);
    return BF_OK;
  }

  ln_event_path = strlen(event_path);
  struct file_handle *file_handle = (struct file_handle *)fid->handle;
  unsigned char *filename = (file_handle->f_handle + file_handle->handle_bytes);
  snprintf(event_path + ln_event_path, PATH_MAX - ln_event_path, "/%s",
           (char *)filename);

  int result = BF_OK;

  if (bf_rules_get(rule_store, event_path) == BF_RULE_ALLOW) {
    result = bf_rules_set(rule_store, event_path, BF_RULE_DENY);

    syslog(LOG_NOTICE, blocked_update_fmt, event_path);

    if (is_verbose)
      printf(blocked_update_fmt, event_path);
  }

  close(event_fd);
  return result;
}

void event_loop(struct pollfd *pfds, int nfds, bf_rule_store_t *rule_store) {

  enum { FAN_EVENTS_CAPACITY = 4096 };

  const struct fanotify_event_metadata *metadata,
      fan_events_buf[FAN_EVENTS_CAPACITY];

  for (;;) {
    int num = poll(pfds, nfds, -1);

    if (num < 1)
      err(EXIT_FAILURE, "poll");

    for (int i = 0; i < nfds; i++) {
      if (pfds[i].revents & ~POLLIN)
        continue;

      for (;;) {
        int rc =
            read(pfds[i].fd, (void *)fan_events_buf, sizeof(fan_events_buf));

        if (rc < 0) {
          if (errno == EAGAIN)
            break;

          err(EXIT_FAILURE, "read");
        }

        metadata = fan_events_buf;

        while (FAN_EVENT_OK(metadata, rc)) {

          int result;
          if (metadata->mask & FAN_OPEN_EXEC_PERM)
            result =
                handle_fan_exec_perm_event(pfds[i].fd, metadata, rule_store);
          else
            result = handle_fan_change_event(pfds[i].fd, metadata, rule_store);

          if (result != BF_OK)
            err(EXIT_FAILURE, "handle_fan_event");

          metadata = FAN_EVENT_NEXT(metadata, rc);
        }
      }
    }
  }
}
