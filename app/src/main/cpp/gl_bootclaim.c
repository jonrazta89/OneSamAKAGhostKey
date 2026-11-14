#define _GNU_SOURCE
#include "gl_bootclaim.h"
#include "gl_ksu_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define BOOT_STATE_PREFIX "boot_id="
#define BOOT_STATUS_PREFIX "status="
#define BOOT_UPTIME_PREFIX "uptime="
#define BOOT_MODE_PREFIX "mode="
#define BOOT_STATUS_RUNNING "running"

static const char *gl_boot_mode(void) {
  const char *m = getenv("GHOSTLOCK_NO_KSU");
  return (m && m[0] == '1') ? "noksu" : "ksu";
}

static int read_first_line_gl(const char *path, char *buf, size_t len) {
  if (!len) return -1;
  buf[0] = 0;
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return -1;
  ssize_t n = read(fd, buf, len - 1);
  close(fd);
  if (n <= 0) return -1;
  buf[n] = 0;
  char *nl = strchr(buf, '\n');
  if (nl) *nl = 0;
  return 0;
}

static int read_boot_state(const char *path, char *boot_out, size_t boot_sz,
                           char *status_out, size_t status_sz) {
  int fd = open(path, O_RDONLY | O_CLOEXEC);
  if (fd < 0) return 0;
  char buf[256];
  ssize_t n = read(fd, buf, sizeof(buf) - 1);
  close(fd);
  if (n <= 0) return 0;
  buf[n] = 0;
  char *line = buf;
  while (line && *line) {
    char *nl = strchr(line, '\n');
    if (nl) *nl = 0;
    if (strncmp(line, BOOT_STATE_PREFIX, strlen(BOOT_STATE_PREFIX)) == 0) {
      snprintf(boot_out, boot_sz, "%s", line + strlen(BOOT_STATE_PREFIX));
    } else if (strncmp(line, BOOT_STATUS_PREFIX, strlen(BOOT_STATUS_PREFIX)) == 0) {
      snprintf(status_out, status_sz, "%s", line + strlen(BOOT_STATUS_PREFIX));
    }
    line = nl ? nl + 1 : NULL;
  }
  return 1;
}

static void write_boot_state(const char *path, const char *boot_id, const char *status,
                             int create) {
  if (!create) {
    struct stat st;
    if (stat(path, &st) != 0) return;
  }
  char tmp[160];
  snprintf(tmp, sizeof(tmp), "%s.tmp", path);
  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    if (create) {
      fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
      if (fd < 0) return;
      dprintf(fd, "%s%s\n%s%s\n%s%s\n", BOOT_STATE_PREFIX, boot_id,
              BOOT_STATUS_PREFIX, status, BOOT_MODE_PREFIX, gl_boot_mode());
      close(fd);
    }
    return;
  }
  dprintf(fd, "%s%s\n%s%s\n%s%s\n", BOOT_STATE_PREFIX, boot_id,
          BOOT_STATUS_PREFIX, status, BOOT_MODE_PREFIX, gl_boot_mode());
  close(fd);
  rename(tmp, path);
}

static void probe_kernelsu_gl(void) {
  struct gl_ksu_get_info_cmd info;
  if (gl_ksu_probe_control(&info) == 0) {
    fprintf(stdout, "[bootclaim] kernelsu active: v=%u flags=0x%x features=%u\n",
            info.version, info.flags, info.features);
  }
}

int gl_boot_claim(int force) {
  char boot_id[64] = "unknown";
  read_first_line_gl("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id));

  char last_boot[64] = "";
  char last_status[32] = "";
  read_boot_state(GL_BOOT_STATE_PATH, last_boot, sizeof(last_boot),
                  last_status, sizeof(last_status));

  int same_boot = (strcmp(last_boot, boot_id) == 0);
  int unfinished = same_boot && strcmp(last_status, BOOT_STATUS_RUNNING) == 0;
  int rooted = same_boot && (strcmp(last_status, "0") == 0 ||
                             strcmp(last_status, "0-no-ksu") == 0);

  if (same_boot && (unfinished || rooted || last_status[0] != 0)) {
    if (!force) {
      if (rooted) {
        fprintf(stdout, "[bootclaim] current boot session already rooted: boot_id=%s\n", boot_id);
        probe_kernelsu_gl();
      } else if (unfinished) {
        fprintf(stdout, "[bootclaim] incomplete run for current boot: boot_id=%s\n", boot_id);
      } else {
        fprintf(stdout, "[bootclaim] previous run failed this boot: boot_id=%s status=%s\n",
                boot_id, last_status);
      }
      return 1; /* claimed/skip */
    }
    fprintf(stdout, "[bootclaim] same boot forcing run (status=%s)\n",
            last_status[0] ? last_status : "unknown");
  }

  write_boot_state(GL_BOOT_STATE_PATH, boot_id, BOOT_STATUS_RUNNING, 1);
  fprintf(stdout, "[bootclaim] boot claim acquired: boot_id=%s\n", boot_id);
  return 0;
}

void gl_boot_mark(int status) {
  char boot_id[64] = "unknown";
  read_first_line_gl("/proc/sys/kernel/random/boot_id", boot_id, sizeof(boot_id));

  char cur_boot[64] = "";
  char cur_status[32] = "";
  if (!read_boot_state(GL_BOOT_STATE_PATH, cur_boot, sizeof(cur_boot),
                       cur_status, sizeof(cur_status)) ||
      strcmp(cur_boot, boot_id) != 0 || strcmp(cur_status, BOOT_STATUS_RUNNING) != 0) {
    return;
  }
  char st[16];
  snprintf(st, sizeof(st), "%d", status);
  write_boot_state(GL_BOOT_STATE_PATH, boot_id, st, 0);
}
