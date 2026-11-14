#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <unistd.h>

#include "gl_ksu_proto.h"

/*
 * ghostlock-s26 su_daemon integrated into GhostKey.
 * Spawned by UMH post-UAF root path; provides temp_su.sock with:
 *  - 'K' + proto: KernelSU late-load exchange (ghostlock protocol)
 *  - 'C' + len + cmd: run command as root
 *  - other/'I': interactive shell
 */

#define GL_LOGCAT_PATH "/system/bin/logcat"

static volatile sig_atomic_t app_client_terminating;

static void terminate_app_client_group(int signo) {
  if (!app_client_terminating) {
    app_client_terminating = 1;
    pid_t group = getpgrp();
    if (group > 0) kill(-group, SIGKILL);
  }
  _exit(128 + signo);
}

static int install_app_client_lifetime_guard(void) {
  pid_t parent = getppid();
  if (setpgid(0, 0) != 0 && getpgrp() != getpid()) return 0;
  struct sigaction action;
  memset(&action, 0, sizeof(action));
  sigemptyset(&action.sa_mask);
  action.sa_handler = terminate_app_client_group;
  action.sa_flags = SA_RESETHAND;
  if (sigaction(SIGTERM, &action, NULL) != 0 || sigaction(SIGHUP, &action, NULL) != 0 ||
      sigaction(SIGINT, &action, NULL) != 0) return 0;
  if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0) return 0;
  if (parent <= 1 || getppid() != parent) terminate_app_client_group(SIGTERM);
  return 1;
}

static void set_root_env(void) {
  setenv("path",
         "/product/bin:/apex/com.android.runtime/bin:/apex/com.android.art/bin:"
         "/apex/com.android.virt/bin:/system_ext/bin:/system/bin:/system/xbin:"
         "/odm/bin:/vendor/bin:/vendor/xbin", 1);
  setenv("home", "/data/local/tmp", 1);
  setenv("user", "root", 1);
  setenv("logname", "root", 1);
}

static int verify_kernelsu_control(void) {
  struct gl_ksu_get_info_cmd info;
  int rc = gl_ksu_probe_control(&info);
  if (rc == -1) {
    dprintf(STDERR_FILENO, "kernelsu driver fd unavailable\n");
    return 0;
  }
  if (rc != 0) {
    dprintf(STDERR_FILENO, "kernelsu control failed errno=%d version=%u flags=0x%x\n",
            errno, info.version, info.flags);
    return 0;
  }
  dprintf(STDOUT_FILENO, "kernelsu verified version=%u flags=0x%x\n", info.version, info.flags);
  return 1;
}

static int wait_status(pid_t pid) {
  int status = 0;
  while (waitpid(pid, &status, 0) < 0) {
    if (errno != EINTR) return 1;
  }
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 1;
}

static void set_adb_selinux_ctx(void) {
  static const char ctx[] = "u:object_r:system_data_root_file:s0";
  setxattr(GL_KSU_ADB_DIR, "security.selinux", ctx, sizeof(ctx), 0);
}

static void xwrite_all(int fd, const void *buf, size_t len) {
  if (!gl_proto_write_all(fd, buf, len)) _exit(111);
}

static int run_kernelsu_late_load(int conn) {
  int pfd[2];
  if (pipe(pfd) != 0) return 1;
  pid_t worker = fork();
  if (worker < 0) { close(pfd[0]); close(pfd[1]); return 1; }
  if (worker == 0) {
    close(conn);
    close(pfd[0]);
    dup2(pfd[1], STDOUT_FILENO);
    dup2(pfd[1], STDERR_FILENO);
    if (pfd[1] > STDERR_FILENO) close(pfd[1]);

    set_adb_selinux_ctx();
    if (gl_ksu_stage_sync(GL_KSU_LOADER_PATH, GL_KSU_STAGE_PATH) < 0) {
      dprintf(STDERR_FILENO, "late-load: stage refresh failed\n");
    }
    if (unshare(CLONE_NEWNS) != 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: ns/mount failed: %s\n", strerror(errno));
      _exit(GL_KSU_LD_NS_FAIL);
    }
    if (mount(GL_KSU_LOADER_PATH, GL_LOGCAT_PATH, NULL, MS_BIND, NULL) != 0) {
      dprintf(STDERR_FILENO, "late-load: bind mount failed: %s\n", strerror(errno));
      _exit(GL_KSU_LD_BIND_FAIL);
    }
    pid_t loader = fork();
    if (loader < 0) _exit(GL_KSU_LD_EXEC_FAIL);
    if (loader == 0) {
      const char *as = getenv("ALLOW_SHELL");
      char *argv_allow[] = {"logcat", "late-load", "--allow-shell", "--kmi",
                            GL_KSU_KMI, "--package-name", "me.weishu.kernelsu", NULL};
      char *argv_norm[] = {"logcat", "late-load", "--kmi", GL_KSU_KMI,
                           "--package-name", "me.weishu.kernelsu", NULL};
      execv(GL_LOGCAT_PATH, (as && as[0] == '1') ? argv_allow : argv_norm);
      dprintf(STDERR_FILENO, "late-load: exec failed: %s\n", strerror(errno));
      _exit(GL_KSU_LD_EXEC_FAIL);
    }
    int st = wait_status(loader);
    if (st != 0) _exit(st);
    _exit(verify_kernelsu_control() ? 0 : GL_KSU_LD_VERIFY_FAIL);
  }
  close(pfd[1]);

  char buf[4096];
  for (;;) {
    ssize_t n = read(pfd[0], buf, sizeof(buf));
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) break;
    uint32_t cl = (uint32_t)n;
    xwrite_all(conn, &cl, sizeof(cl));
    xwrite_all(conn, buf, (size_t)n);
  }
  close(pfd[0]);
  int st = wait_status(worker);
  uint32_t end = 0;
  uint32_t stw = (uint32_t)st;
  xwrite_all(conn, &end, sizeof(end));
  xwrite_all(conn, &stw, sizeof(stw));
  return st;
}

static void relabel_socket_path(const char *path) {
  static const char ctx[] = "u:object_r:shell_data_file:s0";
  setxattr(path, "security.selinux", ctx, sizeof(ctx) - 1, 0);
}

static void set_process_ctx(void) {
  static const char ctx[] = "u:r:kernel:s0";
  int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
  if (fd >= 0) { write(fd, ctx, sizeof(ctx) - 1); close(fd); }
}

static int xread_exact(int fd, void *buf, size_t len) {
  char *p = (char *)buf;
  while (len) {
    ssize_t n = read(fd, p, len);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return 0;
    p += n; len -= (size_t)n;
  }
  return 1;
}

static void handle_conn(int conn) {
  uint8_t req0 = 0;
  if (read(conn, &req0, 1) != 1) return;
  if (req0 == 'K') {
    uint8_t ver = GL_KSU_PROTO_VERSION;
    read(conn, &ver, 1); /* consume proto version if sent */
    run_kernelsu_late_load(conn);
    return;
  }
  if (req0 == 'C') {
    uint32_t len = 0;
    if (!xread_exact(conn, &len, sizeof(len)) || len == 0 || len > 65536) return;
    char *cmd = malloc(len + 1);
    if (!cmd) return;
    if (!xread_exact(conn, cmd, len)) { free(cmd); return; }
    cmd[len] = 0;
    pid_t pid = fork();
    if (pid == 0) {
      dup2(conn, STDOUT_FILENO);
      dup2(conn, STDERR_FILENO);
      close(conn);
      set_root_env();
      execl("/system/bin/sh", "sh", "-c", cmd, NULL);
      _exit(127);
    }
    free(cmd);
    if (pid > 0) waitpid(pid, NULL, 0);
    return;
  }
  /* Interactive shell */
  pid_t pid = fork();
  if (pid == 0) {
    dup2(conn, STDIN_FILENO);
    dup2(conn, STDOUT_FILENO);
    dup2(conn, STDERR_FILENO);
    close(conn);
    set_root_env();
    execl("/system/bin/sh", "sh", NULL);
    _exit(127);
  }
  if (pid > 0) waitpid(pid, NULL, 0);
}

static void daemon_serve(int fd) {
  for (;;) {
    int conn = accept(fd, NULL, NULL);
    if (conn < 0) { if (errno == EINTR) continue; break; }
    pid_t pid = fork();
    if (pid == 0) {
      close(fd);
      handle_conn(conn);
      close(conn);
      _exit(0);
    }
    close(conn);
    if (pid > 0) { int st; while (waitpid(-1, &st, WNOHANG) > 0) {} }
  }
}

int gl_su_daemon_main(int argc, char **argv) {
  (void)argc; (void)argv;
  install_app_client_lifetime_guard();
  set_process_ctx();
  set_root_env();

  int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd < 0) { perror("socket"); return 1; }
  unlink(GL_KSU_SOCK_PATH);
  struct sockaddr_un sun;
  memset(&sun, 0, sizeof(sun));
  sun.sun_family = AF_UNIX;
  snprintf(sun.sun_path, sizeof(sun.sun_path), "%s", GL_KSU_SOCK_PATH);
  if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) != 0) {
    perror("bind"); close(fd); return 1;
  }
  chmod(GL_KSU_SOCK_PATH, 0666);
  relabel_socket_path(GL_KSU_SOCK_PATH);
  if (listen(fd, 8) != 0) { perror("listen"); close(fd); return 1; }
  fprintf(stdout, "[gl_su_daemon] listening %s pid=%d uid=%d\n",
          GL_KSU_SOCK_PATH, getpid(), getuid());
  fflush(stdout);
  daemon_serve(fd);
  close(fd);
  unlink(GL_KSU_SOCK_PATH);
  return 0;
}
