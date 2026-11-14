#ifndef GL_BOOTCLAIM_H
#define GL_BOOTCLAIM_H

/*
 * Ghostlock-s26 style boot claim/state tracking (integrated into GhostKey).
 * Prevents re-exploitation attempts in the same boot session when appropriate.
 */

#define GL_BOOT_STATE_PATH "/data/local/tmp/ghostlock-boot.log"

int gl_boot_claim(int force);
void gl_boot_mark(int status);

#endif /* GL_BOOTCLAIM_H */
