#ifndef SHP_HOOK_H
#define SHP_HOOK_H

#include <cstdio>
#include <cstdint>
#include <mutex>
#include <thread>
#include <chrono>
#include <vector>
#include <iostream>
#include <shared_mutex>
#include <unordered_map>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <pthread.h>
#include <ucontext.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <sys/unistd.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <android/log.h>
typedef enum { LOOP_ON = 1, LOOP_OFF = 0 } mprotect_mode;
typedef enum { TMPREG_ON = 1, TMPREG_ON_FKBTI = 2, TMPREG_OFF = 0 } shadowpage_mode;

typedef struct _mode { mprotect_mode mode; unsigned int time; } mprotect_mode_t;
typedef struct _mode2 { shadowpage_mode mode; unsigned int reg; } shadowpage_mode_t;

void shadowpage_patch_insn64(void *addr, uint64_t new_opcode);
void shadowpage_patch_insn(void *addr, int new_opcode);
typedef void (*__callback__)(ucontext_t *uc, mcontext_t *ctx, fpsimd_context *vctx);
void shadowpage_hook(void *addr, void *fake, void **orig);
void shadowpage_hookctx(void *addr, __callback__ precallback);
void shadowpage_hookinit(shadowpage_mode_t mode, mprotect_mode_t mode2, bool svchook);



#define bit(obj,st) (((obj) >> (st)) & 1)
#define submask(x) ((1L << ((x) + 1)) - 1)
#define bits(obj,st,fn) (((obj) >> (st)) & submask ((fn) - (st)))
#define sbits(obj,st,fn) ((long) (bits(obj,st,fn) | ((long) bit(obj,fn) * ~ submask (fn - st))))
#define align_down(x, n) ((x) & ~(n - 1))
#define align_up(x, n) (((x) + n - 1) & ~(n - 1))
#define __cache_clear __builtin___clear_cache
#define LOG(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG, "TestHook", fmt, ##__VA_ARGS__)

#endif // SHP_HOOK_H