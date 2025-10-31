#include "SHPHook.h"



volatile unsigned int TMPREG = 17;
shadowpage_mode CurrentMode = TMPREG_OFF;
size_t current_offset = 0;
std::mutex mem_mutex;
std::mutex mem_perm_mutex;
// 8mb
constexpr size_t MEMORY_POOL_SIZE = 8 * 1024 * 1024;
alignas(16384) volatile constexpr unsigned char MEMORY_POOL[MEMORY_POOL_SIZE] = {0};

bool memory_pool_read_exec()
{
    uintptr_t pool_start = (uintptr_t)MEMORY_POOL;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t aligned_start = pool_start & ~(page_size - 1);
    uintptr_t aligned_end = (pool_start + MEMORY_POOL_SIZE + page_size - 1) & ~(page_size - 1);

    if (mprotect((void*)aligned_start, (aligned_end - aligned_start), PROT_READ | PROT_EXEC) != 0)
        return false;

    __cache_clear((char*)MEMORY_POOL, (char*)MEMORY_POOL + MEMORY_POOL_SIZE);
    return true;
}

bool memory_pool_read_write_exec()
{
    uintptr_t pool_start = (uintptr_t)MEMORY_POOL;
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t aligned_start = pool_start & ~(page_size - 1);
    uintptr_t aligned_end = (pool_start + MEMORY_POOL_SIZE + page_size - 1) & ~(page_size - 1);

    if (mprotect((void*)aligned_start, (aligned_end - aligned_start), PROT_READ | PROT_WRITE | PROT_EXEC) != 0)
        return false;

    __cache_clear((char*)MEMORY_POOL, (char*)MEMORY_POOL + MEMORY_POOL_SIZE);
    return true;
}

void *memalloc(size_t size)
{
    void *allocated_memory = nullptr;
    {
        std::lock_guard<std::mutex> lock(mem_mutex);

        constexpr size_t ALIGNMENT = 32;
        size = (size + ALIGNMENT - 1) & ~(ALIGNMENT - 1);

        if (current_offset + size > MEMORY_POOL_SIZE) return nullptr;

        allocated_memory = (void *)(MEMORY_POOL + current_offset);
        current_offset += size;
    }
    return allocated_memory;
}

/*------------------------------------------------bypass------------------------------------------------*/

static std::vector<int> GetProcessTask(int pid)
{
    std::vector<int> vOutput;
    DIR* dir = nullptr;
    struct dirent* ptr = nullptr;
    char szTaskPath[256] = {0};
    sprintf(szTaskPath, "/proc/%d/task", pid);

    dir = opendir(szTaskPath);
    if (nullptr != dir) {
        while ((ptr = readdir(dir)) != nullptr)
        {
            if ((strcmp(ptr->d_name, ".") == 0) || (strcmp(ptr->d_name, "..") == 0)) {
                continue;
            } else if (ptr->d_type != DT_DIR) {
                continue;
            } else if (strspn(ptr->d_name, "1234567890") != strlen(ptr->d_name)) {
                continue;
            }

            int task = atoi(ptr->d_name);
            char buff[1024];
            sprintf(buff, "/proc/%d/task/%d/comm", pid, task);
            FILE* fp = fopen(buff, "r");
            if (fp) {
                char name[1024] = {0};
                fgets(name, sizeof(name), fp);
                fclose(fp);
                std::string namestr = name;
                vOutput.push_back(task);
            }
        }
        closedir(dir);
    }
    return vOutput;
}

void sys_handler(int signum, siginfo_t *info, void *context)
{
    if (signum != SIGSYS) return;

    ucontext_t *uc = (ucontext_t *)context;
    mcontext_t *ctx = &uc->uc_mcontext;
}

void install_seccomp_bpf_handler(int signum, siginfo_t *info, void *context)
{
    {
        sigset_t set;
        sigemptyset(&set);
        pthread_sigmask(SIG_SETMASK, &set, 0);
    }
    {
        prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        
        struct sock_filter filter[] = {
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigprocmask, 7, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_rt_sigaction, 0, 5),

            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGILL, 4, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGSYS, 3, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGSEGV, 2, 0),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SIGTRAP, 1, 0),
            
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM)
        };

        struct sock_fprog prog = { .len = sizeof(filter) / sizeof(filter[0]), .filter = filter };
        
        prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog);
    }
}

/*------------------------------------------------指令类型------------------------------------------------*/

typedef enum {
    OTHER = 0,
    B,
    B_COND,
    BL,
    ADR,
    ADRP,
    LDR_LIT_32,
    LDR_LIT_64,
    LDRSW_LIT,
    PRFM_LIT,
    LDR_LIT_S_32,
    LDR_LIT_D_64,
    LDR_LIT_Q_128,
    CBZ,
    CBNZ,
    TBZ,
    TBNZ
} insnwitchpctype;

static insnwitchpctype isinsnwitchpc(uint32_t insn)
{
    if ((insn & 0xFC000000u) == 0x14000000u) return B;
    if ((insn & 0xFF000010u) == 0x54000000u) return B_COND;
    if ((insn & 0xFC000000u) == 0x94000000u) return BL;
    if ((insn & 0x9F000000u) == 0x10000000u) return ADR;
    if ((insn & 0x9F000000u) == 0x90000000u) return ADRP;
    if ((insn & 0xFF000000u) == 0x18000000u) return LDR_LIT_32;
    if ((insn & 0xFF000000u) == 0x58000000u) return LDR_LIT_64;
    if ((insn & 0xFF000000u) == 0x98000000u) return LDRSW_LIT;
    if ((insn & 0xFF000000u) == 0xD8000000u) return PRFM_LIT;
    if ((insn & 0xFF000000u) == 0x1C000000u) return LDR_LIT_S_32;
    if ((insn & 0xFF000000u) == 0x5C000000u) return LDR_LIT_D_64;
    if ((insn & 0xFF000000u) == 0x9C000000u) return LDR_LIT_Q_128;
    if ((insn & 0x7F000000u) == 0x34000000u) return CBZ;
    if ((insn & 0x7F000000u) == 0x35000000u) return CBNZ;
    if ((insn & 0x7F000000u) == 0x36000000u) return TBZ;
    if ((insn & 0x7F000000u) == 0x37000000u) return TBNZ;
    return OTHER;
}

/*------------------------------------------------影子页------------------------------------------------*/

struct trapinfo {
    int type;
    uintptr_t addr;
    trapinfo(int a = 0, uintptr_t b = 0) : type(a), addr(b) {}
};

struct shadowpageinfo {
    uintptr_t shadowpage;
    shadowpageinfo(uintptr_t a = 0) : shadowpage(a) {}
};

std::unordered_map<uintptr_t, trapinfo> TrapMap;
std::unordered_map<uintptr_t, shadowpageinfo> PageMap;

//--------------------------------------------软中断处理

void trap_handler(int signum, siginfo_t *info, void *context)
{
    if (signum != SIGTRAP) return;

    ucontext_t *uc = (ucontext_t *)context;
    mcontext_t *ctx = &uc->uc_mcontext;

    if (auto it = TrapMap.find(ctx->pc); it != TrapMap.end()) {
        switch (it->second.type) {
            case 1: {
                ctx->pc = it->second.addr;
                break;
            }
            case 2: {
                // 写的太烂了 删了
                break;
            }
            case 3: {
                ctx->pc += 0x4;

                struct fpsimd_context *vctx = {};

                char *unkctx = (char *)&uc->uc_mcontext.__reserved;
                while (unkctx < ((char *)&uc->uc_mcontext.__reserved + sizeof(uc->uc_mcontext.__reserved))) {
                    struct _aarch64_ctx *ctx = (struct _aarch64_ctx *)unkctx;
                    if (ctx->magic == FPSIMD_MAGIC) {
                        vctx = (struct fpsimd_context *)ctx;
                        break;
                    }
                    unkctx += ctx->size;
                }

                auto callback = reinterpret_cast<__callback__>(it->second.addr);
                callback(uc, ctx, vctx);
                break;
            }
            case 4: {
                uint64_t reg = (it->second.addr >> 48);
                uint64_t addr = (it->second.addr << 16) >> 16;
                *(uint64_t *)addr = ctx->regs[reg];
                break;
            }
            case 5: {
                uint64_t reg = (it->second.addr >> 48);
                uint64_t addr = (it->second.addr << 16) << 16;
                ctx->regs[reg] = *(uint64_t *)addr;
                break;
            }
            default: {
                syscall(__NR_exit_group);
                break;
            }
        }
        return;
    }
}

//--------------------------------------------转移到影子页

void segv_handler(int signum, siginfo_t *info, void *context)
{
    if (signum != SIGSEGV) return;

    ucontext_t *uc = (ucontext_t *)context;
    mcontext_t *ctx = &uc->uc_mcontext;

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t page_start = align_down((uintptr_t)ctx->pc, page_size);

    if (auto it = PageMap.find(page_start); it != PageMap.end()) {
        size_t offset = ctx->pc - page_start;
        ctx->pc = it->second.shadowpage + offset;
        return;
    }
}

//--------------------------------------------创建影子页

uintptr_t create_shadowpage(uintptr_t pc)
{
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t orig_page_start = align_down(pc, page_size);

    if (auto it = PageMap.find(orig_page_start); it != PageMap.end()) {
        return it->second.shadowpage;
    }

    uintptr_t shadow_page = (uintptr_t)memalloc(0x100000);
    if (!shadow_page) {
        kill(getpid(), SIGABRT);
    }

    PageMap[orig_page_start] = {shadow_page};
    uintptr_t shadow_page_result = shadow_page;
    uintptr_t extraspace = shadow_page + page_size;

    // next page  衔接
    *(uint32_t *)(extraspace + 0x0) = 0xd4200000u; // BRK #0
    TrapMap[extraspace + 0x0] = {1, orig_page_start + page_size};
    extraspace += 0x4;

    bool bypassbti = CurrentMode == TMPREG_ON_FKBTI;
    for (size_t i = 0; i < page_size; i += 0x4) {

        uintptr_t insnadd = orig_page_start + i;
        uint32_t insn = *(uint32_t *)insnadd;
        insnwitchpctype type = isinsnwitchpc(insn);

        switch(type) {

            case B:
            case BL: {
                bool isbl = (insn >> 31) & 0x1;
                intptr_t offset = static_cast<intptr_t>(sbits(insn, 0, 25) * 4);
                uintptr_t addr = insnadd + offset;

                if (addr >= orig_page_start && addr < (orig_page_start + page_size)) {
                    *(uint32_t *)(shadow_page + 0x0) = insn;
                    shadow_page += 0x4;
                } else {
                    int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                    if (isbl) {
                        if (CurrentMode == TMPREG_ON || CurrentMode == TMPREG_ON_FKBTI) {
                            *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                            *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0x14 / 0x4) << 5) | (30 & 0x1f); // LDR X30 #0x14
                            *(uint32_t *)(extraspace + 0x4) = 0x58000000u | ((0x8 / 0x4) << 5) | (TMPREG & 0x1f); // LDR TMPREG #0x8
                            *(uint32_t *)(extraspace + 0x8) = (bypassbti ? 0xd65f0000u : 0xd61f0000u) | (TMPREG & 0x1f) << 5; // BR TMPREG
                            *(uint64_t *)(extraspace + 0xc) = addr;
                            *(uint64_t *)(extraspace + 0x14) = insnadd + 0x4;
                            shadow_page += 0x4, extraspace += 0x1c;
                        } else {
                            *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                            *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0x8 / 0x4) << 5) | (30 & 0x1f); // LDR X30 #0x8
                            *(uint32_t *)(extraspace + 0x4) = 0xd4200000u; // BRK #0
                            *(uint64_t *)(extraspace + 0x8) = insnadd + 0x4;
                            TrapMap[extraspace + 0x4] = {1, addr};
                            shadow_page += 0x4, extraspace += 0x10;
                        }
                    } else {
                        if (CurrentMode == TMPREG_ON || CurrentMode == TMPREG_ON_FKBTI) {
                            *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                            *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0x8 / 0x4) << 5) | (TMPREG & 0x1f); // LDR TMPREG #0x8
                            *(uint32_t *)(extraspace + 0x4) = (bypassbti ? 0xd65f0000u : 0xd61f0000u) | (TMPREG & 0x1f) << 5; // BR TMPREG
                            *(uint64_t *)(extraspace + 0x8) = addr;
                            shadow_page += 0x4, extraspace += 0x10;
                        } else {
                            *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                            *(uint32_t *)(extraspace + 0x0) = 0xd4200000u; // BRK #0
                            TrapMap[extraspace + 0x0] = {1, addr};
                            shadow_page += 0x4, extraspace += 0x4;
                        }
                    }
                }
                continue;
            }

            case B_COND: {
                intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 23) * 4);
                uintptr_t addr = insnadd + offset;

                if (addr >= orig_page_start && addr < (orig_page_start + page_size)) {
                    *(uint32_t *)(shadow_page + 0x0) = insn;
                    shadow_page += 0x4;
                } else {
                    int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                    int32_t offset2 = static_cast<int32_t>((shadow_page + 0x4) - (extraspace + 0x4));
                    if (CurrentMode == TMPREG_ON || CurrentMode == TMPREG_ON_FKBTI) {
                        *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                        *(uint32_t *)(extraspace + 0x0) = (insn & 0xff00001fu) | ((0x8 / 0x4) << 5);  // B.<cond> #0x8
                        *(uint32_t *)(extraspace + 0x4) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                        *(uint32_t *)(extraspace + 0x8) = 0x58000000u | ((0x8 / 0x4) << 5) | (TMPREG & 0x1f); // LDR TMPREG #0x8
                        *(uint32_t *)(extraspace + 0xc) = (bypassbti ? 0xd65f0000u : 0xd61f0000u) | (TMPREG & 0x1f) << 5; // BR TMPREG
                        *(uint64_t *)(extraspace + 0x10) = addr;
                        shadow_page += 0x4, extraspace += 0x18;
                    } else {
                        *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                        *(uint32_t *)(extraspace + 0x0) = (insn & 0xff00001fu) | ((0x8 / 0x4) << 5);  // B.<cond> #0x8
                        *(uint32_t *)(extraspace + 0x4) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                        *(uint32_t *)(extraspace + 0x8) = 0xd4200000u; // BRK #0
                        TrapMap[extraspace + 0x8] = {1, addr};
                        shadow_page += 0x4, extraspace += 0xc;
                    }
                }
                continue;
            }

            case CBZ:
            case CBNZ: {
                intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 23) * 4);
                uintptr_t addr = insnadd + offset;

                if (addr >= orig_page_start && addr < (orig_page_start + page_size)) {
                    *(uint32_t *)(shadow_page + 0x0) = insn;
                    shadow_page += 0x4;
                } else {
                    int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                    int32_t offset2 = static_cast<int32_t>((shadow_page + 0x4) - (extraspace + 0x4));
                    if (CurrentMode == TMPREG_ON || CurrentMode == TMPREG_ON_FKBTI) {
                        *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                        *(uint32_t *)(extraspace + 0x0) = (insn & 0xff00001fu) | ((0x8 / 0x4) << 5);  // CB(N)Z Xn, #8
                        *(uint32_t *)(extraspace + 0x4) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                        *(uint32_t *)(extraspace + 0x8) = 0x58000000u | ((0x8 / 0x4) << 5) | (TMPREG & 0x1f); // LDR TMPREG #0x8
                        *(uint32_t *)(extraspace + 0xc) = (bypassbti ? 0xd65f0000u : 0xd61f0000u) | (TMPREG & 0x1f) << 5; // BR TMPREG
                        *(uint64_t *)(extraspace + 0x10) = addr;
                        shadow_page += 0x4, extraspace += 0x18;
                    } else {
                        *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                        *(uint32_t *)(extraspace + 0x0) = (insn & 0xff00001fu) | ((0x8 / 0x4) << 5);  // CB(N)Z Xn/Wn #0x8
                        *(uint32_t *)(extraspace + 0x4) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                        *(uint32_t *)(extraspace + 0x8) = 0xd4200000u; // BRK #0
                        TrapMap[extraspace + 0x8] = {1, addr};
                        shadow_page += 0x4, extraspace += 0xc;
                    }
                }
                continue;
            }

            case TBZ:
            case TBNZ: {
                intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 18) * 4);
                uintptr_t addr = insnadd + offset;

                if (addr >= orig_page_start && addr < (orig_page_start + page_size)) {
                    *(uint32_t *)(shadow_page + 0x0) = insn;
                    shadow_page += 0x4;
                } else {
                    int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                    int32_t offset2 = static_cast<int32_t>((shadow_page + 0x4) - (extraspace + 0x4));
                    if (CurrentMode == TMPREG_ON || CurrentMode == TMPREG_ON_FKBTI) {
                        *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                        *(uint32_t *)(extraspace + 0x0) = (insn & 0xfff8001fu) | ((0x8 / 0x4) << 5);  // TB(N)Z Xn, #bit, #8
                        *(uint32_t *)(extraspace + 0x4) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                        *(uint32_t *)(extraspace + 0x8) = 0x58000000u | ((0x8 / 0x4) << 5) | (TMPREG & 0x1f); // LDR TMPREG #0x8
                        *(uint32_t *)(extraspace + 0xc) = (bypassbti ? 0xd65f0000u : 0xd61f0000u) | (TMPREG & 0x1f) << 5; // BR TMPREG
                        *(uint64_t *)(extraspace + 0x10) = addr;
                        shadow_page += 0x4, extraspace += 0x18;
                    } else {
                        *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                        *(uint32_t *)(extraspace + 0x0) = (insn & 0xfff8001fu) | ((0x8 / 0x4) << 5);  // TB(N)Z Xn #bit #0x8
                        *(uint32_t *)(extraspace + 0x4) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                        *(uint32_t *)(extraspace + 0x8) = 0xd4200000u; // BRK #0
                        TrapMap[extraspace + 0x8] = {1, addr};
                        shadow_page += 0x4, extraspace += 0xc;
                    }
                }
                continue;
            }

            case ADR:
            case ADRP: {
                intptr_t immlo = (insn >> 29) & 0x3;
                intptr_t immhi = sbits(insn, 5, 23) * 4;
                bool isadrp = (insn >> 31) & 0x1;
                uint32_t rd = (insn >> 0) & 0x1f;
                intptr_t offset = 0;
                uintptr_t addr = 0;

                if (isadrp) {
                    offset = static_cast<intptr_t>((immhi | immlo) * 4096);
                    addr = ((insnadd + offset) >> 12) << 12;
                } else {
                    offset = static_cast<intptr_t>(immhi | immlo);
                    addr = insnadd + offset;
                }
                int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                int32_t offset2 = static_cast<int32_t>((shadow_page + 0x4) - (extraspace + 0x4));
                *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 4) & 0x3ffffffu); // B fixed
                *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0x8 / 0x4) << 5) | (rd & 0x1f); // LDR Xn #0x8
                *(uint32_t *)(extraspace + 0x4) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                *(uint64_t *)(extraspace + 0x8) = addr;
                shadow_page += 0x4, extraspace += 0x10;
                continue;
            }

            case LDRSW_LIT: {
                uint32_t rt = (insn >> 0) & 0x1f;
                intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 23) * 4);
                uintptr_t addr = insnadd + offset;

                int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                int32_t offset2 = static_cast<int32_t>((shadow_page + 0x4) - (extraspace + 0x8));
                uint32_t ldropcode = 0xb9800000u; // LDRSW
                *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0xc / 0x4) << 5) | (rt & 0x1f); // LDR Rt #0xc
                *(uint32_t *)(extraspace + 0x4) = ldropcode | (rt & 0x1f) | (rt & 0x1f ) << 5; // LDRSW Rt [Rt]
                *(uint32_t *)(extraspace + 0x8) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                *(uint64_t *)(extraspace + 0xc) = addr;
                shadow_page += 0x4, extraspace += 0x14;
                continue;
            }

            case LDR_LIT_32:
            case LDR_LIT_64: {
                bool is64 = (insn >> 30) & 0x1;
                uint32_t rt = (insn >> 0) & 0x1f;
                intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 23) * 4);
                uintptr_t addr = insnadd + offset;

                int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                int32_t offset2 = static_cast<int32_t>((shadow_page + 0x4) - (extraspace + 0x8));
                uint32_t ldropcode = is64 ? 0xf9400000u : 0xb9400000u; // LDR Xn / LDR Wn
                *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0xc / 0x4) << 5) | (rt & 0x1f); // LDR Rt #0xc
                *(uint32_t *)(extraspace + 0x4) = ldropcode | (rt & 0x1f) | (rt & 0x1f ) << 5; // LDR Rt [Rt]
                *(uint32_t *)(extraspace + 0x8) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                *(uint64_t *)(extraspace + 0xc) = addr;
                shadow_page += 0x4, extraspace += 0x14;
                continue;
            }

            case LDR_LIT_S_32:
            case LDR_LIT_D_64:
            case LDR_LIT_Q_128: {
                uint32_t rt = (insn >> 0) & 0x1f;
                intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 23) * 4);
                uintptr_t addr = insnadd + offset;
                uint32_t ldropcode = 0;

                if (type == LDR_LIT_S_32) ldropcode = 0xbd400000u;
                if (type == LDR_LIT_D_64) ldropcode = 0xfd400000u;
                if (type == LDR_LIT_Q_128) ldropcode = 0x3dc00000u;

                int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                int32_t offset2 = static_cast<int32_t>((shadow_page + 0x4) - (extraspace + 0x8));

                if (CurrentMode == TMPREG_ON || CurrentMode == TMPREG_ON_FKBTI) {
                    *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                    *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0xc / 0x4) << 5) | (TMPREG & 0x1f); // LDR TMPREG #0xc
                    *(uint32_t *)(extraspace + 0x4) = ldropcode | (rt & 0x1f) | (TMPREG & 0x1f) << 5; // LDRV Rt [TMPREG]
                    *(uint32_t *)(extraspace + 0x8) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                    *(uint64_t *)(extraspace + 0xc) = addr;
                    shadow_page += 0x4, extraspace += 0x14;
                } else {
                    *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                    *(uint32_t *)(extraspace + 0x0) = 0xd4200000u; // BRK #0
                    *(uint32_t *)(extraspace + 0x4) = 0x58000000u | ((0x10 / 0x4) << 5) | (17 & 0x1f); // LDR x17 #0x10
                    *(uint32_t *)(extraspace + 0x8) = ldropcode | (rt & 0x1f) | (17 & 0x1f) << 5; // LDRV Rt [x17]
                    *(uint32_t *)(extraspace + 0xc) = 0xd4200000u; // BRK #0
                    *(uint32_t *)(extraspace + 0x10) = 0x14000000u | ((offset2 / 0x4) & 0x3ffffffu); // B next
                    *(uint64_t *)(extraspace + 0x14) = addr;
                    *(uint64_t *)(extraspace + 0x1c) = 0;
                    TrapMap[extraspace + 0x0] = {4, (17LL << 48) | (((extraspace + 0x1c) << 16) >> 16)};
                    TrapMap[extraspace + 0xc] = {5, (17LL << 48) | (((extraspace + 0x1c) << 16) >> 16)};
                    shadow_page += 0x4, extraspace += 0x24;
                }
                continue;
            }

            case PRFM_LIT: {
                *(uint32_t *)shadow_page = 0xd503201fu;
                shadow_page += 0x4;
                continue;
            }

            case OTHER:
            default: {
                // blr (修复了blr后x30在乱七八糟的位置)
                if ((insn & 0xFFFFFC1Fu) == 0xD63F0000u) {
                    uint32_t reg = (insn >> 5) & 0x1F;
                    int32_t offset1 = static_cast<int32_t>(extraspace - shadow_page);
                    *(uint32_t *)shadow_page = 0x14000000u | ((offset1 / 0x4) & 0x3ffffffu); // B fixed
                    *(uint32_t *)(extraspace + 0x0) = 0x58000000u | ((0x8 / 0x4) << 5) | (30 & 0x1f); // LDR X30 #0x8
                    *(uint32_t *)(extraspace + 0x4) = (bypassbti ? 0xd65f0000u : 0xd61f0000u) | (reg & 0x1f) << 5; // BR REG
                    *(uint64_t *)(extraspace + 0x8) = insnadd + 0x4;
                    shadow_page += 0x4, extraspace += 0x10;
                } else {
                    *(uint32_t *)shadow_page = insn;
                    shadow_page += 0x4;
                }
                continue;
            }
        }
    }
    __cache_clear((char *)shadow_page_result, (char *)shadow_page_result + 0x100000);
    return shadow_page_result;
}

//--------------------------------------------

uintptr_t origflow(uintptr_t pc)
{
    uintptr_t result = (uintptr_t)memalloc(0x40);
    if (!result) {
        kill(getpid(), SIGABRT);
    }

    uintptr_t write = result;
    uint32_t insn = *(uint32_t *)pc;
    insnwitchpctype type = isinsnwitchpc(insn);
    *(uint32_t *)(write + 0x0) = 0xd503201fu;

    switch (type) {
        case B:
        case BL: {
            bool isbl = (insn >> 31) & 0x1;
            intptr_t offset = static_cast<intptr_t>(sbits(insn, 0, 25) * 4);
            uintptr_t addr = pc + offset;
            if (isbl) {
                *(uint32_t *)(write + 0x4) = 0x58000000u | ((0x8 / 0x4) << 5) | (30 & 0x1f); // LDR X30 #0x8
                *(uint32_t *)(write + 0x8) = 0xd4200000u; // BRK #0
                *(uint64_t *)(write + 0xc) = pc + 0x4;
                TrapMap[write + 0x8] = {1, addr};
            } else {
                *(uint32_t *)(write + 0x4) = 0xd4200000u; // BRK #0
                TrapMap[write + 0x4] = {1, addr};
            }
            break;
        }
        case CBZ:
        case CBNZ:
        case B_COND: {
            intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 23) * 4);
            uintptr_t addr = pc + offset;
            *(uint32_t *)(write + 0x4) = (insn & 0xff00001fu) | ((0x8 / 0x4) << 5);  // CB(N)Z Xn/Wn #0x8 || B.<cond> #8
            *(uint32_t *)(write + 0x8) = 0xd4200000u; // BRK #0
            *(uint32_t *)(write + 0xc) = 0xd4200000u; // BRK #0
            TrapMap[write + 0x8] = {1, pc + 0x4};
            TrapMap[write + 0xc] = {1, addr};
            break;
        }
        case TBZ:
        case TBNZ: {
            intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 18) * 4);
            uintptr_t addr = pc + offset;
            *(uint32_t *)(write + 0x4) = (insn & 0xfff8001fu) | ((0x8 / 0x4) << 5);  // TB(N)Z Xn/Wn #0x8
            *(uint32_t *)(write + 0x8) = 0xd4200000u; // BRK #0
            *(uint32_t *)(write + 0xc) = 0xd4200000u; // BRK #0
            TrapMap[write + 0x8] = {1, pc + 0x4};
            TrapMap[write + 0xc] = {1, addr};
            break;
        }
        case ADR:
        case ADRP: {
            intptr_t immlo = (insn >> 29) & 0x3;
            intptr_t immhi = sbits(insn, 5, 23) * 4;
            bool isadrp = (insn >> 31) & 0x1;
            uint32_t rd = (insn >> 0) & 0x1f;
            intptr_t offset = 0;
            uintptr_t addr = 0;
            if (isadrp) {
                offset = static_cast<intptr_t>((immhi | immlo) * 4096);
                addr = ((pc + offset) >> 12) << 12;
            } else {
                offset = static_cast<intptr_t>(immhi | immlo);
                addr = pc + offset;
            }
            *(uint32_t *)(write + 0x4) = 0x58000000u | ((0x8 / 0x4) << 5) | (rd & 0x1f); // LDR Xn #0x8
            *(uint32_t *)(write + 0x8) = 0xd4200000u; // BRK #0
            *(uint64_t *)(write + 0xc) = addr;
            TrapMap[write + 0x8] = {1, pc + 0x4};
            break;
        }
        case LDR_LIT_32:
        case LDR_LIT_64:
        case LDRSW_LIT:
        case LDR_LIT_S_32:
        case LDR_LIT_D_64:
        case LDR_LIT_Q_128: {
            uint32_t rt = (insn >> 0) & 0x1f;
            intptr_t offset = static_cast<intptr_t>(sbits(insn, 5, 23) * 4);
            uintptr_t addr = pc + offset;
            uint32_t ldropcode = 0;
            if (type == LDR_LIT_32) ldropcode = 0xb9400000u;
            if (type == LDR_LIT_64) ldropcode = 0xf9400000u;
            if (type == LDRSW_LIT) ldropcode = 0xb9800000u;
            if (type == LDR_LIT_S_32) ldropcode = 0xbd400000u;
            if (type == LDR_LIT_D_64) ldropcode = 0xfd400000u;
            if (type == LDR_LIT_Q_128) ldropcode = 0x3dc00000u;
            if (type == LDR_LIT_32 || type == LDR_LIT_64 || type == LDRSW_LIT) {
                *(uint32_t *)(write + 0x4) = 0x58000000u | ((0xc / 0x4) << 5) | (rt & 0x1f); // LDR Rt #0xc
                *(uint32_t *)(write + 0x8) = ldropcode | (rt & 0x1f) | (rt & 0x1f ) << 5; // LDR Rt [Rt]
                *(uint32_t *)(write + 0xc) = 0xd4200000u; // BRK #0
                *(uint64_t *)(write + 0x10) = addr;
                TrapMap[write + 0xc] = {1, pc + 0x4};
            } else {
                *(uint32_t *)(write + 0x4) = 0xd4200000u; // BRK #0
                *(uint32_t *)(write + 0x8) = 0x58000000u | ((0x10 / 0x4) << 5) | (17 & 0x1f); // LDR x17 #0x10
                *(uint32_t *)(write + 0xc) = ldropcode | (rt & 0x1f) | (17 & 0x1f) << 5; // LDRV Rt [x17]
                *(uint32_t *)(write + 0x10) = 0xd4200000u; // BRK #0
                *(uint32_t *)(write + 0x14) = 0xd4200000u; // BRK #0
                *(uint64_t *)(write + 0x18) = addr;
                *(uint64_t *)(write + 0x20) = 0;
                TrapMap[write + 0x4] = {4, (17LL << 48) | (((write + 0x20) << 16) >> 16)};
                TrapMap[write + 0x10] = {5, (17LL << 48) | (((write + 0x20) << 16) >> 16)};
                TrapMap[write + 0x14] = {1, pc + 0x4};
            }
            break;
        }
        case PRFM_LIT: {
            *(uint32_t *)(write + 0x4) = 0xd4200000u; // BRK #0
            TrapMap[write + 0x4] = {1, pc + 0x4};
            break;
        }
        case OTHER:
        default: {
            *(uint32_t *)(write + 0x4) = insn;
            *(uint32_t *)(write + 0x8) = 0xd4200000u;
            TrapMap[write + 0x8] = {1, pc + 0x4};
            break;
        }
    }
    __cache_clear((char *)result, (char *)result + 0x40);
    return result;
}

/*------------------------------------------------pageprot------------------------------------------------*/

struct MemProtectInfo { void *addr; size_t size; int prot; };

volatile bool cond_mprotect_thread = false;
std::once_flag hook_init_flag;
std::vector<MemProtectInfo> mprotect_vec;

void mprotect_thread()
{
    for (auto& info : mprotect_vec) {
        mprotect(info.addr, info.size, info.prot);
        __cache_clear((char *)info.addr, (char *)info.addr + info.size);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void push_mprotect(void *addr, size_t size, int prot)
{
    mprotect(addr, size, prot);
    __cache_clear((char *)addr, (char *)addr + size);
    mprotect_vec.push_back({addr, size, prot});
}

bool mprotect__(void *addr, int num, int perms)
{
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uintptr_t page_start = align_down((uintptr_t)addr, page_size);
    size_t need_set_size = num * page_size;
    push_mprotect((void*)page_start, need_set_size, perms);
    return true;
}

/*------------------------------------------------hook------------------------------------------------*/

void install_seccomp_bpf()
{
    {
        struct sigaction sysact;
        sysact.sa_flags = SA_SIGINFO | SA_NODEFER;
        sysact.sa_sigaction = sys_handler;
        sigemptyset(&sysact.sa_mask);
        sigaction(SIGSYS, &sysact, 0);
        
        struct sigaction illact;
        illact.sa_flags = SA_SIGINFO | SA_NODEFER;
        illact.sa_sigaction = install_seccomp_bpf_handler;
        sigemptyset(&illact.sa_mask);
        sigaction(SIGILL, &illact, 0);
        
        for (size_t i = 0; i < 5; i++) {
            std::vector<int> Tasks = GetProcessTask(getpid());
            for (auto Task : Tasks) {
                if (Task == syscall(__NR_gettid)) continue;
                syscall(__NR_tkill, Task, SIGILL);
            }
        }
    }
}

void shadowpage_hookinit(shadowpage_mode_t mode, mprotect_mode_t mode2, bool svchook)
{
    TMPREG = mode.reg;
    CurrentMode = mode.mode;

    std::call_once(hook_init_flag, [&]() {
        if (svchook) {
            install_seccomp_bpf();
        }
        
        struct sigaction segvact;
        segvact.sa_flags = SA_SIGINFO | SA_NODEFER;
        segvact.sa_sigaction = segv_handler;
        sigemptyset(&segvact.sa_mask);

        struct sigaction trapact;
        trapact.sa_flags = SA_SIGINFO | SA_NODEFER;
        trapact.sa_sigaction = trap_handler;
        sigemptyset(&trapact.sa_mask);

        sigaction(SIGSEGV, &segvact, 0);
        sigaction(SIGTRAP, &trapact, 0);

        if (mode2.mode == LOOP_ON) {
            std::thread([&]() {
                unsigned int looptime = mode2.time;
                while(!cond_mprotect_thread);
                do {
                    mprotect_thread();
                    std::this_thread::sleep_for(std::chrono::seconds(looptime));
                } while (true);
            }).detach();
        }
    });
}

void shadowpage_hook(void *addr, void *fake, void **orig)
{
    {
        std::lock_guard<std::mutex> lock(mem_perm_mutex);
        if (!memory_pool_read_write_exec()) kill(getpid(), SIGABRT);
        if (addr) {
            size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
            uintptr_t shadowpage = create_shadowpage((uintptr_t)addr);
            size_t offset = uintptr_t(addr) - align_down((uintptr_t)addr, page_size);
            if (orig) *orig = (void *)origflow(shadowpage + offset);
            TrapMap[shadowpage + offset] = {1, (uintptr_t)fake};
            *(uint32_t *)(shadowpage + offset) = 0xd4200000u; // BRK #0
            __cache_clear((char *)shadowpage, (char *)shadowpage + page_size);
            mprotect__(addr, 1, PROT_READ | PROT_WRITE);
        }
        if (!memory_pool_read_exec()) kill(getpid(), SIGABRT);
    }
}

void shadowpage_hookctx(void *addr, __callback__ precallback)
{
    {
        std::lock_guard<std::mutex> lock(mem_perm_mutex);
        if (!memory_pool_read_write_exec()) kill(getpid(), SIGABRT);
        if (addr) {
            size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
            uintptr_t shadowpage = create_shadowpage((uintptr_t)addr);
            size_t offset = uintptr_t(addr) - align_down((uintptr_t)addr, page_size);
            if (precallback) {
                uintptr_t orig = origflow(shadowpage + offset);
                TrapMap[orig + 0x0] = {3, (uintptr_t)precallback};
                *(uint32_t *)(orig + 0x0) = 0xd4200000u; // BRK #0
                TrapMap[shadowpage + offset] = {1, (uintptr_t)orig};
                *(uint32_t *)(shadowpage + offset) = 0xd4200000u; // BRK #0
                __cache_clear((char *)shadowpage, (char *)shadowpage + page_size);
                mprotect__(addr, 1, PROT_READ | PROT_WRITE);
            }
        }
        if (!memory_pool_read_exec()) kill(getpid(), SIGABRT);
    }
}


void shadowpage_patch_insn64(void *addr, uint64_t new_opcode)
{
    {
        std::lock_guard<std::mutex> lock(mem_perm_mutex);
        if (!memory_pool_read_write_exec()) kill(getpid(), SIGABRT);

        if (addr) {
            size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
            uintptr_t shadowpage = create_shadowpage((uintptr_t)addr);
            size_t offset = uintptr_t(addr) - align_down((uintptr_t)addr, page_size);
            
            // 在影子页中写入新的ARM64指令机器码
            *(uint64_t *)(shadowpage + offset) = new_opcode;
            
            // 清理指令缓存，这在ARM64上是必须的
            __cache_clear((char *)(shadowpage + offset), (char *)(shadowpage + offset) + sizeof(uint64_t));
            
            // 保护原始页，触发后续执行重定向到影子页
            mprotect__(addr, 1, PROT_READ | PROT_WRITE);
        }

        if (!memory_pool_read_exec()) kill(getpid(), SIGABRT);
    }
}

void shadowpage_patch_insn(void *addr, int new_opcode)
{
    {
        std::lock_guard<std::mutex> lock(mem_perm_mutex);
        if (!memory_pool_read_write_exec()) kill(getpid(), SIGABRT);

        if (addr) {
            size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
            uintptr_t shadowpage = create_shadowpage((uintptr_t)addr);
            size_t offset = uintptr_t(addr) - align_down((uintptr_t)addr, page_size);
            
            // 在影子页中写入新的ARM64指令机器码
            *(uint32_t *)(shadowpage + offset) = new_opcode;
            
            // 清理指令缓存，这在ARM64上是必须的
            __cache_clear((char *)(shadowpage + offset), (char *)(shadowpage + offset) + sizeof(uint32_t));
            
            // 保护原始页，触发后续执行重定向到影子页
            mprotect__(addr, 1, PROT_READ | PROT_WRITE);
        }

        if (!memory_pool_read_exec()) kill(getpid(), SIGABRT);
    }
}
