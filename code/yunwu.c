#include "yunwu.h"

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/mm.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/pid.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/version.h>
#include <linux/kprobes.h>
#include <linux/ktime.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/vmalloc.h>
#include <linux/list.h>
#include <linux/seqlock.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/fpsimd.h>
#include <asm/thread_info.h>
#include <asm/debug-monitors.h>
#include <asm/tlbflush.h>

#define MAX_BREAKPOINTS    4
#define MAX_HIT_QUEUE      128
#define ENABLE_ANTI_PTRACE 0
#define ENABLE_HIDE_MODULE 0
#define MAX_RW_SIZE        (4 * 1024 * 1024)
#define MAX_STEP_TRACK     64
#define YW_BRK_INSN        0xd4200000   /* BRK #0 */

/* ============================================================
 * ARM64 PTE 断点专用位（用户不可执行 UXN = bit 54）
 * 注意：执行断点已改用 BRK 软件断点，此宏仅写断点保留
 * ============================================================ */
#if defined(CONFIG_ARM64)
#define YW_PTE_UXN      (1UL << 54)
#define YW_PTE_PXN      (1UL << 53)
#else
#error "PTE breakpoint only supported on ARM64"
#endif

/* ============================================================
 * 内核版本兼容类型定义（必须在函数声明之前）
 * ============================================================ */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
typedef unsigned long yw_esr_t;
#else
typedef unsigned int  yw_esr_t;
#endif

/* ============================================================
 * 某些内核版本未在头文件中导出 user_break_hook 定义
 * 自行定义兼容结构（布局与内核内部一致）
 * ============================================================ */
struct user_break_hook {
    struct list_head list;
    u32 esr_val;
    u32 esr_mask;
    int (*handler)(struct pt_regs *regs, unsigned int esr);
};

/* ============================================================
 * 前置函数声明（在静态变量初始化之前）
 * ============================================================ */
static int yunwu_brk_handler(struct pt_regs *regs, unsigned int esr);
static int yunwu_step_fn(struct pt_regs *regs, unsigned int esr);
static int pte_bp_kprobe_pre(struct kprobe *p, struct pt_regs *regs);
static struct task_struct *get_task_by_pid(pid_t pid);

/* ============================================================
 * TLB 刷新内联函数（三级策略，严格区分上下文）
 * ============================================================ */

/*
 * 局部刷新：仅刷新当前 CPU 的指定 VA TLB 条目。
 * 使用 tlbi vae1（当前 ASID，EL1），适用于 kprobe 原子上下文。
 * 不广播、不发送 IPI，绝对安全。
 */
static inline void yw_flush_tlb_local(unsigned long addr)
{
    dsb(ishst);
    __asm__ __volatile__(
        "tlbi vae1, %0\n"
        "dsb ish\n"
        "isb\n"
        :
        : "r" (addr)
        : "memory"
    );
}

/*
 * 按 VA 广播刷新：刷新 Inner-Shareable 域内所有 CPU 的指定 VA。
 * 使用 tlbi vae1is，适用于单步钩子（异常上下文，非原子）。
 * 只刷目标 VA，开销远小于 vmalle1is。
 */
static inline void yw_flush_tlb_va_is(unsigned long addr)
{
    dsb(ishst);
    __asm__ __volatile__(
        "tlbi vae1is, %0\n"
        "dsb ish\n"
        "isb\n"
        :
        : "r" (addr)
        : "memory"
    );
}

/*
 * 全局刷新：广播到所有 Inner Shareable CPU，刷新当前 VMID 的全部 TLB。
 * 使用 tlbi vmalle1is，仅适用于 ioctl 可睡眠上下文（安装/卸载/恢复/挂起）。
 * 严禁在原子/异常上下文中使用！
 */
static inline void yw_flush_tlb_global(void)
{
    dsb(ishst);
    __asm__ __volatile__(
        "tlbi vmalle1is\n"
        "dsb ish\n"
        "isb\n"
        ::: "memory"
    );
}

/* ============================================================
 * 函数指针类型定义
 * ============================================================ */
typedef struct perf_event *(*reg_hw_bp_fn)(struct perf_event_attr *,
        perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_hw_bp_fn)(struct perf_event *);
typedef void (*fpsimd_preserve_fn)(void);
typedef void (*fpsimd_flush_fn)(struct task_struct *);
typedef void (*user_ss_fn)(struct task_struct *);
typedef void (*reg_step_hook_fn)(struct step_hook *);
typedef void (*unreg_step_hook_fn)(struct step_hook *);
typedef void (*reg_brk_hook_fn)(struct user_break_hook *);
typedef void (*unreg_brk_hook_fn)(struct user_break_hook *);

/* ============================================================
 * 全局符号指针
 * ============================================================ */
static reg_hw_bp_fn dyn_register_hw_bp;
static unreg_hw_bp_fn dyn_unregister_hw_bp;
static fpsimd_preserve_fn dyn_fpsimd_preserve;
static fpsimd_flush_fn dyn_fpsimd_flush;
static user_ss_fn dyn_user_enable_ss;
static user_ss_fn dyn_user_disable_ss;
static reg_step_hook_fn dyn_register_step_hook;
static unreg_step_hook_fn dyn_unregister_step_hook;
static reg_brk_hook_fn dyn_register_user_brk_hook;
static unreg_brk_hook_fn dyn_unregister_user_brk_hook;
static bool step_hook_registered;
static bool pte_kprobe_registered;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

/* ============================================================
 * 硬件断点数据结构
 * ============================================================ */
struct bp_thread_event {
    struct perf_event *pevent;
    struct task_struct *task;
    struct list_head list;
};

struct bp_entry {
    struct list_head events;
    pid_t pid;
    unsigned long addr;
    unsigned int type, len;
    bool auto_reg_enable;
    unsigned int reg_id;
    unsigned long reg_value;
    int index;
    u64 fp_reg_mask;
    u64 fp_reg_values[32][2];
    u8 fp_reg_size;
    seqcount_t fp_seq;
    atomic_t hit_total;
    atomic_t in_handler;
    atomic_t user_enabled;
    struct yunwu_hit_detail last_hit;
    struct yunwu_hit_detail hit_ring[MAX_HIT_QUEUE];
    atomic_t head;
    atomic_t tail;
    raw_spinlock_t hit_lock;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_MUTEX(bp_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static atomic64_t global_hook_pc = ATOMIC64_INIT(0);

/* ============================================================
 * PTE 断点数据结构
 * ============================================================ */
#define MAX_PTE_BPS         4
#define MAX_PTE_STEP_TRACK  64

struct pte_bp_entry {
    pid_t pid;
    unsigned long addr;
    unsigned int type;          /* 0=X(BRK), 1=W(PTE RDONLY) */
    bool active;
    bool stepping;
    struct mm_struct *mm;       /* 仅用于引用计数，handler 中绝不直接使用 */

    /* 执行断点: BRK 软件断点 */
    u32 orig_insn;              /* 原始指令 */

    /* 写断点: PTE 写保护 */
    pte_t orig_pte;             /* 原始 PTE 值（用于恢复） */

    /* 寄存器/浮点修改 */
    bool auto_reg_enable;
    unsigned int reg_id;
    unsigned long reg_value;
    u64 fp_reg_mask;
    u64 fp_reg_values[32][2];
    u8 fp_reg_size;
    seqcount_t fp_seq;
    bool fp_modify_pending;

    atomic_t hit_total;
    struct yunwu_hit_detail last_hit;
    raw_spinlock_t lock;
};

static struct pte_bp_entry pte_bp_table[MAX_PTE_BPS];
static DEFINE_MUTEX(pte_bp_mutex);

struct pte_step_track_entry {
    struct task_struct *task;
    int pte_index;
    bool used;
};

static struct pte_step_track_entry pte_step_track[MAX_PTE_STEP_TRACK];
static DEFINE_RAW_SPINLOCK(pte_step_track_lock);
static struct kprobe pte_kprobe;

/* ============================================================
 * 硬件断点单步跟踪表
 * ============================================================ */
struct step_track_entry {
    struct task_struct *task;
    struct perf_event *pev;
    bool used;
};
static struct step_track_entry step_track[MAX_STEP_TRACK];
static DEFINE_SPINLOCK(step_track_lock);

/* ============================================================
 * 静态 hook 变量（依赖上述前置声明）
 * ============================================================ */
static struct user_break_hook yunwu_brk_hook = {
    .esr_val = 0xF2000000,   /* BRK: EC=0x3c, IL=1, ISS=0 */
    .esr_mask = 0xFE000000,  /* 匹配 EC=0x3c 和 IL=1 */
    .handler = yunwu_brk_handler,
};

static struct step_hook yunwu_step_hook = {
    .fn = yunwu_step_fn,
};

/* ============================================================
 * 辅助内联函数（在 handler 之前定义）
 * ============================================================ */
static inline int set_user_reg(struct pt_regs *regs, unsigned int reg_id, unsigned long value) {
    if (reg_id <= 30) regs->regs[reg_id] = value;
    else if (reg_id == 31) regs->sp = value;
    else if (reg_id == 32) regs->pc = value;
    else if (reg_id == 33) regs->pstate = value;
    else return -EINVAL;
    return 0;
}

/* ============================================================
 * PTE 权限检查兼容层
 * ============================================================ */
#ifndef pte_read
static inline int __yunwu_pte_read(pte_t pte)
{
#if defined(CONFIG_ARM64)
    return pte_present(pte);
#elif defined(CONFIG_X86)
    return pte_present(pte);
#else
    return pte_present(pte);
#endif
}
#define pte_read(pte) __yunwu_pte_read(pte)
#endif

#ifndef pte_write
static inline int __yunwu_pte_write(pte_t pte)
{
#if defined(CONFIG_ARM64)
    return !(pte_val(pte) & PTE_RDONLY);
#elif defined(CONFIG_X86)
    return pte_val(pte) & _PAGE_RW;
#else
    return 0;
#endif
}
#define pte_write(pte) __yunwu_pte_write(pte)
#endif

/* ============================================================
 * 内核版本兼容层
 * ============================================================ */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#define yw_mmap_read_lock(mm)     down_read(&(mm)->mmap_sem)
#define yw_mmap_read_unlock(mm)   up_read(&(mm)->mmap_sem)
#define yw_mmap_write_lock(mm)    down_write(&(mm)->mmap_sem)
#define yw_mmap_write_unlock(mm)  up_write(&(mm)->mmap_sem)
#define yw_mmap_write_trylock(mm) down_write_trylock(&(mm)->mmap_sem)
#else
#define yw_mmap_read_lock(mm)     mmap_read_lock(mm)
#define yw_mmap_read_unlock(mm)   mmap_read_unlock(mm)
#define yw_mmap_write_lock(mm)    mmap_write_lock(mm)
#define yw_mmap_write_unlock(mm)  mmap_write_unlock(mm)
#define yw_mmap_write_trylock(mm) down_write_trylock(&(mm)->mmap_lock)
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
static inline void *yw_kmap_page(struct page *page) { return kmap_local_page(page); }
static inline void yw_kunmap_page(void *addr) { kunmap_local(addr); }
#else
static inline void *yw_kmap_page(struct page *page) { return kmap_atomic(page); }
static inline void yw_kunmap_page(void *addr) { kunmap_atomic(addr); }
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
#define YW_VMA_ITER_DECL(mm)  VMA_ITERATOR(_yw_vmi, mm, 0)
#define YW_FOR_EACH_VMA(vma)  for_each_vma(_yw_vmi, vma)
#else
#define YW_VMA_ITER_DECL(mm)  struct mm_struct *_yw_mm = (mm)
#define YW_FOR_EACH_VMA(vma)  for (vma = _yw_mm->mmap; vma; vma = vma->vm_next)
#endif

/* ============================================================
 * ARM64 6.12+ fpsimd_state 被包裹在 thread.uw 联合体中
 * ============================================================ */
#if defined(CONFIG_ARM64)
#define YW_THREAD_FPSIMD(t)   ((t)->thread.uw.fpsimd_state)
#else
#define YW_THREAD_FPSIMD(t)   ((t)->thread.fpsimd_state)
#endif

static int resolve_symbols(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -1;
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name_ptr) return -1;

    dyn_register_hw_bp = (reg_hw_bp_fn)kallsyms_lookup_name_ptr("register_user_hw_breakpoint");
    dyn_unregister_hw_bp = (unreg_hw_bp_fn)kallsyms_lookup_name_ptr("unregister_hw_breakpoint");
    dyn_fpsimd_preserve =
        (fpsimd_preserve_fn)kallsyms_lookup_name_ptr("fpsimd_preserve_current_state");
    if (!dyn_fpsimd_preserve)
        pr_warn("yunwu: fpsimd_preserve_current_state not found\n");

    dyn_fpsimd_flush =
        (fpsimd_flush_fn)kallsyms_lookup_name_ptr("fpsimd_flush_task_state");
    if (!dyn_fpsimd_flush)
        pr_warn("yunwu: fpsimd_flush_task_state not found\n");

    dyn_user_enable_ss = (user_ss_fn)kallsyms_lookup_name_ptr("user_enable_single_step");
    dyn_user_disable_ss = (user_ss_fn)kallsyms_lookup_name_ptr("user_disable_single_step");
    dyn_register_step_hook = (reg_step_hook_fn)kallsyms_lookup_name_ptr("register_user_step_hook");
    dyn_unregister_step_hook = (unreg_step_hook_fn)kallsyms_lookup_name_ptr("unregister_user_step_hook");
    if (!dyn_user_enable_ss || !dyn_user_disable_ss ||
        !dyn_register_step_hook || !dyn_unregister_step_hook)
        pr_warn("yunwu: single-step symbols not found, X bp falls back to one-shot\n");

    dyn_register_user_brk_hook = (reg_brk_hook_fn)kallsyms_lookup_name_ptr("register_user_break_hook");
    dyn_unregister_user_brk_hook = (unreg_brk_hook_fn)kallsyms_lookup_name_ptr("unregister_user_break_hook");
    if (!dyn_register_user_brk_hook || !dyn_unregister_user_brk_hook)
        pr_warn("yunwu: user break hook symbols not found, BRK bp disabled\n");

    if (dyn_register_hw_bp && dyn_unregister_hw_bp) return 0;
    return -1;
}

static void hide_module(void) {
#if ENABLE_HIDE_MODULE
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
#endif
}

static void enable_anti_ptrace(void) {
#if ENABLE_ANTI_PTRACE
#endif
}
static void disable_anti_ptrace(void) {
#if ENABLE_ANTI_PTRACE
#endif
}

static bool step_track_add(struct task_struct *task, struct perf_event *pev)
{
    unsigned long flags;
    int i;
    bool ok = false;
    spin_lock_irqsave(&step_track_lock, flags);
    for (i = 0; i < MAX_STEP_TRACK; i++) {
        if (!step_track[i].used) {
            get_task_struct(task);
            step_track[i].task = task;
            step_track[i].pev = pev;
            step_track[i].used = true;
            ok = true;
            break;
        }
    }
    spin_unlock_irqrestore(&step_track_lock, flags);
    return ok;
}

static struct perf_event *step_track_remove(struct task_struct *task)
{
    unsigned long flags;
    int i;
    struct perf_event *pev = NULL;
    spin_lock_irqsave(&step_track_lock, flags);
    for (i = 0; i < MAX_STEP_TRACK; i++) {
        if (step_track[i].used && step_track[i].task == task) {
            pev = step_track[i].pev;
            step_track[i].used = false;
            step_track[i].task = NULL;
            step_track[i].pev = NULL;
            put_task_struct(task);
            break;
        }
    }
    spin_unlock_irqrestore(&step_track_lock, flags);
    return pev;
}

static bool step_track_has_task(struct task_struct *task)
{
    unsigned long flags;
    int i;
    bool found = false;
    spin_lock_irqsave(&step_track_lock, flags);
    for (i = 0; i < MAX_STEP_TRACK; i++) {
        if (step_track[i].used && step_track[i].task == task) {
            found = true;
            break;
        }
    }
    spin_unlock_irqrestore(&step_track_lock, flags);
    return found;
}

static void step_track_remove_by_pev(struct perf_event *pev)
{
    unsigned long flags;
    int i;
    spin_lock_irqsave(&step_track_lock, flags);
    for (i = 0; i < MAX_STEP_TRACK; i++) {
        if (step_track[i].used && step_track[i].pev == pev) {
            put_task_struct(step_track[i].task);
            step_track[i].used = false;
            step_track[i].task = NULL;
            step_track[i].pev = NULL;
        }
    }
    spin_unlock_irqrestore(&step_track_lock, flags);
}

/* ============================================================
 * PTE 断点辅助函数
 * ============================================================ */
static pte_t *yw_get_pte_ptr(struct mm_struct *mm, unsigned long addr, pte_t *out_pte)
{
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;

    pgd = pgd_offset(mm, addr);
    if (pgd_none(*pgd) || pgd_bad(*pgd)) return NULL;
    p4d = p4d_offset(pgd, addr);
    if (p4d_none(*p4d) || p4d_bad(*p4d)) return NULL;
    pud = pud_offset(p4d, addr);
    if (pud_none(*pud) || pud_bad(*pud)) return NULL;
    pmd = pmd_offset(pud, addr);
    if (pmd_none(*pmd) || pmd_bad(*pmd)) return NULL;
    pte = pte_offset_map(pmd, addr);
    if (!pte) return NULL;
    if (out_pte) *out_pte = *pte;
    return pte;
}

static bool pte_step_track_add(struct task_struct *task, int pte_index)
{
    unsigned long flags;
    int i;
    bool ok = false;
    raw_spin_lock_irqsave(&pte_step_track_lock, flags);
    for (i = 0; i < MAX_PTE_STEP_TRACK; i++) {
        if (!pte_step_track[i].used) {
            get_task_struct(task);
            pte_step_track[i].task = task;
            pte_step_track[i].pte_index = pte_index;
            pte_step_track[i].used = true;
            ok = true;
            break;
        }
    }
    raw_spin_unlock_irqrestore(&pte_step_track_lock, flags);
    return ok;
}

static int pte_step_track_remove(struct task_struct *task)
{
    unsigned long flags;
    int i, idx = -1;
    raw_spin_lock_irqsave(&pte_step_track_lock, flags);
    for (i = 0; i < MAX_PTE_STEP_TRACK; i++) {
        if (pte_step_track[i].used && pte_step_track[i].task == task) {
            idx = pte_step_track[i].pte_index;
            pte_step_track[i].used = false;
            pte_step_track[i].task = NULL;
            pte_step_track[i].pte_index = -1;
            put_task_struct(task);
            break;
        }
    }
    raw_spin_unlock_irqrestore(&pte_step_track_lock, flags);
    return idx;
}

static void pte_step_track_remove_by_index(int pte_index)
{
    unsigned long flags;
    int i;
    raw_spin_lock_irqsave(&pte_step_track_lock, flags);
    for (i = 0; i < MAX_PTE_STEP_TRACK; i++) {
        if (pte_step_track[i].used && pte_step_track[i].pte_index == pte_index) {
            put_task_struct(pte_step_track[i].task);
            pte_step_track[i].used = false;
            pte_step_track[i].task = NULL;
            pte_step_track[i].pte_index = -1;
        }
    }
    raw_spin_unlock_irqrestore(&pte_step_track_lock, flags);
}

/* ============================================================
 * PTE 执行断点：BRK 软件断点 handler
 * ARM64 上 UXN + kprobe 方案不可行（EL0 指令权限故障走 do_bad_area 直接 SIGSEGV），
 * 改用 BRK 指令 + register_user_break_hook 拦截。
 * ============================================================ */
static int yunwu_brk_handler(struct pt_regs *regs, unsigned int esr)
{
    unsigned long addr = regs->pc;
    struct pte_bp_entry *entry;
    int i;
    unsigned long flags;

    for (i = 0; i < MAX_PTE_BPS; i++) {
        entry = &pte_bp_table[i];
        if (!entry->active || entry->type != 0 || entry->pid != current->pid)
            continue;
        if (entry->addr != addr)
            continue;

        /* 恢复原始指令 */
        u32 insn = entry->orig_insn;
        if (access_process_vm(current, addr, &insn, sizeof(insn), FOLL_WRITE) != sizeof(insn)) {
            pr_warn("yunwu: brk restore failed at 0x%lx\n", addr);
            return -1; /* 未处理，让内核发送 SIGTRAP 避免死循环 */
        }

        raw_spin_lock_irqsave(&entry->lock, flags);
        entry->stepping = true;
        raw_spin_unlock_irqrestore(&entry->lock, flags);

        /* GP 修改 */
        if (entry->auto_reg_enable)
            set_user_reg(regs, entry->reg_id, entry->reg_value);

        /* 浮点修改延迟到单步钩子（异常上下文不触碰硬件浮点） */
        if (entry->fp_reg_mask)
            entry->fp_modify_pending = true;

        /* 记录命中 */
        atomic_inc(&entry->hit_total);
        {
            struct yunwu_hit_detail d;
            memset(&d, 0, sizeof(d));
            d.task_id = entry->pid;
            d.hit_addr = addr;
            d.hit_time = ktime_get_real_seconds();
            d.bp_index = i;
            memcpy(d.regs_info.regs, regs->regs, sizeof(regs->regs));
            d.regs_info.sp = regs->sp;
            d.regs_info.pc = regs->pc;
            d.regs_info.pstate = regs->pstate;
            d.regs_info.orig_x0 = regs->orig_x0;
            d.regs_info.syscallno = regs->syscallno;
            memset(&d.fpsimd, 0, sizeof(d.fpsimd));
            memcpy(&entry->last_hit, &d, sizeof(d));
        }

        /* 加入单步跟踪 */
        if (!pte_step_track_add(current, i)) {
            pr_warn_ratelimited("yunwu: brk step track full, bp lost\n");
            raw_spin_lock_irqsave(&entry->lock, flags);
            entry->stepping = false;
            raw_spin_unlock_irqrestore(&entry->lock, flags);
            return 0; /* 已处理，但断点丢失 */
        }

        /* 开启单步（执行完原始指令后触发单步异常） */
        if (dyn_user_enable_ss)
            dyn_user_enable_ss(current);

        return 0; /* 已处理，内核不发送 SIGTRAP */
    }

    return -1; /* 未处理，继续正常流程（SIGTRAP） */
}

/* ============================================================
 * 单步钩子（硬件断点 + PTE 断点统一处理）
 * ============================================================ */
static int yunwu_step_fn(struct pt_regs *regs, unsigned int esr)
{
    int pte_idx;
    struct perf_event *pev;
    struct bp_entry *entry;

    /* 优先处理 PTE 断点单步 */
    pte_idx = pte_step_track_remove(current);
    if (pte_idx >= 0 && pte_idx < MAX_PTE_BPS) {
        struct pte_bp_entry *pte_entry = &pte_bp_table[pte_idx];
        unsigned long flags;

        raw_spin_lock_irqsave(&pte_entry->lock, flags);
        pte_entry->stepping = false;
        raw_spin_unlock_irqrestore(&pte_entry->lock, flags);

        if (pte_entry->type == 0) {
            /* 执行断点: 重新写入 BRK */
            u32 brk_insn = YW_BRK_INSN;
            int n = access_process_vm(current, pte_entry->addr, &brk_insn, sizeof(brk_insn), FOLL_WRITE);
            if (n != sizeof(brk_insn))
                pr_warn("yunwu: brk re-arm failed at 0x%lx\n", pte_entry->addr);
        } else if (pte_entry->type == 1) {
            /* 写断点: 重新 walk page table 并设置 RDONLY
             * 使用 current->mm，绝不使用 entry->mm（避免悬空指针） */
            struct mm_struct *mm = current->mm;
            if (mm) {
                yw_mmap_write_lock(mm);
                pte_t *pte_ptr = yw_get_pte_ptr(mm, pte_entry->addr, NULL);
                if (pte_ptr) {
                    pte_t new_pte = pte_wrprotect(pte_entry->orig_pte);
                    WRITE_ONCE(*pte_ptr, new_pte);
                    yw_flush_tlb_va_is(pte_entry->addr);
                    pte_unmap(pte_ptr);
                }
                yw_mmap_write_unlock(mm);
            }
        }

        /* 安全浮点修改（仅修改内存副本，绝不调用 dyn_fpsimd_preserve） */
        if (pte_entry->fp_modify_pending) {
            pte_entry->fp_modify_pending = false;
            if (test_thread_flag(TIF_FOREIGN_FPSTATE)) {
                struct user_fpsimd_state *fpsimd = &YW_THREAD_FPSIMD(current);
                u64 local_mask;
                u64 local_values[32][2];
                u8 local_size;
                unsigned seq;
                int j;

                do {
                    seq = read_seqcount_begin(&pte_entry->fp_seq);
                    local_mask = pte_entry->fp_reg_mask;
                    memcpy(local_values, pte_entry->fp_reg_values, sizeof(local_values));
                    local_size = pte_entry->fp_reg_size;
                } while (read_seqcount_retry(&pte_entry->fp_seq, seq));

                for (j = 0; j < 32; j++) {
                    if (local_mask & (1ULL << j)) {
                        __uint128_t cur = fpsimd->vregs[j];
                        if (local_size == 0) {
                            cur = (cur & ~((__uint128_t)0xFFFFFFFFULL)) |
                                  (u32)(local_values[j][0]);
                        } else if (local_size == 1) {
                            cur = (cur & ~((__uint128_t)0xFFFFFFFFFFFFFFFFULL)) |
                                  local_values[j][0];
                        } else {
                            cur = ((__uint128_t)local_values[j][1] << 64) |
                                  local_values[j][0]);
                        }
                        fpsimd->vregs[j] = cur;
                    }
                }
                set_thread_flag(TIF_FOREIGN_FPSTATE);
            } else {
                pr_warn_ratelimited("yunwu: pte bp fp modify skipped, hw state active\n");
            }
        }

        if (dyn_user_disable_ss)
            dyn_user_disable_ss(current);

        return DBG_HOOK_HANDLED;
    }

    /* 硬件断点单步 */
    pev = step_track_remove(current);
    if (!pev)
        return DBG_HOOK_ERROR;

    if (dyn_user_disable_ss)
        dyn_user_disable_ss(current);

    entry = pev->overflow_handler_context;
    if (entry && atomic_read(&entry->user_enabled))
        perf_event_enable(pev);

    return DBG_HOOK_HANDLED;
}

/* ============================================================
 * PTE 写断点：kprobe 挂钩 do_page_fault
 * 注意：执行断点 (type=0) 已改用 BRK 软件断点，此 handler 仅处理写断点 (type=1)
 * 不再保存 pte_ptr，每次重新 walk page table，使用 current->mm 避免悬空指针
 * ============================================================ */
static int pte_bp_kprobe_pre(struct kprobe *p, struct pt_regs *regs)
{
    unsigned long addr = current->thread.fault_address;
    struct mm_struct *mm = current->mm;
    struct pte_bp_entry *entry;
    int i;
    unsigned long flags;

    if (!mm)
        return 0;

    /* ARM64 do_page_fault 第一个参数 x0 = fault address，作为 fallback */
    if (!addr && regs)
        addr = regs->regs[0];
    if (!addr)
        return 0;

    for (i = 0; i < MAX_PTE_BPS; i++) {
        entry = &pte_bp_table[i];

        raw_spin_lock_irqsave(&entry->lock, flags);
        if (!entry->active || entry->stepping || entry->pid != current->pid ||
            (addr & PAGE_MASK) != (entry->addr & PAGE_MASK) || entry->type != 1) {
            raw_spin_unlock_irqrestore(&entry->lock, flags);
            continue;
        }
        raw_spin_unlock_irqrestore(&entry->lock, flags);

        /* 重新 walk page table（绝不使用 entry->mm，避免 use-after-free） */
        if (!yw_mmap_write_trylock(mm)) {
            pr_warn_ratelimited("yunwu: w bp trylock failed, skip hit\n");
            continue;
        }

        pte_t *pte_ptr = yw_get_pte_ptr(mm, entry->addr, NULL);
        if (!pte_ptr) {
            yw_mmap_write_unlock(mm);
            continue;
        }

        pte_t cur_pte = READ_ONCE(*pte_ptr);

        /* 验证 PFN 匹配（确保是同一物理页） */
        if (pte_pfn(cur_pte) != pte_pfn(entry->orig_pte)) {
            pte_unmap(pte_ptr);
            yw_mmap_write_unlock(mm);
            continue;
        }

        /* 检查是否处于断点状态（present 但不可写） */
        if (!pte_present(cur_pte) || pte_write(cur_pte)) {
            pte_unmap(pte_ptr);
            yw_mmap_write_unlock(mm);
            continue;
        }

        /* 恢复原始 PTE（可写） */
        WRITE_ONCE(*pte_ptr, entry->orig_pte);
        yw_flush_tlb_local(addr);  /* 仅刷新当前 CPU，不广播，原子上下文安全 */
        pte_unmap(pte_ptr);
        yw_mmap_write_unlock(mm);

        /* 标记单步中 */
        raw_spin_lock_irqsave(&entry->lock, flags);
        entry->stepping = true;
        raw_spin_unlock_irqrestore(&entry->lock, flags);

        /* GP 修改：FP 模式(fp_reg_mask!=0)时跳过，避免意外清零 GP */
        if (entry->auto_reg_enable && !entry->fp_reg_mask && regs)
            set_user_reg(regs, entry->reg_id, entry->reg_value);

        /* 浮点修改延迟到单步钩子（kprobe 原子上下文绝不触碰硬件浮点） */
        if (entry->fp_reg_mask)
            entry->fp_modify_pending = true;

        /* 记录命中 */
        atomic_inc(&entry->hit_total);
        {
            struct yunwu_hit_detail d;
            memset(&d, 0, sizeof(d));
            d.task_id = entry->pid;
            d.hit_addr = addr;
            d.hit_time = ktime_get_real_seconds();
            d.bp_index = i;
            if (regs) {
                memcpy(d.regs_info.regs, regs->regs, sizeof(regs->regs));
                d.regs_info.sp = regs->sp;
                d.regs_info.pc = regs->pc;
                d.regs_info.pstate = regs->pstate;
                d.regs_info.orig_x0 = regs->orig_x0;
                d.regs_info.syscallno = regs->syscallno;
            }
            memset(&d.fpsimd, 0, sizeof(d.fpsimd));
            memcpy(&entry->last_hit, &d, sizeof(d));
        }

        /* 加入单步跟踪 */
        if (!pte_step_track_add(current, i)) {
            pr_warn_ratelimited("yunwu: w bp step track full, re-arm without step\n");
            /* 跟踪表满：重新武装写保护，不进入单步（本次命中丢失） */
            if (mm) {
                yw_mmap_write_lock(mm);
                pte_t *pte_ptr2 = yw_get_pte_ptr(mm, entry->addr, NULL);
                if (pte_ptr2) {
                    pte_t new_pte = pte_wrprotect(entry->orig_pte);
                    WRITE_ONCE(*pte_ptr2, new_pte);
                    yw_flush_tlb_local(entry->addr);
                    pte_unmap(pte_ptr2);
                }
                yw_mmap_write_unlock(mm);
            }
            raw_spin_lock_irqsave(&entry->lock, flags);
            entry->stepping = false;
            raw_spin_unlock_irqrestore(&entry->lock, flags);
            continue;
        }

        /* 开启单步 */
        if (dyn_user_enable_ss)
            dyn_user_enable_ss(current);

        return 0;   /* 让 do_page_fault 正常运行：PTE 已恢复，它会正常解析并返回 */
    }

    return 0;
}

/* ============================================================
 * PTE 断点安装/卸载/挂起/恢复辅助函数
 * ============================================================ */
static int pte_bp_install_exec(struct pte_bp_entry *entry, struct task_struct *task, unsigned long addr)
{
    u32 brk_insn = YW_BRK_INSN;
    u32 orig;

    if (access_process_vm(task, addr, &orig, sizeof(orig), 0) != sizeof(orig))
        return -EFAULT;

    if (access_process_vm(task, addr, &brk_insn, sizeof(brk_insn), FOLL_WRITE) != sizeof(brk_insn))
        return -EFAULT;

    entry->orig_insn = orig;
    return 0;
}

static int pte_bp_remove_exec(struct pte_bp_entry *entry)
{
    struct task_struct *task = get_task_by_pid(entry->pid);
    if (!task) return -ESRCH;

    u32 insn = entry->orig_insn;
    int n = access_process_vm(task, entry->addr, &insn, sizeof(insn), FOLL_WRITE);
    if (n != sizeof(insn))
        pr_warn("yunwu: brk remove restore failed at 0x%lx, ret=%d\n", entry->addr, n);

    put_task_struct(task);
    return 0;
}

static struct task_struct *get_task_by_pid(pid_t pid) {
    struct pid *p = find_get_pid(pid);
    struct task_struct *task = NULL;
    if (p) {
        task = get_pid_task(p, PIDTYPE_PID);
        put_pid(p);
    }
    return task;
}

static int pte_bp_install(struct yunwu_pte_bp_args *args, int *out_index)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int free_slot = -1, i, ret = 0;
    struct pte_bp_entry *entry;

    task = get_task_by_pid(args->pid);
    if (!task) return -ESRCH;
    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); return -EINVAL; }

    mutex_lock(&pte_bp_mutex);
    for (i = 0; i < MAX_PTE_BPS; i++) {
        if (!pte_bp_table[i].active) { free_slot = i; break; }
    }
    if (free_slot < 0) { ret = -EBUSY; goto out_put; }

    entry = &pte_bp_table[free_slot];
    memset(entry, 0, sizeof(*entry));
    entry->pid = args->pid;
    entry->addr = args->addr;
    entry->type = args->type;
    entry->mm = mm;  /* 保存引用计数，卸载时 mmput */
    atomic_set(&entry->hit_total, 0);
    seqcount_init(&entry->fp_seq);
    raw_spin_lock_init(&entry->lock);
    entry->active = true;
    entry->stepping = false;
    entry->fp_modify_pending = false;

    if (args->type == 0) {
        /* 执行断点: BRK 软件断点 */
        ret = pte_bp_install_exec(entry, task, args->addr);
        if (ret < 0) {
            entry->active = false;
            goto out_put;
        }
    } else if (args->type == 1) {
        /* 写断点: PTE 写保护 */
        yw_mmap_write_lock(mm);
        pte_t *pte_ptr = yw_get_pte_ptr(mm, args->addr, &entry->orig_pte);
        if (!pte_ptr) {
            ret = -EFAULT;
            yw_mmap_write_unlock(mm);
            entry->active = false;
            goto out_put;
        }
        if (!pte_present(entry->orig_pte)) {
            ret = -ENXIO;
            pte_unmap(pte_ptr);
            yw_mmap_write_unlock(mm);
            entry->active = false;
            goto out_put;
        }
        if (!pte_write(entry->orig_pte)) {
            pr_warn("yunwu: w bp install addr 0x%lx not writable, may not trigger\n", args->addr);
        }
        pte_t new_pte = pte_wrprotect(entry->orig_pte);
        WRITE_ONCE(*pte_ptr, new_pte);
        yw_flush_tlb_global();  /* 仅在可睡眠上下文使用 */
        pte_unmap(pte_ptr);
        yw_mmap_write_unlock(mm);
    } else {
        ret = -EINVAL;
        entry->active = false;
        goto out_put;
    }

    *out_index = free_slot;
    pr_info("yunwu: PTE BP installed slot=%d pid=%d addr=0x%lx type=%u\n",
            free_slot, args->pid, args->addr, args->type);

out_put:
    mutex_unlock(&pte_bp_mutex);
    put_task_struct(task);
    if (ret && mm) mmput(mm);
    return ret;
}

static int pte_bp_remove(int index)
{
    struct pte_bp_entry *entry;
    int ret = 0;

    if (index < 0 || index >= MAX_PTE_BPS) return -EINVAL;
    mutex_lock(&pte_bp_mutex);
    entry = &pte_bp_table[index];
    if (!entry->active) { ret = -ENOENT; goto out; }

    entry->active = false;
    pte_step_track_remove_by_index(index);

    if (entry->type == 0) {
        /* 执行断点: 恢复原始指令 */
        pte_bp_remove_exec(entry);
    } else if (entry->type == 1) {
        /* 写断点: 恢复原始 PTE */
        if (entry->mm) {
            yw_mmap_write_lock(entry->mm);
            pte_t *pte_ptr = yw_get_pte_ptr(entry->mm, entry->addr, NULL);
            if (pte_ptr) {
                WRITE_ONCE(*pte_ptr, entry->orig_pte);
                yw_flush_tlb_global();
                pte_unmap(pte_ptr);
            }
            yw_mmap_write_unlock(entry->mm);
            mmput(entry->mm);
        }
    }
    entry->mm = NULL;

out:
    mutex_unlock(&pte_bp_mutex);
    return ret;
}

static int pte_bp_suspend(int index)
{
    struct pte_bp_entry *entry;

    if (index < 0 || index >= MAX_PTE_BPS) return -EINVAL;
    mutex_lock(&pte_bp_mutex);
    entry = &pte_bp_table[index];
    if (!entry->active) { mutex_unlock(&pte_bp_mutex); return -ENOENT; }

    if (entry->type == 0) {
        pte_bp_remove_exec(entry);
    } else if (entry->type == 1) {
        if (entry->mm) {
            yw_mmap_write_lock(entry->mm);
            pte_t *pte_ptr = yw_get_pte_ptr(entry->mm, entry->addr, NULL);
            if (pte_ptr) {
                WRITE_ONCE(*pte_ptr, entry->orig_pte);
                yw_flush_tlb_global();
                pte_unmap(pte_ptr);
            }
            yw_mmap_write_unlock(entry->mm);
        }
    }

    mutex_unlock(&pte_bp_mutex);
    return 0;
}

static int pte_bp_resume(int index)
{
    struct pte_bp_entry *entry;

    if (index < 0 || index >= MAX_PTE_BPS) return -EINVAL;
    mutex_lock(&pte_bp_mutex);
    entry = &pte_bp_table[index];
    if (!entry->active) { mutex_unlock(&pte_bp_mutex); return -ENOENT; }
    if (entry->stepping) { mutex_unlock(&pte_bp_mutex); return -EBUSY; }

    if (entry->type == 0) {
        struct task_struct *task = get_task_by_pid(entry->pid);
        if (task) {
            u32 brk_insn = YW_BRK_INSN;
            access_process_vm(task, entry->addr, &brk_insn, sizeof(brk_insn), FOLL_WRITE);
            put_task_struct(task);
        }
    } else if (entry->type == 1) {
        if (entry->mm) {
            yw_mmap_write_lock(entry->mm);
            pte_t *pte_ptr = yw_get_pte_ptr(entry->mm, entry->addr, NULL);
            if (pte_ptr) {
                pte_t new_pte = pte_wrprotect(entry->orig_pte);
                WRITE_ONCE(*pte_ptr, new_pte);
                yw_flush_tlb_global();
                pte_unmap(pte_ptr);
            }
            yw_mmap_write_unlock(entry->mm);
        }
    }

    mutex_unlock(&pte_bp_mutex);
    return 0;
}

/* ============================================================
 * 物理内存读写
 * ============================================================ */
static int do_memory_read_phys(struct task_struct *task, unsigned long addr,
                                void __user *user_buf, size_t size)
{
    struct mm_struct *mm;
    size_t remain = size;
    int total = 0;
    char *kbuf;

    if (size == 0 || size > MAX_RW_SIZE)
        return -EINVAL;

    kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    mm = get_task_mm(task);
    if (!mm) {
        kfree(kbuf);
        return -EINVAL;
    }

    while (remain > 0) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        struct page *page;
        void *vaddr;
        size_t offset, sz;
        bool need_kunmap = false;
        pte_t pte_val;

        offset = addr & ~PAGE_MASK;
        sz = min(remain, (size_t)(PAGE_SIZE - offset));

        yw_mmap_read_lock(mm);

        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            yw_mmap_read_unlock(mm);
            break;
        }
        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
            yw_mmap_read_unlock(mm);
            break;
        }
        pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) {
            yw_mmap_read_unlock(mm);
            break;
        }
        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) {
            yw_mmap_read_unlock(mm);
            break;
        }

        pte = pte_offset_map(pmd, addr);
        if (!pte) {
            yw_mmap_read_unlock(mm);
            break;
        }
        pte_val = *pte;
        if (pte_none(pte_val) || !pte_present(pte_val)) {
            pte_unmap(pte);
            yw_mmap_read_unlock(mm);
            break;
        }
        if (!pte_read(pte_val)) {
            pte_unmap(pte);
            yw_mmap_read_unlock(mm);
            break;
        }

        page = pte_page(pte_val);
        flush_dcache_page(page);

        vaddr = page_address(page);
        if (!vaddr) {
            vaddr = yw_kmap_page(page);
            need_kunmap = true;
        }
        if (!vaddr) {
            pte_unmap(pte);
            yw_mmap_read_unlock(mm);
            break;
        }

        memcpy(kbuf, (char *)vaddr + offset, sz);

        if (need_kunmap)
            yw_kunmap_page(vaddr);
        pte_unmap(pte);
        yw_mmap_read_unlock(mm);

        if (copy_to_user((char __user *)user_buf + total, kbuf, sz))
            break;

        addr += sz;
        total += sz;
        remain -= sz;
    }

    mmput(mm);
    kfree(kbuf);
    return total > 0 ? total : -EFAULT;
}

static int do_memory_write_phys(struct task_struct *task, unsigned long addr,
                                 void __user *user_buf, size_t size)
{
    struct mm_struct *mm;
    size_t remain = size;
    int total = 0;
    char *kbuf;

    if (size == 0 || size > MAX_RW_SIZE)
        return -EINVAL;

    kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    mm = get_task_mm(task);
    if (!mm) {
        kfree(kbuf);
        return -EINVAL;
    }

    while (remain > 0) {
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *pte;
        struct page *page;
        void *vaddr;
        size_t offset, chunk;
        bool need_kunmap = false;
        pte_t pte_val;

        offset = addr & ~PAGE_MASK;
        chunk = min(remain, (size_t)(PAGE_SIZE - offset));

        if (copy_from_user(kbuf, (char __user *)user_buf + total, chunk))
            break;

        yw_mmap_write_lock(mm);

        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            yw_mmap_write_unlock(mm);
            break;
        }
        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
            yw_mmap_write_unlock(mm);
            break;
        }
        pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) {
            yw_mmap_write_unlock(mm);
            break;
        }
        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) {
            yw_mmap_write_unlock(mm);
            break;
        }

        pte = pte_offset_map(pmd, addr);
        if (!pte) {
            yw_mmap_write_unlock(mm);
            break;
        }
        pte_val = *pte;
        if (pte_none(pte_val) || !pte_present(pte_val)) {
            pte_unmap(pte);
            yw_mmap_write_unlock(mm);
            break;
        }
        if (!pte_write(pte_val)) {
            pte_unmap(pte);
            yw_mmap_write_unlock(mm);
            break;
        }

        page = pte_page(pte_val);
        vaddr = page_address(page);
        if (!vaddr) {
            vaddr = yw_kmap_page(page);
            need_kunmap = true;
        }
        if (!vaddr) {
            pte_unmap(pte);
            yw_mmap_write_unlock(mm);
            break;
        }

        memcpy((char *)vaddr + offset, kbuf, chunk);
        flush_dcache_page(page);

        if (need_kunmap)
            yw_kunmap_page(vaddr);
        pte_unmap(pte);
        yw_mmap_write_unlock(mm);

        addr += chunk;
        total += chunk;
        remain -= chunk;
    }

    mmput(mm);
    kfree(kbuf);
    return total > 0 ? total : -EFAULT;
}

static int do_memory_read(pid_t pid, unsigned long addr,
                          void __user *user_buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    int ret;

    if (size == 0 || size > MAX_RW_SIZE)
        return -EINVAL;

    task = get_task_by_pid(pid);
    if (!task) return -ESRCH;
    if (!task->mm) { put_task_struct(task); return -EINVAL; }

    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); return -EINVAL; }

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) { mmput(mm); put_task_struct(task); return -ENOMEM; }

    ret = access_process_vm(task, addr, kbuf, size, 0);
    if (ret > 0) {
        if (copy_to_user(user_buf, kbuf, ret))
            ret = -EFAULT;
    } else {
        int phys_ret = do_memory_read_phys(task, addr, user_buf, size);
        if (phys_ret > 0)
            ret = phys_ret;
        else
            ret = -EFAULT;
    }

    kfree(kbuf);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

static int do_memory_write(pid_t pid, unsigned long addr,
                           void __user *user_buf, size_t size)
{
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    int ret;

    if (size == 0 || size > MAX_RW_SIZE)
        return -EINVAL;

    task = get_task_by_pid(pid);
    if (!task) return -ESRCH;
    if (!task->mm) { put_task_struct(task); return -EINVAL; }

    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); return -EINVAL; }

    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) { mmput(mm); put_task_struct(task); return -ENOMEM; }

    if (copy_from_user(kbuf, user_buf, size)) {
        kfree(kbuf);
        mmput(mm);
        put_task_struct(task);
        return -EFAULT;
    }

    ret = access_process_vm(task, addr, kbuf, size, FOLL_WRITE);
    if (ret <= 0) {
        int phys_ret = do_memory_write_phys(task, addr, user_buf, size);
        if (phys_ret > 0)
            ret = phys_ret;
        else
            ret = -EFAULT;
    }

    kfree(kbuf);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

/* ============================================================
 * 获取模块基址
 * ============================================================ */
static unsigned long get_module_base(pid_t pid, char *name) {
    struct task_struct *task;
    struct mm_struct *mm;
    unsigned long base = 0;
    struct pid *pid_struct = find_get_pid(pid);
    if (!pid_struct) return 0;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) return 0;

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return 0;
    }

    yw_mmap_read_lock(mm);
    {
        YW_VMA_ITER_DECL(mm);
        struct vm_area_struct *vma;
        YW_FOR_EACH_VMA(vma) {
            if (vma->vm_file) {
                char buf[256];
                char *path = d_path(&vma->vm_file->f_path, buf, sizeof(buf) - 1);
                if (!IS_ERR(path) && strcmp(kbasename(path), name) == 0) {
                    base = vma->vm_start;
                    break;
                }
            }
        }
    }
    yw_mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return base;
}

/* ============================================================
 * 抓取当前任务的浮点寄存器现场
 * ============================================================ */
static void yunwu_capture_fpsimd(struct yunwu_fpsimd_state *out)
{
    if (!test_thread_flag(TIF_FOREIGN_FPSTATE) && dyn_fpsimd_preserve)
        dyn_fpsimd_preserve();
    memcpy(out, &YW_THREAD_FPSIMD(current), sizeof(*out));
}

/* ============================================================
 * 硬件断点命中处理
 * ============================================================ */
static void yunwu_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
                             struct pt_regs *regs) {
    struct bp_entry *entry = bp->overflow_handler_context;
    u64 hook_pc;
    int bp_idx;

    if (!entry) return;
    bp_idx = entry->index;

    hook_pc = atomic64_read(&global_hook_pc);
    if (hook_pc) {
        regs->pc = hook_pc;
        return;
    }

    atomic_inc(&entry->in_handler);

    if (entry->type == 0) {
        if (step_hook_registered && dyn_user_enable_ss &&
            step_track_add(current, bp)) {
            perf_event_disable(bp);
            dyn_user_enable_ss(current);
        } else {
            perf_event_disable(bp);
        }
    }

    pr_info_ratelimited("yunwu: bp hit, idx=%d, pc=0x%llx, tid=%d\n",
                        bp_idx, regs->pc, current->pid);

    if (entry->auto_reg_enable && regs)
        set_user_reg(regs, entry->reg_id, entry->reg_value);

    if (entry->fp_reg_mask) {
        if (!dyn_fpsimd_preserve) {
            pr_warn_ratelimited("yunwu: fp modify skipped, fpsimd_preserve unavailable\n");
        } else {
            struct user_fpsimd_state *fpsimd;
            u64 local_mask;
            u64 local_values[32][2];
            u8 local_size;
            unsigned seq;
            int i;

            do {
                seq = read_seqcount_begin(&entry->fp_seq);
                local_mask = entry->fp_reg_mask;
                memcpy(local_values, entry->fp_reg_values, sizeof(local_values));
                local_size = entry->fp_reg_size;
            } while (read_seqcount_retry(&entry->fp_seq, seq));

            if (!local_mask)
                goto skip_fp;

            dyn_fpsimd_preserve();
            fpsimd = &YW_THREAD_FPSIMD(current);

            for (i = 0; i < 32; i++) {
                if (local_mask & (1ULL << i)) {
                    __uint128_t cur = fpsimd->vregs[i];
                    if (local_size == 0) {
                        cur = (cur & ~((__uint128_t)0xFFFFFFFFULL)) |
                              (u32)(local_values[i][0]);
                    } else if (local_size == 1) {
                        cur = (cur & ~((__uint128_t)0xFFFFFFFFFFFFFFFFULL)) |
                              local_values[i][0];
                    } else {
                        cur = ((__uint128_t)local_values[i][1] << 64) |
                              local_values[i][0];
                    }
                    fpsimd->vregs[i] = cur;
                }
            }

            if (dyn_fpsimd_flush)
                dyn_fpsimd_flush(current);
            else
                set_thread_flag(TIF_FOREIGN_FPSTATE);
        }
    }
    skip_fp:;

    atomic_inc(&entry->hit_total);

    {
        struct yunwu_hit_detail d;
        memset(&d, 0, sizeof(d));
        d.task_id = (u64)entry->pid;
        d.hit_addr = regs->pc;
        d.hit_time = ktime_get_real_seconds();
        d.bp_index = bp_idx;
        memcpy(d.regs_info.regs, regs->regs, sizeof(regs->regs));
        d.regs_info.sp = regs->sp;
        d.regs_info.pc = regs->pc;
        d.regs_info.pstate = regs->pstate;
        d.regs_info.orig_x0 = regs->orig_x0;
        d.regs_info.syscallno = regs->syscallno;
        yunwu_capture_fpsimd(&d.fpsimd);
        memcpy(&entry->last_hit, &d, sizeof(d));
    }

    atomic_dec(&entry->in_handler);
}

/* ============================================================
 * 硬件断点管理
 * ============================================================ */
static void bp_entry_remove_all_events(struct bp_entry *entry) {
    struct bp_thread_event *pos, *n;
    atomic_set(&entry->user_enabled, 0);
    list_for_each_entry_safe(pos, n, &entry->events, list) {
        if (pos->pevent && dyn_unregister_hw_bp) {
            step_track_remove_by_pev(pos->pevent);
            dyn_unregister_hw_bp(pos->pevent);
        }
        if (pos->task)
            put_task_struct(pos->task);
        list_del(&pos->list);
        kfree(pos);
    }
    INIT_LIST_HEAD(&entry->events);
}

static int install_hw_bp(struct yunwu_bp_args *args, int *out_index) {
    struct perf_event_attr attr = {0};
    struct task_struct *leader, *task;
    struct pid *pid_struct;
    struct bp_entry *entry;
    int free_slot = -1, i;
    int ret = 0;
    struct temp_task_node {
        struct task_struct *task;
        struct list_head list;
    };
    LIST_HEAD(temp_task_list);

    if (!dyn_register_hw_bp) return -ENODEV;

    pid_struct = find_get_pid(args->pid);
    if (!pid_struct) return -ESRCH;
    leader = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!leader) return -ESRCH;

    mutex_lock(&bp_mutex);

    for (i = 0; i < MAX_BREAKPOINTS; i++)
        if (list_empty(&bp_table[i].events)) { free_slot = i; break; }
    if (free_slot < 0) {
        mutex_unlock(&bp_mutex);
        put_task_struct(leader);
        return -EBUSY;
    }

    entry = &bp_table[free_slot];
    bp_entry_remove_all_events(entry);

    attr.bp_addr = args->addr;
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.sample_period = 1;
    attr.disabled = 1;
    switch (args->len) {
    case 1: attr.bp_len = HW_BREAKPOINT_LEN_1; break;
    case 2: attr.bp_len = HW_BREAKPOINT_LEN_2; break;
    case 4: attr.bp_len = HW_BREAKPOINT_LEN_4; break;
    case 8: attr.bp_len = HW_BREAKPOINT_LEN_8; break;
    default: mutex_unlock(&bp_mutex); put_task_struct(leader); return -EINVAL;
    }
    switch (args->type) {
    case 0: attr.bp_type = HW_BREAKPOINT_X; break;
    case 1: attr.bp_type = HW_BREAKPOINT_W; break;
    case 2: attr.bp_type = HW_BREAKPOINT_RW; break;
    default: mutex_unlock(&bp_mutex); put_task_struct(leader); return -EINVAL;
    }

    rcu_read_lock();
    for_each_thread(leader, task) {
        struct temp_task_node *tn = kmalloc(sizeof(*tn), GFP_ATOMIC);
        if (!tn) {
            rcu_read_unlock();
            ret = -ENOMEM;
            goto cleanup_temp;
        }
        get_task_struct(task);
        tn->task = task;
        list_add_tail(&tn->list, &temp_task_list);
    }
    rcu_read_unlock();

    {
        struct temp_task_node *tn, *tn_n;
        list_for_each_entry_safe(tn, tn_n, &temp_task_list, list) {
            struct bp_thread_event *ev_node;
            struct perf_event *pevent;

            pevent = dyn_register_hw_bp(&attr, yunwu_bp_handler, entry, tn->task);
            if (IS_ERR(pevent)) {
                ret = PTR_ERR(pevent);
                pr_err("yunwu: register fail tid %d err %d\n", tn->task->pid, ret);
                put_task_struct(tn->task);
                list_del(&tn->list);
                kfree(tn);
                goto rollback;
            } else if (pevent == NULL) {
                ret = -ENODEV;
                pr_err("yunwu: NULL pevent tid %d\n", tn->task->pid);
                put_task_struct(tn->task);
                list_del(&tn->list);
                kfree(tn);
                goto rollback;
            }

            ev_node = kmalloc(sizeof(*ev_node), GFP_KERNEL);
            if (!ev_node) {
                dyn_unregister_hw_bp(pevent);
                put_task_struct(tn->task);
                ret = -ENOMEM;
                list_del(&tn->list);
                kfree(tn);
                goto rollback;
            }

            ev_node->pevent = pevent;
            ev_node->task = tn->task;
            list_add_tail(&ev_node->list, &entry->events);
            list_del(&tn->list);
            kfree(tn);

            pr_info("yunwu: registered tid %d, pevent=%px\n", ev_node->task->pid, ev_node->pevent);
        }
    }

    entry->pid = args->pid;
    entry->addr = args->addr;
    entry->type = args->type;
    entry->len = args->len;
    entry->auto_reg_enable = false;
    entry->index = free_slot;
    entry->fp_reg_mask = 0;
    memset(entry->fp_reg_values, 0, sizeof(entry->fp_reg_values));
    entry->fp_reg_size = 0;
    seqcount_init(&entry->fp_seq);
    atomic_set(&entry->hit_total, 0);
    atomic_set(&entry->in_handler, 0);
    atomic_set(&entry->user_enabled, 0);
    memset(&entry->last_hit, 0, sizeof(entry->last_hit));
    atomic_set(&entry->head, 0);
    atomic_set(&entry->tail, 0);
    raw_spin_lock_init(&entry->hit_lock);

    *out_index = free_slot;
    mutex_unlock(&bp_mutex);
    put_task_struct(leader);
    pr_info("yunwu: install success slot %d addr 0x%lx\n", free_slot, args->addr);
    return 0;

rollback:
    bp_entry_remove_all_events(entry);
cleanup_temp:
    {
        struct temp_task_node *tn, *tn_n;
        list_for_each_entry_safe(tn, tn_n, &temp_task_list, list) {
            put_task_struct(tn->task);
            list_del(&tn->list);
            kfree(tn);
        }
    }
    mutex_unlock(&bp_mutex);
    put_task_struct(leader);
    return ret;
}

static int remove_hw_bp(int index) {
    if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
    mutex_lock(&bp_mutex);
    bp_entry_remove_all_events(&bp_table[index]);
    mutex_unlock(&bp_mutex);
    return 0;
}

static int suspend_hw_bp(int index) {
    struct bp_entry *entry;
    struct bp_thread_event *pos;
    if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
    mutex_lock(&bp_mutex);
    entry = &bp_table[index];
    atomic_set(&entry->user_enabled, 0);
    list_for_each_entry(pos, &entry->events, list) {
        if (pos->pevent) perf_event_disable(pos->pevent);
    }
    mutex_unlock(&bp_mutex);
    return 0;
}

static int resume_hw_bp(int index) {
    struct bp_entry *entry;
    struct bp_thread_event *pos;
    if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
    mutex_lock(&bp_mutex);
    entry = &bp_table[index];
    atomic_set(&entry->user_enabled, 1);
    list_for_each_entry(pos, &entry->events, list) {
        if (pos->pevent) {
            if (atomic_read(&entry->in_handler) == 0 &&
                !step_track_has_task(pos->task)) {
                perf_event_enable(pos->pevent);
            }
        }
    }
    mutex_unlock(&bp_mutex);
    return 0;
}

/* ============================================================
 * ioctl 处理
 * ============================================================ */
static long yunwu_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0, idx;
    switch (cmd) {
    case YUNWU_READ_MEM: {
        struct yunwu_mem_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        ret = do_memory_read(args.pid, args.addr, (void __user *)args.data_ptr, args.size);
        if (ret > 0) ret = 0;
        else if (ret == 0) ret = -ENODATA;
        break;
    }
    case YUNWU_WRITE_MEM: {
        struct yunwu_mem_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        ret = do_memory_write(args.pid, args.addr, (void __user *)args.data_ptr, args.size);
        if (ret > 0) ret = 0;
        else if (ret == 0) ret = -ENODATA;
        break;
    }
    case YUNWU_MODULE_BASE: {
        struct yunwu_module_base_args args; char name[256] = {0};
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        if (strncpy_from_user(name, (const char __user *)args.name_ptr, sizeof(name)-1) < 0)
            return -EFAULT;
        args.base = get_module_base(args.pid, name);
        if (copy_to_user((void __user *)arg, &args, sizeof(args))) return -EFAULT;
        break;
    }
    case YUNWU_SET_BP: {
        struct yunwu_bp_args bp_args;
        if (copy_from_user(&bp_args, (void __user *)arg, sizeof(bp_args))) return -EFAULT;
        ret = install_hw_bp(&bp_args, &bp_args.out_index);
        if (ret == 0 && copy_to_user((void __user *)arg, &bp_args, sizeof(bp_args)))
            ret = -EFAULT;
        break;
    }
    case YUNWU_DEL_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = remove_hw_bp(idx);
        break;
    case YUNWU_WAIT_BP: {
        return -EAGAIN;
    }
    case YUNWU_SET_AUTO_REG: {
        struct yunwu_auto_reg_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        if (args.bp_index < 0 || args.bp_index >= MAX_BREAKPOINTS) return -EINVAL;
        mutex_lock(&bp_mutex);
        if (list_empty(&bp_table[args.bp_index].events)) {
            mutex_unlock(&bp_mutex);
            return -EINVAL;
        }
        write_seqcount_begin(&bp_table[args.bp_index].fp_seq);
        bp_table[args.bp_index].auto_reg_enable = args.enable;
        bp_table[args.bp_index].reg_id = args.reg_id;
        bp_table[args.bp_index].reg_value = args.value;
        bp_table[args.bp_index].fp_reg_mask = args.fp_reg_mask;
        memcpy(bp_table[args.bp_index].fp_reg_values, args.fp_reg_values,
               sizeof(args.fp_reg_values));
        bp_table[args.bp_index].fp_reg_size = args.fp_reg_size;
        write_seqcount_end(&bp_table[args.bp_index].fp_seq);
        mutex_unlock(&bp_mutex);
        ret = 0;
        break;
    }
    case YUNWU_SUSPEND_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = suspend_hw_bp(idx);
        break;
    case YUNWU_RESUME_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = resume_hw_bp(idx);
        break;
    case YUNWU_GET_HIT_COUNT: {
        struct yunwu_hit_count hc;
        if (copy_from_user(&hc, (void __user *)arg, sizeof(hc))) return -EFAULT;
        idx = hc.bp_index;
        if (idx < 0 || idx >= MAX_BREAKPOINTS) return -EINVAL;
        hc.total_hits = atomic_read(&bp_table[idx].hit_total);
        hc.queued_hits = 0;
        if (copy_to_user((void __user *)arg, &hc, sizeof(hc))) return -EFAULT;
        break;
    }
    case YUNWU_GET_HIT_DETAIL: {
        struct yunwu_hit_detail detail;
        if (copy_from_user(&detail, (void __user *)arg, sizeof(detail))) return -EFAULT;
        idx = detail.bp_index;
        if (idx < 0 || idx >= MAX_BREAKPOINTS) return -EINVAL;
        if (copy_to_user((void __user *)arg, &bp_table[idx].last_hit, sizeof(detail)))
            return -EFAULT;
        break;
    }
    case YUNWU_SET_HOOK_PC: {
        unsigned long pc;
        if (get_user(pc, (unsigned long __user *)arg)) return -EFAULT;
        atomic64_set(&global_hook_pc, pc);
        ret = 0;
        break;
    }
    case YUNWU_HIDE_MODULE:
        hide_module();
        enable_anti_ptrace();
        ret = 0;
        break;
    /* ========== PTE 断点 ioctl ========== */
    case YUNWU_SET_PTE_BP: {
        struct yunwu_pte_bp_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        ret = pte_bp_install(&args, &args.out_index);
        if (ret == 0 && copy_to_user((void __user *)arg, &args, sizeof(args)))
            ret = -EFAULT;
        break;
    }
    case YUNWU_DEL_PTE_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = pte_bp_remove(idx);
        break;
    case YUNWU_SUSPEND_PTE_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = pte_bp_suspend(idx);
        break;
    case YUNWU_RESUME_PTE_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = pte_bp_resume(idx);
        break;
    case YUNWU_SET_PTE_AUTO_REG: {
        struct yunwu_auto_reg_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        if (args.bp_index < 0 || args.bp_index >= MAX_PTE_BPS) return -EINVAL;
        mutex_lock(&pte_bp_mutex);
        if (!pte_bp_table[args.bp_index].active) {
            mutex_unlock(&pte_bp_mutex);
            return -EINVAL;
        }
        write_seqcount_begin(&pte_bp_table[args.bp_index].fp_seq);
        pte_bp_table[args.bp_index].auto_reg_enable = args.enable;
        pte_bp_table[args.bp_index].reg_id = args.reg_id;
        pte_bp_table[args.bp_index].reg_value = args.value;
        pte_bp_table[args.bp_index].fp_reg_mask = args.fp_reg_mask;
        memcpy(pte_bp_table[args.bp_index].fp_reg_values, args.fp_reg_values,
               sizeof(args.fp_reg_values));
        pte_bp_table[args.bp_index].fp_reg_size = args.fp_reg_size;
        write_seqcount_end(&pte_bp_table[args.bp_index].fp_seq);
        mutex_unlock(&pte_bp_mutex);
        ret = 0;
        break;
    }
    case YUNWU_GET_PTE_HIT_COUNT: {
        struct yunwu_hit_count hc;
        if (copy_from_user(&hc, (void __user *)arg, sizeof(hc))) return -EFAULT;
        idx = hc.bp_index;
        if (idx < 0 || idx >= MAX_PTE_BPS) return -EINVAL;
        hc.total_hits = atomic_read(&pte_bp_table[idx].hit_total);
        hc.queued_hits = 0;
        if (copy_to_user((void __user *)arg, &hc, sizeof(hc))) return -EFAULT;
        break;
    }
    case YUNWU_GET_PTE_HIT_DETAIL: {
        struct yunwu_hit_detail detail;
        if (copy_from_user(&detail, (void __user *)arg, sizeof(detail))) return -EFAULT;
        idx = detail.bp_index;
        if (idx < 0 || idx >= MAX_PTE_BPS) return -EINVAL;
        if (copy_to_user((void __user *)arg, &pte_bp_table[idx].last_hit, sizeof(detail)))
            return -EFAULT;
        break;
    }
    default:
        ret = -ENOTTY;
    }
    return ret;
}

static const struct file_operations yunwu_fops = {
    .owner = THIS_MODULE,
    .unlocked_ioctl = yunwu_ioctl,
};

static struct miscdevice yunwu_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "yunwu",
    .fops = &yunwu_fops,
};

static int __init yunwu_init(void) {
    int i;
    int ret;

    BUILD_BUG_ON(sizeof(struct yunwu_fpsimd_state) != sizeof(struct user_fpsimd_state));

    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        INIT_LIST_HEAD(&bp_table[i].events);
        seqcount_init(&bp_table[i].fp_seq);
        atomic_set(&bp_table[i].hit_total, 0);
        atomic_set(&bp_table[i].in_handler, 0);
        atomic_set(&bp_table[i].user_enabled, 0);
        memset(&bp_table[i].last_hit, 0, sizeof(bp_table[i].last_hit));
        atomic_set(&bp_table[i].head, 0);
        atomic_set(&bp_table[i].tail, 0);
        raw_spin_lock_init(&bp_table[i].hit_lock);
    }

    for (i = 0; i < MAX_PTE_BPS; i++) {
        memset(&pte_bp_table[i], 0, sizeof(pte_bp_table[i]));
        seqcount_init(&pte_bp_table[i].fp_seq);
        atomic_set(&pte_bp_table[i].hit_total, 0);
        raw_spin_lock_init(&pte_bp_table[i].lock);
    }

    if (resolve_symbols() < 0)
        dyn_register_hw_bp = NULL;

    if (dyn_register_step_hook && dyn_unregister_step_hook &&
        dyn_user_enable_ss && dyn_user_disable_ss) {
        dyn_register_step_hook(&yunwu_step_hook);
        step_hook_registered = true;
        pr_info("yunwu: user step hook registered (continuous X bp)\n");
    } else {
        pr_warn("yunwu: step hook unavailable, X bp falls back to one-shot\n");
    }

    if (dyn_register_user_brk_hook && dyn_unregister_user_brk_hook) {
        dyn_register_user_brk_hook(&yunwu_brk_hook);
        pr_info("yunwu: user break hook registered (BRK bp)\n");
    } else {
        pr_warn("yunwu: user break hook unavailable, BRK bp disabled\n");
    }

    if (kallsyms_lookup_name_ptr) {
        pte_kprobe.pre_handler = pte_bp_kprobe_pre;
        /* ARM64 6.12 上 do_page_fault 可能存在也可能不存在，依次尝试 */
        {
            static const char *pte_bp_symbols[] = {
                "do_page_fault",
                "__do_page_fault",
                NULL
            };
            int si;
            ret = -ENOENT;
            for (si = 0; pte_bp_symbols[si]; si++) {
                pte_kprobe.symbol_name = pte_bp_symbols[si];
                ret = register_kprobe(&pte_kprobe);
                if (ret == 0) {
                    pte_kprobe_registered = true;
                    pr_info("yunwu: PTE W-BP kprobe on %s\n", pte_bp_symbols[si]);
                    break;
                }
                pr_info("yunwu: %s not found, trying next\n", pte_bp_symbols[si]);
            }
            if (ret < 0) {
                pr_warn("yunwu: no suitable page fault symbol found, PTE W-BP disabled\n");
                pte_kprobe.symbol_name = NULL;
            }
        }
    } else {
        pr_warn("yunwu: kallsyms unavailable, PTE W-BP disabled\n");
    }

    if (misc_register(&yunwu_dev) < 0) {
        if (step_hook_registered) {
            dyn_unregister_step_hook(&yunwu_step_hook);
            step_hook_registered = false;
        }
        if (dyn_unregister_user_brk_hook)
            dyn_unregister_user_brk_hook(&yunwu_brk_hook);
        if (pte_kprobe_registered) {
            unregister_kprobe(&pte_kprobe);
            pte_kprobe_registered = false;
        }
        return -1;
    }
    pr_info("yunwu: loaded (multi-thread BP + BRK/PTE BP v3)\n");
    return 0;
}

static void __exit yunwu_exit(void) {
    int i;
    disable_anti_ptrace();
    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++)
        bp_entry_remove_all_events(&bp_table[i]);
    mutex_unlock(&bp_mutex);

    {
        unsigned long flags;
        spin_lock_irqsave(&step_track_lock, flags);
        for (i = 0; i < MAX_STEP_TRACK; i++) {
            if (step_track[i].used) {
                put_task_struct(step_track[i].task);
                step_track[i].used = false;
                step_track[i].task = NULL;
                step_track[i].pev = NULL;
            }
        }
        spin_unlock_irqrestore(&step_track_lock, flags);
    }

    if (step_hook_registered) {
        dyn_unregister_step_hook(&yunwu_step_hook);
        step_hook_registered = false;
    }

    if (dyn_unregister_user_brk_hook)
        dyn_unregister_user_brk_hook(&yunwu_brk_hook);

    if (pte_kprobe_registered) {
        unregister_kprobe(&pte_kprobe);
        pte_kprobe_registered = false;
    }

    for (i = 0; i < MAX_PTE_BPS; i++) {
        if (pte_bp_table[i].active)
            pte_bp_remove(i);
    }

    {
        unsigned long flags;
        raw_spin_lock_irqsave(&pte_step_track_lock, flags);
        for (i = 0; i < MAX_PTE_STEP_TRACK; i++) {
            if (pte_step_track[i].used) {
                put_task_struct(pte_step_track[i].task);
                pte_step_track[i].used = false;
                pte_step_track[i].task = NULL;
                pte_step_track[i].pte_index = -1;
            }
        }
        raw_spin_unlock_irqrestore(&pte_step_track_lock, flags);
    }

    misc_deregister(&yunwu_dev);
    pr_info("yunwu: unloaded\n");
}

module_init(yunwu_init);
module_exit(yunwu_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YunWu Team");
MODULE_DESCRIPTION("Memory R/W, HW BP, BRK/PTE BP");