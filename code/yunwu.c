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
#include <linux/mm.h>
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
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/fpsimd.h>
#include <asm/thread_info.h>

#include "yunwu.h"

#define MAX_BREAKPOINTS    4
#define MAX_HIT_QUEUE      128
#define ENABLE_ANTI_PTRACE 0
#define ENABLE_HIDE_MODULE 0

/* 内存读写最大单次限制 */
#define MAX_RW_SIZE        (4 * 1024 * 1024)

typedef struct perf_event *(*reg_hw_bp_fn)(struct perf_event_attr *,
        perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_hw_bp_fn)(struct perf_event *);
typedef void (*fpsimd_preserve_fn)(void);

static reg_hw_bp_fn dyn_register_hw_bp;
static unreg_hw_bp_fn dyn_unregister_hw_bp;
static fpsimd_preserve_fn dyn_fpsimd_preserve;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);


/* ============================================================
 * PTE 权限检查兼容层 — 修复 ARM64 下 pte_read 错误
 * ============================================================ */

#ifndef pte_read
static inline int __yunwu_pte_read(pte_t pte)
{
#if defined(CONFIG_ARM64)
    /* 修复：ARM64 下所有 present 页均可读 */
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
        pr_warn("yunwu: fpsimd_preserve_current_state not found, FP reg writeback limited\n");

    if (dyn_register_hw_bp && dyn_unregister_hw_bp) return 0;
    return -1;
}

struct bp_entry {
    struct perf_event *pevent;
    pid_t pid;
    unsigned long addr;
    unsigned int type, len;
    bool auto_reg_enable;
    unsigned int reg_id;
    unsigned long reg_value;
    int index;
    uint64_t fp_reg_mask;
    uint64_t fp_reg_values[32][2];
    uint8_t fp_reg_size;
    atomic_t hit_total;
    struct yunwu_hit_detail hit_ring[MAX_HIT_QUEUE];
    atomic_t head;
    atomic_t tail;
    raw_spinlock_t hit_lock;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_MUTEX(bp_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static atomic64_t bp_hit_counter = ATOMIC64_INIT(0);
static atomic64_t global_hook_pc = ATOMIC64_INIT(0);

/* 每个断点独立的事件等待队列和事件缓存 */
static DEFINE_RAW_SPINLOCK(hit_event_lock);
static struct yunwu_bp_event pending_events[MAX_BREAKPOINTS];
static atomic_t pending_event_count = ATOMIC_INIT(0);

static inline int set_user_reg(struct pt_regs *regs, unsigned int reg_id, unsigned long value) {
    if (reg_id <= 30) regs->regs[reg_id] = value;
    else if (reg_id == 31) regs->sp = value;
    else if (reg_id == 32) regs->pc = value;
    else if (reg_id == 33) regs->pstate = value;
    else return -EINVAL;
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

/* ============================================================
 * 物理内存读取 — 带 PTE 权限检查（已修复可读性）
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

        mmap_read_lock(mm);

        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            mmap_read_unlock(mm);
            break;
        }

        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
            mmap_read_unlock(mm);
            break;
        }

        pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) {
            mmap_read_unlock(mm);
            break;
        }

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) {
            mmap_read_unlock(mm);
            break;
        }

        pte = pte_offset_map(pmd, addr);
        if (!pte) {
            mmap_read_unlock(mm);
            break;
        }
        pte_val = *pte;
        if (pte_none(pte_val) || !pte_present(pte_val)) {
            pte_unmap(pte);
            mmap_read_unlock(mm);
            break;
        }

        /* [修复] 使用修正后的 pte_read，所有 present 页均可读 */
        if (!pte_read(pte_val)) {
            pte_unmap(pte);
            mmap_read_unlock(mm);
            break;
        }

        page = pte_page(pte_val);
        flush_dcache_page(page);

        vaddr = page_address(page);
        if (!vaddr) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
            vaddr = kmap_local_page(page);
#else
            vaddr = kmap_atomic(page);
#endif
            need_kunmap = true;
        }

        if (!vaddr) {
            pte_unmap(pte);
            mmap_read_unlock(mm);
            break;
        }

        memcpy(kbuf, (char *)vaddr + offset, sz);

        if (need_kunmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
            kunmap_local(vaddr);
#else
            kunmap_atomic(vaddr);
#endif
        }
        pte_unmap(pte);
        mmap_read_unlock(mm);

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

/* ============================================================
 * 物理内存写入 — 带 PTE 写权限检查
 * ============================================================ */
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
        size_t offset, sz;
        bool need_kunmap = false;
        pte_t pte_val;
        size_t chunk;

        offset = addr & ~PAGE_MASK;
        chunk = min(remain, (size_t)(PAGE_SIZE - offset));

        if (copy_from_user(kbuf, (char __user *)user_buf + total, chunk))
            break;

        mmap_write_lock(mm);

        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd)) {
            mmap_write_unlock(mm);
            break;
        }

        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d)) {
            mmap_write_unlock(mm);
            break;
        }

        pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud)) {
            mmap_write_unlock(mm);
            break;
        }

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd)) {
            mmap_write_unlock(mm);
            break;
        }

        pte = pte_offset_map(pmd, addr);
        if (!pte) {
            mmap_write_unlock(mm);
            break;
        }
        pte_val = *pte;
        if (pte_none(pte_val) || !pte_present(pte_val)) {
            pte_unmap(pte);
            mmap_write_unlock(mm);
            break;
        }

        /* [修复] 检查页是否可写 */
        if (!pte_write(pte_val)) {
            pte_unmap(pte);
            mmap_write_unlock(mm);
            break;
        }

        page = pte_page(pte_val);
        sz = chunk;

        vaddr = page_address(page);
        if (!vaddr) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
            vaddr = kmap_local_page(page);
#else
            vaddr = kmap_atomic(page);
#endif
            need_kunmap = true;
        }

        if (!vaddr) {
            pte_unmap(pte);
            mmap_write_unlock(mm);
            break;
        }

        memcpy((char *)vaddr + offset, kbuf, sz);
        flush_dcache_page(page);

        if (need_kunmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
            kunmap_local(vaddr);
#else
            kunmap_atomic(vaddr);
#endif
        }
        pte_unmap(pte);
        mmap_write_unlock(mm);

        addr += sz;
        total += sz;
        remain -= sz;
    }

    mmput(mm);
    kfree(kbuf);

    return total > 0 ? total : -EFAULT;
}

/* ============================================================
 * 标准内存读取 — 优先使用 access_process_vm（标准VMA权限）
 * 失败后回退物理读取
 * ============================================================ */
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

    /* [修复] 优先使用标准 access_process_vm，它自动处理VMA权限 */
    ret = access_process_vm(task, addr, kbuf, size, 0);
    if (ret > 0) {
        if (copy_to_user(user_buf, kbuf, ret))
            ret = -EFAULT;
    } else {
        /* 标准方式失败，回退到物理读取 */
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

/* ============================================================
 * 标准内存写入 — 优先使用 access_process_vm（标准VMA权限）
 * 失败后回退物理写入
 * ============================================================ */
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

    /* [修复] 优先使用标准 access_process_vm，它自动处理VMA权限 */
    ret = access_process_vm(task, addr, kbuf, size, FOLL_WRITE);
    if (ret <= 0) {
        /* 标准方式失败，回退到物理写入 */
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
 * 获取模块基址 — 修复引用计数
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

    mmap_read_lock(mm);
    {
        VMA_ITERATOR(vmi, mm, 0);
        struct vm_area_struct *vma;
        for_each_vma(vmi, vma) {
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
    mmap_read_unlock(mm);
    mmput(mm);
    put_task_struct(task);
    return base;
}

/* ============================================================
 * 断点处理程序 — 修复事件队列竞态
 * ============================================================ */
static void yunwu_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
                             struct pt_regs *regs) {
    struct bp_entry *entry = bp->overflow_handler_context;
    uint64_t hook_pc;
    unsigned long flags;
    int bp_idx;

    if (!entry) return;
    bp_idx = entry->index;

    hook_pc = atomic64_read(&global_hook_pc);
    if (hook_pc) {
        regs->pc = hook_pc;
        return;
    }

    if (entry->auto_reg_enable && regs)
        set_user_reg(regs, entry->reg_id, entry->reg_value);

    if (entry->fp_reg_mask) {
        struct user_fpsimd_state *fpsimd;
        int i;

        if (dyn_fpsimd_preserve)
            dyn_fpsimd_preserve();

        fpsimd = &current->thread.uw.fpsimd_state;

        for (i = 0; i < 32; i++) {
            if (entry->fp_reg_mask & (1ULL << i)) {
                __uint128_t val;

                if (entry->fp_reg_size == 0) {
                    val = (__uint128_t)(uint32_t)(entry->fp_reg_values[i][0]);
                } else if (entry->fp_reg_size == 1) {
                    val = (__uint128_t)(entry->fp_reg_values[i][0]);
                } else {
                    val = ((__uint128_t)entry->fp_reg_values[i][1] << 64) |
                          entry->fp_reg_values[i][0];
                }
                fpsimd->vregs[i] = val;
            }
        }

        set_thread_flag(TIF_FOREIGN_FPSTATE);
    }

    raw_spin_lock_irqsave(&entry->hit_lock, flags);
    {
        int tail = atomic_read(&entry->tail);
        int next = (tail + 1) % MAX_HIT_QUEUE;
        if (next != atomic_read(&entry->head)) {
            struct yunwu_hit_detail *d = &entry->hit_ring[tail];
            d->task_id = (uint64_t)entry->pid;
            d->hit_addr = regs->pc;
            d->hit_time = ktime_get_real_seconds();
            d->bp_index = entry->index;
            memcpy(d->regs_info.regs, regs->regs, sizeof(regs->regs));
            d->regs_info.sp = regs->sp;
            d->regs_info.pc = regs->pc;
            d->regs_info.pstate = regs->pstate;
            d->regs_info.orig_x0 = regs->orig_x0;
            d->regs_info.syscallno = regs->syscallno;
            atomic_set(&entry->tail, next);
        }
    }
    raw_spin_unlock_irqrestore(&entry->hit_lock, flags);

    atomic_inc(&entry->hit_total);

    raw_spin_lock_irqsave(&hit_event_lock, flags);
    if (bp_idx >= 0 && bp_idx < MAX_BREAKPOINTS) {
        pending_events[bp_idx].bp_index = bp_idx;
        pending_events[bp_idx].addr = entry->addr;
        pending_events[bp_idx].type = entry->type;
    }
    atomic_inc(&pending_event_count);
    atomic64_inc(&bp_hit_counter);
    raw_spin_unlock_irqrestore(&hit_event_lock, flags);

    wake_up_interruptible(&bp_wait);
}

static int install_hw_bp(struct yunwu_bp_args *args, int *out_index) {
    struct perf_event_attr attr = {0};
    struct perf_event *pevent;
    struct task_struct *task = get_task_by_pid(args->pid);
    int free_slot = -1, i;

    if (!dyn_register_hw_bp) return -ENODEV;
    if (!task) return -ESRCH;

    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++)
        if (!bp_table[i].pevent) { free_slot = i; break; }
    if (free_slot < 0) { mutex_unlock(&bp_mutex); put_task_struct(task); return -EBUSY; }

    attr.bp_addr = args->addr;
    attr.type = PERF_TYPE_BREAKPOINT;
    attr.size = sizeof(attr);
    attr.disabled = 0;
    switch (args->len) {
    case 1: attr.bp_len = HW_BREAKPOINT_LEN_1; break;
    case 2: attr.bp_len = HW_BREAKPOINT_LEN_2; break;
    case 4: attr.bp_len = HW_BREAKPOINT_LEN_4; break;
    case 8: attr.bp_len = HW_BREAKPOINT_LEN_8; break;
    default: mutex_unlock(&bp_mutex); put_task_struct(task); return -EINVAL;
    }
    switch (args->type) {
    case 0: attr.bp_type = HW_BREAKPOINT_X; break;
    case 1: attr.bp_type = HW_BREAKPOINT_W; break;
    case 2: attr.bp_type = HW_BREAKPOINT_RW; break;
    default: mutex_unlock(&bp_mutex); put_task_struct(task); return -EINVAL;
    }

    pevent = dyn_register_hw_bp(&attr, yunwu_bp_handler, &bp_table[free_slot], task);
    if (IS_ERR(pevent)) {
        int ret = PTR_ERR(pevent);
        mutex_unlock(&bp_mutex);
        put_task_struct(task);
        return ret;
    }

    bp_table[free_slot].pevent = pevent;
    bp_table[free_slot].pid = args->pid;
    bp_table[free_slot].addr = args->addr;
    bp_table[free_slot].type = args->type;
    bp_table[free_slot].len = args->len;
    bp_table[free_slot].auto_reg_enable = false;
    bp_table[free_slot].index = free_slot;
    bp_table[free_slot].fp_reg_mask = 0;
    memset(bp_table[free_slot].fp_reg_values, 0, sizeof(bp_table[free_slot].fp_reg_values));
    bp_table[free_slot].fp_reg_size = 0;
    atomic_set(&bp_table[free_slot].hit_total, 0);
    atomic_set(&bp_table[free_slot].head, 0);
    atomic_set(&bp_table[free_slot].tail, 0);
    raw_spin_lock_init(&bp_table[free_slot].hit_lock);
    mutex_unlock(&bp_mutex);
    put_task_struct(task);
    *out_index = free_slot;
    return 0;
}

static int remove_hw_bp(int index) {
    if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
    mutex_lock(&bp_mutex);
    if (bp_table[index].pevent) {
        if (dyn_unregister_hw_bp)
            dyn_unregister_hw_bp(bp_table[index].pevent);
        bp_table[index].pevent = NULL;
    }
    mutex_unlock(&bp_mutex);
    return 0;
}

static int suspend_hw_bp(int index) {
    if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
    mutex_lock(&bp_mutex);
    if (!bp_table[index].pevent) { mutex_unlock(&bp_mutex); return -EINVAL; }
    perf_event_disable(bp_table[index].pevent);
    mutex_unlock(&bp_mutex);
    return 0;
}

static int resume_hw_bp(int index) {
    if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
    mutex_lock(&bp_mutex);
    if (!bp_table[index].pevent) { mutex_unlock(&bp_mutex); return -EINVAL; }
    perf_event_enable(bp_table[index].pevent);
    mutex_unlock(&bp_mutex);
    return 0;
}

#if ENABLE_ANTI_PTRACE
#include <linux/ptrace.h>
#define PTRACE_GETREGSET 0x4204
#define NT_ARM_HW_BREAK  0x402
#define NT_ARM_HW_WATCH  0x403

static struct kretprobe kretp_ptrace;
static bool anti_ptrace_enabled;

static int entry_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    long request = regs->regs[1];
    unsigned long addr = regs->regs[2];
    if (request == PTRACE_GETREGSET &&
        (addr == NT_ARM_HW_BREAK || addr == NT_ARM_HW_WATCH)) {
        unsigned long iov_ptr = regs->regs[3];
        struct iovec iov;
        if (copy_from_user(&iov, (void __user *)iov_ptr, sizeof(iov))) return 0;
        *(struct iovec *)ri->data = iov;
    }
    return 0;
}

static int ret_ptrace(struct kretprobe_instance *ri, struct pt_regs *regs) {
    struct iovec iov = *(struct iovec *)ri->data;
    struct user_hwdebug_state state;
    struct user_hwdebug_state cleaned = {0};
    size_t copy_size;
    int i, j = 0;
    if (!iov.iov_base || !iov.iov_len) return 0;
    copy_size = min(iov.iov_len, sizeof(state));
    if (copy_from_user(&state, iov.iov_base, copy_size)) return 0;
    for (i = 0; i < 16; i++) {
        unsigned long addr = state.dbg_regs[i].addr;
        bool mine = false;
        int k;
        for (k = 0; k < MAX_BREAKPOINTS; k++) {
            if (bp_table[k].pevent && bp_table[k].addr == addr) {
                mine = true; break;
            }
        }
        if (!mine) cleaned.dbg_regs[j++] = state.dbg_regs[i];
    }
    copy_to_user(iov.iov_base, &cleaned, copy_size);
    return 0;
}

static void enable_anti_ptrace(void) {
    if (anti_ptrace_enabled) return;
    kretp_ptrace.kp.symbol_name = "arch_ptrace";
    kretp_ptrace.data_size = sizeof(struct iovec);
    kretp_ptrace.entry_handler = entry_ptrace;
    kretp_ptrace.handler = ret_ptrace;
    kretp_ptrace.maxactive = 20;
    if (!register_kretprobe(&kretp_ptrace)) {
        anti_ptrace_enabled = true;
        pr_info("yunwu: anti-ptrace enabled\n");
    }
}

static void disable_anti_ptrace(void) {
    if (anti_ptrace_enabled) {
        unregister_kretprobe(&kretp_ptrace);
        anti_ptrace_enabled = false;
    }
}
#else
static void enable_anti_ptrace(void) {}
static void disable_anti_ptrace(void) {}
#endif

#if ENABLE_HIDE_MODULE
static void hide_module(void) {
    list_del_init(&THIS_MODULE->list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    pr_info("yunwu: module hidden\n");
}
#else
static void hide_module(void) {
    pr_info("yunwu: hide_module is disabled\n");
}
#endif

/* ============================================================
 * ioctl 处理 — 修复返回值，成功时返回0
 * ============================================================ */
static long yunwu_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0, idx;
    switch (cmd) {
    case YUNWU_READ_MEM: {
        struct yunwu_mem_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        ret = do_memory_read(args.pid, args.addr,
                             (void __user *)args.data_ptr, args.size);
        /* 修复：成功时返回0，失败时返回错误码 */
        if (ret > 0)
            ret = 0;
        else if (ret == 0)
            ret = -ENODATA;
        break;
    }
    case YUNWU_WRITE_MEM: {
        struct yunwu_mem_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        ret = do_memory_write(args.pid, args.addr,
                              (void __user *)args.data_ptr, args.size);
        /* 修复：成功时返回0 */
        if (ret > 0)
            ret = 0;
        else if (ret == 0)
            ret = -ENODATA;
        break;
    }
    case YUNWU_MODULE_BASE: {
        struct yunwu_module_base_args args; char name[256] = {0};
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        if (strncpy_from_user(name, (const char __user *)args.name_ptr, sizeof(name) - 1) < 0)
            return -EFAULT;
        args.base = get_module_base(args.pid, name);
        if (copy_to_user((void __user *)arg, &args, sizeof(args))) return -EFAULT;
        break;
    }
    case YUNWU_SET_BP: {
        struct yunwu_bp_args bp_args;
        if (copy_from_user(&bp_args, (void __user *)arg, sizeof(bp_args))) return -EFAULT;
        ret = install_hw_bp(&bp_args, &bp_args.out_index);
        if (ret == 0) {
            if (copy_to_user((void __user *)arg, &bp_args, sizeof(bp_args)))
                ret = -EFAULT;
        }
        break;
    }
    case YUNWU_DEL_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = remove_hw_bp(idx);
        break;
    case YUNWU_WAIT_BP: {
        struct yunwu_bp_event ev;
        int found = 0;
        unsigned long flags;

        ret = wait_event_interruptible(bp_wait,
                atomic_read(&pending_event_count) > 0);
        if (ret) return ret;

        raw_spin_lock_irqsave(&hit_event_lock, flags);
        if (atomic_read(&pending_event_count) > 0) {
            int i;
            for (i = 0; i < MAX_BREAKPOINTS; i++) {
                if (pending_events[i].bp_index >= 0) {
                    ev = pending_events[i];
                    pending_events[i].bp_index = -1;
                    atomic_dec(&pending_event_count);
                    atomic64_dec(&bp_hit_counter);
                    found = 1;
                    break;
                }
            }
        }
        raw_spin_unlock_irqrestore(&hit_event_lock, flags);

        if (!found) return -EAGAIN;

        if (copy_to_user((void __user *)arg, &ev, sizeof(ev))) return -EFAULT;
        break;
    }
    case YUNWU_SET_AUTO_REG: {
        struct yunwu_auto_reg_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        if (args.bp_index < 0 || args.bp_index >= MAX_BREAKPOINTS) return -EINVAL;
        mutex_lock(&bp_mutex);
        if (!bp_table[args.bp_index].pevent) { mutex_unlock(&bp_mutex); return -EINVAL; }
        bp_table[args.bp_index].auto_reg_enable = args.enable;
        bp_table[args.bp_index].reg_id = args.reg_id;
        bp_table[args.bp_index].reg_value = args.value;
        bp_table[args.bp_index].fp_reg_mask = args.fp_reg_mask;
        memcpy(bp_table[args.bp_index].fp_reg_values, args.fp_reg_values,
               sizeof(args.fp_reg_values));
        bp_table[args.bp_index].fp_reg_size = args.fp_reg_size;
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
        hc.queued_hits = (atomic_read(&bp_table[idx].tail) -
                         atomic_read(&bp_table[idx].head) + MAX_HIT_QUEUE) % MAX_HIT_QUEUE;
        if (copy_to_user((void __user *)arg, &hc, sizeof(hc))) return -EFAULT;
        break;
    }
    case YUNWU_GET_HIT_DETAIL: {
        struct yunwu_hit_detail detail;
        unsigned long flags;
        if (copy_from_user(&detail, (void __user *)arg, sizeof(detail))) return -EFAULT;
        idx = detail.bp_index;
        if (idx < 0 || idx >= MAX_BREAKPOINTS) return -EINVAL;

        raw_spin_lock_irqsave(&bp_table[idx].hit_lock, flags);
        {
            int head = atomic_read(&bp_table[idx].head);
            if (head == atomic_read(&bp_table[idx].tail)) {
                raw_spin_unlock_irqrestore(&bp_table[idx].hit_lock, flags);
                return -ENODATA;
            }
            detail = bp_table[idx].hit_ring[head];
            atomic_set(&bp_table[idx].head, (head + 1) % MAX_HIT_QUEUE);
        }
        raw_spin_unlock_irqrestore(&bp_table[idx].hit_lock, flags);

        if (copy_to_user((void __user *)arg, &detail, sizeof(detail))) return -EFAULT;
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
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        bp_table[i].pevent = NULL;
        atomic_set(&bp_table[i].head, 0);
        atomic_set(&bp_table[i].tail, 0);
        raw_spin_lock_init(&bp_table[i].hit_lock);
        pending_events[i].bp_index = -1;
    }
    if (resolve_symbols() < 0) {
        pr_warn("yunwu: failed to resolve HW BP symbols, breakpoint features disabled\n");
        dyn_register_hw_bp = NULL;
    }
    if (misc_register(&yunwu_dev) < 0) {
        pr_err("yunwu: misc_register failed\n");
        return -1;
    }
    pr_info("yunwu: /dev/yunwu loaded\n");
    return 0;
}

static void __exit yunwu_exit(void) {
    int i;
    disable_anti_ptrace();
    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bp_table[i].pevent && dyn_unregister_hw_bp)
            dyn_unregister_hw_bp(bp_table[i].pevent);
    }
    mutex_unlock(&bp_mutex);
    misc_deregister(&yunwu_dev);
    pr_info("yunwu: unloaded\n");
}

module_init(yunwu_init);
module_exit(yunwu_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YunWu Team");
MODULE_DESCRIPTION("Fixed memory R/W, HW breakpoint, register mod, FP/SIMD for Android GKI");