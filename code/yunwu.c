#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/sched.h>
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
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/fpsimd.h>        /* 新增：用于访问 fpsimd_state 修改浮点寄存器 */

#include "yunwu.h"

/* ==================== 配置宏 ==================== */
#define MAX_BREAKPOINTS    4
#define MAX_HIT_QUEUE      128
#define ENABLE_ANTI_PTRACE 0   /* 设为 1 可启用反 ptrace 断点隐藏 */
#define ENABLE_HIDE_MODULE 0   /* 设为 1 可启用模块链表隐藏 */

/* ==================== 动态符号解析 ==================== */
typedef struct perf_event *(*reg_hw_bp_fn)(struct perf_event_attr *,
        perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unreg_hw_bp_fn)(struct perf_event *);

static reg_hw_bp_fn dyn_register_hw_bp;
static unreg_hw_bp_fn dyn_unregister_hw_bp;

static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

static int resolve_symbols(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -1;
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name_ptr) return -1;

    dyn_register_hw_bp = (reg_hw_bp_fn)kallsyms_lookup_name_ptr("register_user_hw_breakpoint");
    dyn_unregister_hw_bp = (unreg_hw_bp_fn)kallsyms_lookup_name_ptr("unregister_hw_breakpoint");
    if (dyn_register_hw_bp && dyn_unregister_hw_bp) return 0;
    return -1;
}

/* ==================== 断点条目管理 ==================== */
struct bp_entry {
    struct perf_event *pevent;
    pid_t pid;
    unsigned long addr;
    unsigned int type, len;
    bool auto_reg_enable;
    unsigned int reg_id;
    unsigned long reg_value;
    int index;
    /* ---- 新增：浮点寄存器修改 ---- */
    uint64_t fp_reg_mask;                 /* bit i 表示修改 Vreg[i] */
    uint64_t fp_reg_values[32][2];        /* 每个寄存器128位，低64位+高64位 */
    uint8_t fp_reg_size;                  /* 0:32位, 1:64位, 2:128位 */
    /* ---- 命中记录环形缓冲 ---- */
    atomic_t hit_total;
    struct yunwu_hit_detail hit_ring[MAX_HIT_QUEUE];
    atomic_t head;
    atomic_t tail;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_MUTEX(bp_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static atomic_t bp_hit_signal = ATOMIC_INIT(0);
static struct yunwu_bp_event last_hit_event;
static atomic64_t global_hook_pc = ATOMIC64_INIT(0);

/* ==================== 寄存器修改 ==================== */
static inline int set_user_reg(struct pt_regs *regs, unsigned int reg_id, unsigned long value) {
    if (reg_id <= 30) regs->regs[reg_id] = value;
    else if (reg_id == 31) regs->sp = value;
    else if (reg_id == 32) regs->pc = value;
    else if (reg_id == 33) regs->pstate = value;
    else return -EINVAL;
    return 0;
}

/* ==================== 工具函数 ==================== */
static struct task_struct *get_task_by_pid(pid_t pid) {
    struct pid *p = find_get_pid(pid);
    struct task_struct *task = NULL;
    if (p) {
        task = get_pid_task(p, PIDTYPE_PID);
        put_pid(p);
    }
    return task;
}

/* ==================== 物理内存回退读写 ==================== */
/**
 * 通过页表遍历直接读取目标进程内存（绕过 VMA 权限检查）
 * 适用于 access_process_vm 因 mprotect/PROT_NONE 等失败的场景
 */
static int do_memory_read_phys(struct task_struct *task, unsigned long addr,
                                void __user *user_buf, size_t size)
{
    struct mm_struct *mm;
    size_t remain = size;
    int total = 0;
    char *kbuf;

    if (size == 0 || size > (4 * 1024 * 1024))
        return -EINVAL;

    kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    mm = get_task_mm(task);
    if (!mm) {
        kfree(kbuf);
        return -EINVAL;
    }

    mmap_read_lock(mm);

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

        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd))
            break;

        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d))
            break;

        pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud))
            break;

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd))
            break;

        pte = pte_offset_map(pmd, addr);
        if (!pte) {
            break;
        }
        if (pte_none(*pte) || !pte_present(*pte)) {
            pte_unmap(pte);
            break;
        }

        page = pte_page(*pte);
        offset = addr & ~PAGE_MASK;
        sz = min(remain, (size_t)(PAGE_SIZE - offset));

        /* 获取页面内核虚拟地址 */
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

        if (copy_to_user((char __user *)user_buf + total, kbuf, sz))
            break;

        addr += sz;
        total += sz;
        remain -= sz;
    }

    mmap_read_unlock(mm);
    mmput(mm);
    kfree(kbuf);

    return total > 0 ? total : -EFAULT;
}

/**
 * 通过页表遍历直接写入目标进程内存（绕过 VMA 权限检查）
 */
static int do_memory_write_phys(struct task_struct *task, unsigned long addr,
                                 void __user *user_buf, size_t size)
{
    struct mm_struct *mm;
    size_t remain = size;
    int total = 0;
    char *kbuf;

    if (size == 0 || size > (4 * 1024 * 1024))
        return -EINVAL;

    kbuf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, user_buf, size)) {
        kfree(kbuf);
        return -EFAULT;
    }

    mm = get_task_mm(task);
    if (!mm) {
        kfree(kbuf);
        return -EINVAL;
    }

    mmap_read_lock(mm);

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

        pgd = pgd_offset(mm, addr);
        if (pgd_none(*pgd) || pgd_bad(*pgd))
            break;

        p4d = p4d_offset(pgd, addr);
        if (p4d_none(*p4d) || p4d_bad(*p4d))
            break;

        pud = pud_offset(p4d, addr);
        if (pud_none(*pud) || pud_bad(*pud))
            break;

        pmd = pmd_offset(pud, addr);
        if (pmd_none(*pmd) || pmd_bad(*pmd))
            break;

        pte = pte_offset_map(pmd, addr);
        if (!pte) {
            break;
        }
        if (pte_none(*pte) || !pte_present(*pte)) {
            pte_unmap(pte);
            break;
        }

        page = pte_page(*pte);
        offset = addr & ~PAGE_MASK;
        sz = min(remain, (size_t)(PAGE_SIZE - offset));

        /* 获取页面内核虚拟地址 */
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
            break;
        }

        memcpy((char *)vaddr + offset, kbuf + total, sz);

        if (need_kunmap) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,14,0)
            kunmap_local(vaddr);
#else
            kunmap_atomic(vaddr);
#endif
        }
        pte_unmap(pte);

        addr += sz;
        total += sz;
        remain -= sz;
    }

    mmap_read_unlock(mm);
    mmput(mm);
    kfree(kbuf);

    return total > 0 ? total : -EFAULT;
}

/* [修复] 内存读写：必须使用内核缓冲区做中转，
 * 严禁将用户空间指针直接传给 access_process_vm */
static int do_memory_read(pid_t pid, unsigned long addr,
                          void __user *user_buf, size_t size) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    int ret;

    if (size == 0 || size > (4 * 1024 * 1024))  /* 限制最大 4MB */
        return -EINVAL;

    task = get_task_by_pid(pid);
    if (!task) return -ESRCH;
    if (!task->mm) { put_task_struct(task); return -EINVAL; }

    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); return -EINVAL; }

    /* 1. 分配内核缓冲区 */
    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) { mmput(mm); put_task_struct(task); return -ENOMEM; }

    /* 2. 从目标进程读到内核缓冲区 */
    ret = access_process_vm(task, addr, kbuf, size, 0);
    if (ret == size) {
        /* 3. 从内核缓冲区拷贝到用户空间 */
        if (copy_to_user(user_buf, kbuf, size))
            ret = -EFAULT;
    } else {
        ret = (ret < 0) ? ret : -EFAULT;
        /* [回退] access_process_vm 因 VMA 权限/映射问题失败时，
         * 尝试通过页表遍历直接读取物理内存 */
        if (ret == -EFAULT || ret == 0) {
            int phys_ret = do_memory_read_phys(task, addr, user_buf, size);
            if (phys_ret > 0)
                ret = phys_ret;
        }
    }

    kfree(kbuf);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

static int do_memory_write(pid_t pid, unsigned long addr,
                           void __user *user_buf, size_t size) {
    struct task_struct *task;
    struct mm_struct *mm;
    void *kbuf;
    int ret;

    if (size == 0 || size > (4 * 1024 * 1024))
        return -EINVAL;

    task = get_task_by_pid(pid);
    if (!task) return -ESRCH;
    if (!task->mm) { put_task_struct(task); return -EINVAL; }

    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); return -EINVAL; }

    /* 1. 分配内核缓冲区 */
    kbuf = kmalloc(size, GFP_KERNEL);
    if (!kbuf) { mmput(mm); put_task_struct(task); return -ENOMEM; }

    /* 2. 从用户空间拷贝到内核缓冲区 */
    if (copy_from_user(kbuf, user_buf, size)) {
        kfree(kbuf);
        mmput(mm);
        put_task_struct(task);
        return -EFAULT;
    }

    /* 3. 从内核缓冲区写入目标进程 */
    ret = access_process_vm(task, addr, kbuf, size, FOLL_WRITE);
    if (ret != (int)size) {
        ret = (ret < 0) ? ret : -EFAULT;
        /* [回退] 尝试物理内存写入 */
        if (ret == -EFAULT || ret == 0) {
            int phys_ret = do_memory_write_phys(task, addr, user_buf, size);
            if (phys_ret > 0)
                ret = 0;
        }
    } else {
        ret = 0;
    }

    kfree(kbuf);
    mmput(mm);
    put_task_struct(task);
    return ret;
}

/* [修复] 使用 VMA iterator 兼容 kernel 6.12 maple tree */
static uintptr_t get_module_base(pid_t pid, char *name) {
    struct task_struct *task;
    struct mm_struct *mm;
    uintptr_t base = 0;
    struct pid *pid_struct = find_get_pid(pid);
    if (!pid_struct) return 0;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task) return 0;
    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm) return 0;

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
    return base;
}

/* ==================== 硬件断点回调 ==================== */
static void yunwu_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
                             struct pt_regs *regs) {
    struct bp_entry *entry = bp->overflow_handler_context;
    uint64_t hook_pc;
    if (!entry) return;

    /* 全局 Hook PC */
    hook_pc = atomic64_read(&global_hook_pc);
    if (hook_pc) {
        regs->pc = hook_pc;
        return;
    }

    /* 自动修改通用寄存器 */
    if (entry->auto_reg_enable && regs)
        set_user_reg(regs, entry->reg_id, entry->reg_value);

    /* ========== 新增：自动修改浮点/向量寄存器 ========== */
    if (entry->fp_reg_mask) {
        struct task_struct *task = current;  // 断点命中时，current 为被中断的任务
        struct fpsimd_state *fpsimd = &task->thread.fpsimd_state;
        int i;
        for (i = 0; i < 32; i++) {
            if (entry->fp_reg_mask & (1ULL << i)) {
                __uint128_t val;
                /* 根据 fp_reg_size 选择写入宽度 */
                if (entry->fp_reg_size == 0) { // 32位单精度
                    float f = *(float *)entry->fp_reg_values[i];
                    val = (__uint128_t)(*(uint32_t *)&f);
                } else if (entry->fp_reg_size == 1) { // 64位双精度
                    double d = *(double *)entry->fp_reg_values[i];
                    val = (__uint128_t)(*(uint64_t *)&d);
                } else { // 128位，直接使用两个64位组合
                    val = ((__uint128_t)entry->fp_reg_values[i][1] << 64) | entry->fp_reg_values[i][0];
                }
                fpsimd->vregs[i] = val;
            }
        }
        /* 修改后无需额外操作，下次使用该寄存器时将从 fpsimd_state 加载 */
    }
    /* ==================================================== */

    /* 记录命中 */
    atomic_inc(&entry->hit_total);
    {
        int tail = atomic_read(&entry->tail);
        int next = (tail + 1) % MAX_HIT_QUEUE;
        if (next != atomic_read(&entry->head)) {
            struct yunwu_hit_detail *d = &entry->hit_ring[tail];
            d->task_id = entry->pid;
            d->hit_addr = regs->pc;
            d->hit_time = ktime_get_real_seconds();
            memcpy(d->regs_info.regs, regs->regs, sizeof(regs->regs));
            d->regs_info.sp = regs->sp;
            d->regs_info.pc = regs->pc;
            d->regs_info.pstate = regs->pstate;
            d->regs_info.orig_x0 = regs->orig_x0;
            d->regs_info.syscallno = regs->syscallno;
            atomic_set(&entry->tail, next);
        }
    }

    last_hit_event.bp_index = entry->index;
    last_hit_event.addr = entry->addr;
    last_hit_event.type = entry->type;
    atomic_inc(&bp_hit_signal);
    wake_up_interruptible(&bp_wait);
}

/* ==================== 断点管理 ==================== */
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
    /* ---- 新增：初始化浮点字段 ---- */
    bp_table[free_slot].fp_reg_mask = 0;
    memset(bp_table[free_slot].fp_reg_values, 0, sizeof(bp_table[free_slot].fp_reg_values));
    bp_table[free_slot].fp_reg_size = 0;
    /* --------------------------------- */
    atomic_set(&bp_table[free_slot].hit_total, 0);
    atomic_set(&bp_table[free_slot].head, 0);
    atomic_set(&bp_table[free_slot].tail, 0);
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

/* [修复] 使用内核标准 API 暂停/恢复断点，不再直接操作调试寄存器 */
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

/* ==================== 反 ptrace (可选) ==================== */
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
    if (!iov.iov_base || !iov.iov_len) return 0;
    struct user_hwdebug_state state;
    size_t copy_size = min(iov.iov_len, sizeof(state));
    if (copy_from_user(&state, iov.iov_base, copy_size)) return 0;
    int i, j = 0;
    struct user_hwdebug_state cleaned = {0};
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

/* ==================== 模块隐藏 (可选) ==================== */
#if ENABLE_HIDE_MODULE
static void hide_module(void) {
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    pr_info("yunwu: module hidden\n");
}
#else
static void hide_module(void) {
    pr_info("yunwu: hide_module is disabled\n");
}
#endif

/* ==================== ioctl 分发 ==================== */
static long yunwu_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0, idx;
    switch (cmd) {
    case YUNWU_READ_MEM: {
        struct yunwu_mem_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        ret = do_memory_read(args.pid, args.addr,
                             (void __user *)args.data_ptr, args.size);
        break;
    }
    case YUNWU_WRITE_MEM: {
        struct yunwu_mem_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        ret = do_memory_write(args.pid, args.addr,
                              (void __user *)args.data_ptr, args.size);
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
        struct yunwu_bp_args bp_args; int index;
        if (copy_from_user(&bp_args, (void __user *)arg, sizeof(bp_args))) return -EFAULT;
        ret = install_hw_bp(&bp_args, &index);
        if (ret == 0 && put_user(index, (int __user *)arg)) ret = -EFAULT;
        break;
    }
    case YUNWU_DEL_BP:
        if (get_user(idx, (int __user *)arg)) return -EFAULT;
        ret = remove_hw_bp(idx);
        break;
    case YUNWU_WAIT_BP: {
        struct yunwu_bp_event ev;
        ret = wait_event_interruptible(bp_wait, atomic_read(&bp_hit_signal) > 0);
        if (ret) return ret;
        ev = last_hit_event;
        atomic_set(&bp_hit_signal, 0);
        if (copy_to_user((void __user *)arg, &ev, sizeof(ev))) return -EFAULT;
        break;
    }
    case YUNWU_SET_AUTO_REG: {
        struct yunwu_auto_reg_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        if (args.bp_index < 0 || args.bp_index >= MAX_BREAKPOINTS) return -EINVAL;
        mutex_lock(&bp_mutex);
        if (!bp_table[args.bp_index].pevent) { mutex_unlock(&bp_mutex); return -EINVAL; }
        /* ---- 原有通用寄存器 ---- */
        bp_table[args.bp_index].auto_reg_enable = args.enable;
        bp_table[args.bp_index].reg_id = args.reg_id;
        bp_table[args.bp_index].reg_value = args.value;
        /* ---- 新增：浮点寄存器 ---- */
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
        idx = hc.total_hits;   /* 用户写入索引 */
        if (idx < 0 || idx >= MAX_BREAKPOINTS) return -EINVAL;
        hc.total_hits = atomic_read(&bp_table[idx].hit_total);
        hc.queued_hits = (atomic_read(&bp_table[idx].tail) -
                         atomic_read(&bp_table[idx].head) + MAX_HIT_QUEUE) % MAX_HIT_QUEUE;
        if (copy_to_user((void __user *)arg, &hc, sizeof(hc))) return -EFAULT;
        break;
    }
    case YUNWU_GET_HIT_DETAIL: {
        struct yunwu_hit_detail detail;
        if (copy_from_user(&detail, (void __user *)arg, sizeof(detail))) return -EFAULT;
        idx = detail.task_id;   /* 用户写入索引 */
        if (idx < 0 || idx >= MAX_BREAKPOINTS) return -EINVAL;
        int head = atomic_read(&bp_table[idx].head);
        if (head == atomic_read(&bp_table[idx].tail)) return -ENODATA;
        detail = bp_table[idx].hit_ring[head];
        atomic_set(&bp_table[idx].head, (head + 1) % MAX_HIT_QUEUE);
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
MODULE_DESCRIPTION("Full-featured memory R/W, HW breakpoint, register mod, anti-ptrace, hide module, FP/SIMD support");