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
#include <linux/compat.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <asm/ptrace.h>
#include <linux/atomic.h>
#include <linux/kprobes.h>
#include <linux/ptrace.h>
#include <linux/hardirq.h>

#include "yunwu.h"

/* ========== 配置宏 ========== */
#define MAX_BREAKPOINTS 4
#define MAX_HIT_ITEMS   128

/* 调试寄存器操作（ARM64） */
#define AARCH64_DBG_REG_BVR  0
#define AARCH64_DBG_REG_BCR  16
#define AARCH64_DBG_REG_WVR  32
#define AARCH64_DBG_REG_WCR  48

#define AARCH64_DBG_READ(N, REG, VAL) \
    asm volatile("mrs %0, dbg" #REG #N "_el1" : "=r" (VAL))
#define AARCH64_DBG_WRITE(N, REG, VAL) \
    asm volatile("msr dbg" #REG #N "_el1, %0" :: "r" (VAL))

/* ========== 动态符号解析 ========== */
typedef struct perf_event *(*register_hw_bp_fn)(struct perf_event_attr *,
        perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unregister_hw_bp_fn)(struct perf_event *);
typedef int (*modify_hw_bp_fn)(struct perf_event *, struct perf_event_attr *);

static register_hw_bp_fn dyn_register_hw_bp;
static unregister_hw_bp_fn dyn_unregister_hw_bp;
static modify_hw_bp_fn dyn_modify_hw_bp;
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

static int try_resolve_symbols(void) {
    struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
    if (register_kprobe(&kp) < 0) return -1;
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);
    if (!kallsyms_lookup_name_ptr) return -1;

    dyn_register_hw_bp = (register_hw_bp_fn)kallsyms_lookup_name_ptr("register_user_hw_breakpoint");
    dyn_unregister_hw_bp = (unregister_hw_bp_fn)kallsyms_lookup_name_ptr("unregister_hw_breakpoint");
    dyn_modify_hw_bp = (modify_hw_bp_fn)kallsyms_lookup_name_ptr("modify_user_hw_breakpoint");
    if (dyn_register_hw_bp && dyn_unregister_hw_bp) return 0;
    return -1;
}

/* ========== 调试寄存器辅助 ========== */
static int get_cpu_num_brps(void) {
    return ((read_cpuid(ID_AA64DFR0_EL1) >> 12) & 0xf) + 1;
}
static int get_cpu_num_wrps(void) {
    return ((read_cpuid(ID_AA64DFR0_EL1) >> 20) & 0xf) + 1;
}

static uint64_t read_wb_reg(int reg, int n) {
    uint64_t val = 0;
    switch (reg + n) {
    case 0 ... 15:
        asm volatile("mrs %0, dbgbvr" #n "_el1" : "=r" (val)); break;
    case 16 ... 31:
        asm volatile("mrs %0, dbgbcr" #(n-16) "_el1" : "=r" (val)); break;
    case 32 ... 47:
        asm volatile("mrs %0, dbgwvr" #(n-32) "_el1" : "=r" (val)); break;
    case 48 ... 63:
        asm volatile("mrs %0, dbgwcr" #(n-48) "_el1" : "=r" (val)); break;
    }
    return val;
}

static void write_wb_reg(int reg, int n, uint64_t val) {
    switch (reg + n) {
    case 0 ... 15:
        asm volatile("msr dbgbvr" #n "_el1, %0" :: "r" (val)); break;
    case 16 ... 31:
        asm volatile("msr dbgbcr" #(n-16) "_el1, %0" :: "r" (val)); break;
    case 32 ... 47:
        asm volatile("msr dbgwvr" #(n-32) "_el1, %0" :: "r" (val)); break;
    case 48 ... 63:
        asm volatile("msr dbgwcr" #(n-48) "_el1, %0" :: "r" (val)); break;
    }
    isb();
}

static bool toggle_hw_bp_direct(struct perf_event_attr *attr, int enable) {
    int i, max_slots, val_reg, ctrl_reg;
    uint64_t hw_addr = attr->bp_addr & ~((attr->bp_len == 8) ? 0x7 : 0x3);

    if (attr->bp_type == HW_BREAKPOINT_X) {
        val_reg = 0; ctrl_reg = 16; max_slots = get_cpu_num_brps();
    } else {
        val_reg = 32; ctrl_reg = 48; max_slots = get_cpu_num_wrps();
    }

    for (i = 0; i < max_slots; i++) {
        if (read_wb_reg(val_reg, i) == hw_addr) {
            uint64_t ctrl = read_wb_reg(ctrl_reg, i);
            if (enable) ctrl |= 1; else ctrl &= ~1;
            write_wb_reg(ctrl_reg, i, ctrl);
            return true;
        }
    }
    return false;
}

/* ========== 硬件断点条目 ========== */
struct bp_entry {
    struct perf_event *pevent;
    pid_t pid;
    unsigned long addr;
    unsigned int type;
    unsigned int len;
    bool auto_reg_enable;
    unsigned int reg_id;
    unsigned long reg_value;
    int index;
    /* 命中记录 */
    atomic_t hit_count;
    struct {
        struct yunwu_hit_detail data[MAX_HIT_ITEMS];
        atomic_t head;
        atomic_t tail;
    } hit_ring;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_MUTEX(bp_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static atomic_t bp_hit_signal = ATOMIC_INIT(0);
static struct yunwu_bp_event last_hit_event;
static atomic64_t global_hook_pc = ATOMIC64_INIT(0);

/* ========== 寄存器修改 ========== */
static inline int set_user_reg(struct pt_regs *regs, unsigned int reg_id, unsigned long value) {
    if (!regs) return -EINVAL;
#if defined(CONFIG_ARM64)
    if (reg_id <= 30) regs->regs[reg_id] = value;
    else if (reg_id == 31) regs->sp = value;
    else if (reg_id == 32) regs->pc = value;
    else if (reg_id == 33) regs->pstate = value;
    else return -EINVAL;
#else
#error "Only ARM64 supported"
#endif
    return 0;
}

/* ========== 工具函数 ========== */
static struct task_struct *get_task_by_pid(pid_t pid) {
    struct pid *p = find_get_pid(pid);
    struct task_struct *task = NULL;
    if (p) {
        task = get_pid_task(p, PIDTYPE_PID);
        put_pid(p);
    }
    return task;
}

static int do_memory_rw(pid_t pid, unsigned long addr, void __user *buf, size_t size, int write) {
    struct task_struct *task = get_task_by_pid(pid);
    struct mm_struct *mm;
    int ret;
    if (!task) return -ESRCH;
    if (!task->mm) { put_task_struct(task); return -EINVAL; }
    mm = get_task_mm(task);
    if (!mm) { put_task_struct(task); return -EINVAL; }
    ret = access_process_vm(task, addr, buf, size, write ? FOLL_WRITE : 0);
    mmput(mm);
    put_task_struct(task);
    return (ret == size) ? 0 : -EFAULT;
}

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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    struct vma_iterator vmi;
    struct vm_area_struct *vma;
    vma_iter_init(&vmi, mm, 0);
    for_each_vma(vmi, vma) {
#else
    struct vm_area_struct *vma;
    for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
        if (vma->vm_file) {
            char buf[256];
            char *path = d_path(&vma->vm_file->f_path, buf, sizeof(buf)-1);
            if (!IS_ERR(path) && strcmp(kbasename(path), name) == 0) {
                base = vma->vm_start;
                break;
            }
        }
    }
    mmap_read_unlock(mm);
    mmput(mm);
    return base;
}

/* ========== 断点回调（无锁，context 传参） ========== */
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

    /* 自动寄存器修改 */
    if (entry->auto_reg_enable && regs)
        set_user_reg(regs, entry->reg_id, entry->reg_value);

    /* 记录命中信息 */
    atomic_inc(&entry->hit_count);
    {
        int tail = atomic_read(&entry->hit_ring.tail);
        int next = (tail + 1) % MAX_HIT_ITEMS;
        if (next != atomic_read(&entry->hit_ring.head)) {
            struct yunwu_hit_detail *d = &entry->hit_ring.data[tail];
            d->task_id = entry->pid;
            d->hit_addr = regs->pc;
            d->hit_time = ktime_get_real_seconds();
            memcpy(d->regs_info.regs, regs->regs, sizeof(regs->regs));
            d->regs_info.sp = regs->sp;
            d->regs_info.pc = regs->pc;
            d->regs_info.pstate = regs->pstate;
            d->regs_info.orig_x0 = regs->orig_x0;
            d->regs_info.syscallno = regs->syscallno;
            atomic_set(&entry->hit_ring.tail, next);
        }
    }

    /* 通知等待者 */
    last_hit_event.bp_index = entry->index;
    last_hit_event.addr = entry->addr;
    last_hit_event.type = entry->type;
    atomic_inc(&bp_hit_signal);
    wake_up_interruptible(&bp_wait);
}

/* ========== 断点管理 ========== */
static int install_hw_bp(struct yunwu_bp_args *args, int *out_index) {
    struct perf_event_attr attr;
    struct perf_event *pevent;
    struct task_struct *task;
    int free_slot = -1, i;

    if (!dyn_register_hw_bp) return -ENODEV;

    task = get_task_by_pid(args->pid);
    if (!task) return -ESRCH;

    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++)
        if (!bp_table[i].pevent) { free_slot = i; break; }
    if (free_slot < 0) { mutex_unlock(&bp_mutex); put_task_struct(task); return -EBUSY; }

    memset(&attr, 0, sizeof(attr));
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

    bp_table[free_slot].pid = args->pid;
    bp_table[free_slot].addr = args->addr;
    bp_table[free_slot].type = args->type;
    bp_table[free_slot].len = args->len;
    bp_table[free_slot].auto_reg_enable = false;
    bp_table[free_slot].index = free_slot;
    atomic_set(&bp_table[free_slot].hit_count, 0);
    atomic_set(&bp_table[free_slot].hit_ring.head, 0);
    atomic_set(&bp_table[free_slot].hit_ring.tail, 0);

    pevent = dyn_register_hw_bp(&attr, yunwu_bp_handler, &bp_table[free_slot], task);
    if (IS_ERR(pevent)) {
        int ret = PTR_ERR(pevent);
        mutex_unlock(&bp_mutex);
        put_task_struct(task);
        return ret;
    }
    bp_table[free_slot].pevent = pevent;
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
    struct perf_event_attr *attr;
    mutex_lock(&bp_mutex);
    if (!bp_table[index].pevent) { mutex_unlock(&bp_mutex); return -EINVAL; }
    attr = &bp_table[index].pevent->attr;
    toggle_hw_bp_direct(attr, 0);
    mutex_unlock(&bp_mutex);
    return 0;
}

static int resume_hw_bp(int index) {
    if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
    struct perf_event_attr *attr;
    mutex_lock(&bp_mutex);
    if (!bp_table[index].pevent) { mutex_unlock(&bp_mutex); return -EINVAL; }
    attr = &bp_table[index].pevent->attr;
    toggle_hw_bp_direct(attr, 1);
    mutex_unlock(&bp_mutex);
    return 0;
}

/* ========== 反 ptrace 检测（隐藏硬件断点） ========== */
#define PTRACE_GETREGSET 0x4204
#define NT_ARM_HW_BREAK  0x402
#define NT_ARM_HW_WATCH  0x403

static struct kretprobe kretp_ptrace;
static bool anti_ptrace_enabled = false;

static int entry_ptrace_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
    long request = regs->regs[1];
    unsigned long addr = regs->regs[2];
    if (request == PTRACE_GETREGSET && (addr == NT_ARM_HW_BREAK || addr == NT_ARM_HW_WATCH)) {
        unsigned long iov_ptr = regs->regs[3];
        struct iovec iov;
        if (copy_from_user(&iov, (void __user *)iov_ptr, sizeof(iov))) return 0;
        *(struct iovec *)ri->data = iov;
    }
    return 0;
}

static int ret_ptrace_handler(struct kretprobe_instance *ri, struct pt_regs *regs) {
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
                mine = true;
                break;
            }
        }
        if (!mine) {
            cleaned.dbg_regs[j++] = state.dbg_regs[i];
        }
    }
    copy_to_user(iov.iov_base, &cleaned, copy_size);
    return 0;
}

static void enable_anti_ptrace(void) {
    if (anti_ptrace_enabled) return;
    kretp_ptrace.kp.symbol_name = "arch_ptrace";
    kretp_ptrace.data_size = sizeof(struct iovec);
    kretp_ptrace.entry_handler = entry_ptrace_handler;
    kretp_ptrace.handler = ret_ptrace_handler;
    kretp_ptrace.maxactive = 20;
    if (register_kretprobe(&kretp_ptrace) == 0) {
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

/* ========== 模块隐藏 ========== */
static void hide_module(void) {
    list_del_init(&__this_module.list);
    kobject_del(&THIS_MODULE->mkobj.kobj);
    pr_info("yunwu: module hidden\n");
}

/* ========== ioctl 分发 ========== */
static long yunwu_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0, index;
    switch (cmd) {
    case YUNWU_READ_MEM: {
        struct yunwu_mem_args args; void __user *buf;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        buf = (void __user *)args.data_ptr;
        ret = do_memory_rw(args.pid, args.addr, buf, args.size, 0);
        break;
    }
    case YUNWU_WRITE_MEM: {
        struct yunwu_mem_args args; void __user *buf;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        buf = (void __user *)args.data_ptr;
        ret = do_memory_rw(args.pid, args.addr, buf, args.size, 1);
        break;
    }
    case YUNWU_MODULE_BASE: {
        struct yunwu_module_base_args args; char name[256] = {0};
        if (copy_from_user(&args, (void __user *)arg, sizeof(args))) return -EFAULT;
        if (strncpy_from_user(name, (const char __user *)args.name_ptr, sizeof(name)-1) < 0) return -EFAULT;
        args.base = get_module_base(args.pid, name);
        if (copy_to_user((void __user *)arg, &args, sizeof(args))) return -EFAULT;
        break;
    }
    case YUNWU_SET_BP: {
        struct yunwu_bp_args bp_args; int idx;
        if (copy_from_user(&bp_args, (void __user *)arg, sizeof(bp_args))) return -EFAULT;
        ret = install_hw_bp(&bp_args, &idx);
        if (ret == 0 && put_user(idx, (int __user *)arg)) ret = -EFAULT;
        break;
    }
    case YUNWU_DEL_BP:
        if (get_user(index, (int __user *)arg)) return -EFAULT;
        ret = remove_hw_bp(index);
        break;
    case YUNWU_WAIT_BP: {
        struct yunwu_bp_event event;
        ret = wait_event_interruptible(bp_wait, atomic_read(&bp_hit_signal) > 0);
        if (ret) return ret;
        event = last_hit_event;
        atomic_set(&bp_hit_signal, 0);
        if (copy_to_user((void __user *)arg, &event, sizeof(event))) return -EFAULT;
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
        mutex_unlock(&bp_mutex);
        ret = 0;
        break;
    }
    case YUNWU_SUSPEND_BP:
        if (get_user(index, (int __user *)arg)) return -EFAULT;
        ret = suspend_hw_bp(index);
        break;
    case YUNWU_RESUME_BP:
        if (get_user(index, (int __user *)arg)) return -EFAULT;
        ret = resume_hw_bp(index);
        break;
    case YUNWU_GET_HIT_COUNT: {
        struct yunwu_hit_count hc = {0};
        if (get_user(index, &((struct yunwu_hit_count __user *)arg)->total_hits)) return -EFAULT; // 这里简单起见，要求用户提供 index 在 total_hits 位置
        if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
        hc.total_hits = atomic_read(&bp_table[index].hit_count);
        hc.queued_hits = (atomic_read(&bp_table[index].hit_ring.tail) - atomic_read(&bp_table[index].hit_ring.head) + MAX_HIT_ITEMS) % MAX_HIT_ITEMS;
        if (copy_to_user((void __user *)arg, &hc, sizeof(hc))) return -EFAULT;
        break;
    }
    case YUNWU_GET_HIT_DETAIL: {
        struct yunwu_hit_detail detail;
        int head;
        if (get_user(index, &((struct yunwu_hit_detail __user *)arg)->task_id)) return -EFAULT; // index 藏在 task_id
        if (index < 0 || index >= MAX_BREAKPOINTS) return -EINVAL;
        head = atomic_read(&bp_table[index].hit_ring.head);
        if (head == atomic_read(&bp_table[index].hit_ring.tail)) return -ENODATA;
        detail = bp_table[index].hit_ring.data[head];
        atomic_set(&bp_table[index].hit_ring.head, (head + 1) % MAX_HIT_ITEMS);
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
        enable_anti_ptrace(); // 同时启用反 ptrace
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
#ifdef CONFIG_COMPAT
    .compat_ioctl = yunwu_ioctl,
#endif
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
        atomic_set(&bp_table[i].hit_ring.head, 0);
        atomic_set(&bp_table[i].hit_ring.tail, 0);
    }
    if (try_resolve_symbols() < 0) {
        pr_warn("yunwu: failed to resolve HW BP symbols, hardware breakpoints disabled\n");
        dyn_register_hw_bp = NULL;
    }
    if (misc_register(&yunwu_dev) < 0) {
        pr_err("yunwu: register misc device failed\n");
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
MODULE_DESCRIPTION("Advanced memory R/W, HW breakpoints, register mod, anti-ptrace, hide module");