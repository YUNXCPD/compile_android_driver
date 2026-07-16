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

#ifdef CONFIG_KPROBES
#include <linux/kprobes.h>
#endif

#include "yunwu.h"

#define MAX_BREAKPOINTS 4

struct bp_entry {
    struct perf_event *pevent;
    pid_t pid;
    unsigned long addr;
    unsigned int type;
    unsigned int len;
    uint8_t auto_reg_enable;
    unsigned int reg_id;
    unsigned long reg_value;
    int index;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_MUTEX(bp_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static atomic_t bp_hit_count = ATOMIC_INIT(0);
static struct yunwu_bp_event bp_hit_event;

/* ---------- 动态符号解析（仅 kprobe 和 模块参数） ---------- */
typedef struct perf_event *(*register_hw_bp_fn)(struct perf_event_attr *,
        perf_overflow_handler_t, void *, struct task_struct *);
typedef void (*unregister_hw_bp_fn)(struct perf_event *);

static register_hw_bp_fn dyn_register_hw_bp;
static unregister_hw_bp_fn dyn_unregister_hw_bp;

static unsigned long sym_register_hw_bp;
static unsigned long sym_unregister_hw_bp;
module_param(sym_register_hw_bp, ulong, 0400);
module_param(sym_unregister_hw_bp, ulong, 0400);

#ifdef CONFIG_KPROBES
static unsigned long (*dyn_kallsyms_lookup_name)(const char *name);
static int kp_pre_handler(struct kprobe *p, struct pt_regs *regs) {
    dyn_kallsyms_lookup_name = (void *)p->addr;
    return 1;
}
static struct kprobe kp_ksym = { .symbol_name = "kallsyms_lookup_name", .pre_handler = kp_pre_handler };
static int try_resolve_via_kprobe(void) {
    if (register_kprobe(&kp_ksym) < 0) return -ENOENT;
    unregister_kprobe(&kp_ksym);
    if (!dyn_kallsyms_lookup_name) return -ENOENT;
    dyn_register_hw_bp = (register_hw_bp_fn)dyn_kallsyms_lookup_name("register_user_hw_breakpoint");
    dyn_unregister_hw_bp = (unregister_hw_bp_fn)dyn_kallsyms_lookup_name("unregister_hw_breakpoint");
    if (!dyn_register_hw_bp || !dyn_unregister_hw_bp) return -ENOENT;
    return 0;
}
#else
static int try_resolve_via_kprobe(void) { return -ENOTSUPP; }
#endif

static int try_resolve_via_params(void) {
    if (!sym_register_hw_bp || !sym_unregister_hw_bp) return -EINVAL;
    dyn_register_hw_bp = (register_hw_bp_fn)sym_register_hw_bp;
    dyn_unregister_hw_bp = (unregister_hw_bp_fn)sym_unregister_hw_bp;
    return 0;
}

static void resolve_hw_bp_symbols(void) {
    if (try_resolve_via_kprobe() == 0) {
        pr_info("yunwu: HW BP symbols resolved via kprobe\n");
        return;
    }
    if (try_resolve_via_params() == 0) {
        pr_info("yunwu: HW BP symbols resolved via module params\n");
        return;
    }
    pr_warn("yunwu: HW BP NOT available. Provide insmod params or enable CONFIG_KPROBES.\n");
}

/* ---------- 寄存器修改 ---------- */
static inline int set_user_reg(struct pt_regs *regs, unsigned int reg_id, unsigned long value) {
    if (!regs) return -EINVAL;
#if defined(CONFIG_ARM64)
    if (reg_id <= 30) regs->regs[reg_id] = value;
    else if (reg_id == 31) regs->sp = value;
    else if (reg_id == 32) regs->pc = value;
    else if (reg_id == 33) regs->pstate = value;
    else return -EINVAL;
#elif defined(CONFIG_X86_64) || defined(CONFIG_X86_32)
    switch (reg_id) {
    case 0: regs->ax = value; break;
    case 1: regs->bx = value; break;
    case 2: regs->cx = value; break;
    case 3: regs->dx = value; break;
    case 4: regs->si = value; break;
    case 5: regs->di = value; break;
    case 6: regs->bp = value; break;
    case 7: regs->sp = value; break;
    case 8: regs->ip = value; break;
    case 9: regs->flags = value; break;
    default: return -EINVAL;
    }
#elif defined(CONFIG_ARM)
    if (reg_id <= 15) regs->uregs[reg_id] = value;
    else if (reg_id == 16) regs->uregs[16] = value;
    else return -EINVAL;
#else
    return -EOPNOTSUPP;
#endif
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

static int do_memory_rw(pid_t pid, unsigned long addr, void __user *buf, size_t size, int write) {
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    if (!buf || addr < 0x1000 || size == 0) return -EINVAL; /* 简单保护 */

    task = get_task_by_pid(pid);
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
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,1,0)
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

/* 无锁回调 */
static void yunwu_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
                             struct pt_regs *regs) {
    struct bp_entry *entry = bp->overflow_handler_context;
    if (!entry) return;
    if (entry->auto_reg_enable && regs)
        set_user_reg(regs, entry->reg_id, entry->reg_value);
    bp_hit_event.bp_index = entry->index;
    bp_hit_event.addr = entry->addr;
    bp_hit_event.type = entry->type;
    atomic_inc(&bp_hit_count);
    wake_up_interruptible(&bp_wait);
}

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
    bp_table[free_slot].auto_reg_enable = 0;
    bp_table[free_slot].index = free_slot;
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
        if (dyn_unregister_hw_bp) dyn_unregister_hw_bp(bp_table[index].pevent);
        bp_table[index].pevent = NULL;
    }
    mutex_unlock(&bp_mutex);
    return 0;
}

static long yunwu_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    int ret = 0;
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
    case YUNWU_DEL_BP: {
        int index;
        if (get_user(index, (int __user *)arg)) return -EFAULT;
        ret = remove_hw_bp(index);
        break;
    }
    case YUNWU_WAIT_BP: {
        struct yunwu_bp_event event;
        ret = wait_event_interruptible(bp_wait, atomic_read(&bp_hit_count) > 0);
        if (ret) return ret;
        event = bp_hit_event;
        atomic_set(&bp_hit_count, 0);
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
    default: ret = -ENOTTY;
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

/* 模块加载时打印结构体大小，以便核对 */
static void print_struct_sizes(void) {
    pr_info("yunwu: struct sizes: mem_args=%lu bp_args=%lu bp_event=%lu module_base=%lu auto_reg=%lu\n",
            sizeof(struct yunwu_mem_args),
            sizeof(struct yunwu_bp_args),
            sizeof(struct yunwu_bp_event),
            sizeof(struct yunwu_module_base_args),
            sizeof(struct yunwu_auto_reg_args));
}

static int __init yunwu_init(void) {
    int i;
    for (i = 0; i < MAX_BREAKPOINTS; i++) bp_table[i].pevent = NULL;
    resolve_hw_bp_symbols();
    print_struct_sizes();
    if (misc_register(&yunwu_dev) < 0) {
        pr_err("YunWu: register misc failed\n");
        return -1;
    }
    pr_info("YunWu: /dev/yunwu loaded\n");
    return 0;
}

static void __exit yunwu_exit(void) {
    int i;
    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bp_table[i].pevent && dyn_unregister_hw_bp)
            dyn_unregister_hw_bp(bp_table[i].pevent);
    }
    mutex_unlock(&bp_mutex);
    misc_deregister(&yunwu_dev);
    pr_info("YunWu: unloaded\n");
}

module_init(yunwu_init);
module_exit(yunwu_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YunWu Team");
MODULE_DESCRIPTION("Stable memory r/w, hardware breakpoints + register mod");
