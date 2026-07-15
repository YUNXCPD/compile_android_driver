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
#include <linux/signal.h>
#include <linux/compat.h>
#include <linux/dcache.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/spinlock.h>
#include <linux/kprobes.h>
#include <asm/ptrace.h>

#include "yunwu.h"

#define MAX_BREAKPOINTS 4

struct bp_entry {
    struct perf_event *pevent;
    pid_t pid;
    unsigned long addr;
    unsigned int type;
    unsigned int len;
    /* 自动修改寄存器 */
    bool auto_reg_enable;
    unsigned int reg_id;
    unsigned long reg_value;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_SPINLOCK(bp_lock);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static int bp_hit_index = -1;
static struct yunwu_bp_event bp_hit_info;

/* ---------- 动态符号解析 ---------- */
typedef struct perf_event *(*register_hw_bp_fn)(struct perf_event_attr *attr,
                    perf_overflow_handler_t triggered,
                    void *context,
                    struct task_struct *tsk);
typedef void (*unregister_hw_bp_fn)(struct perf_event *bp);

static register_hw_bp_fn dyn_register_hw_bp;
static unregister_hw_bp_fn dyn_unregister_hw_bp;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 7, 0)
static unsigned long (*dyn_kallsyms_lookup_name)(const char *name);
static int kp_handler_ret;

static int kp_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    dyn_kallsyms_lookup_name = (void *)p->addr;
    kp_handler_ret = 0;
    return 1;
}

static struct kprobe kp = {
    .symbol_name    = "kallsyms_lookup_name",
    .pre_handler    = kp_handler_pre,
};

static int resolve_kallsyms(void)
{
    int ret;
    ret = register_kprobe(&kp);
    if (ret < 0) {
        pr_err("yunwu: failed to register kprobe on kallsyms_lookup_name: %d\n", ret);
        return ret;
    }
    unregister_kprobe(&kp);
    if (!dyn_kallsyms_lookup_name)
        return -ENOENT;
    return 0;
}
#else
static int resolve_kallsyms(void)
{
    dyn_kallsyms_lookup_name = kallsyms_lookup_name;
    return dyn_kallsyms_lookup_name ? 0 : -ENOENT;
}
#endif

static int resolve_hw_bp_symbols(void)
{
    int ret;
    unsigned long addr;

    ret = resolve_kallsyms();
    if (ret) {
        pr_err("yunwu: cannot resolve kallsyms_lookup_name\n");
        return ret;
    }

    addr = dyn_kallsyms_lookup_name("register_user_hw_breakpoint");
    if (!addr) {
        pr_err("yunwu: symbol register_user_hw_breakpoint not found\n");
        return -ENOENT;
    }
    dyn_register_hw_bp = (register_hw_bp_fn)addr;

    addr = dyn_kallsyms_lookup_name("unregister_hw_breakpoint");
    if (!addr) {
        pr_err("yunwu: symbol unregister_hw_breakpoint not found\n");
        return -ENOENT;
    }
    dyn_unregister_hw_bp = (unregister_hw_bp_fn)addr;

    pr_info("yunwu: hw_breakpoint symbols resolved OK\n");
    return 0;
}

/* ---------- 设置寄存器（ARM64 / x86 / ARM） ---------- */
static inline int set_user_reg(struct pt_regs *regs, unsigned int reg_id,
                               unsigned long value)
{
    if (!regs)
        return -EINVAL;

#if defined(CONFIG_ARM64)
    if (reg_id <= 30) {
        regs->regs[reg_id] = value;
    } else if (reg_id == 31) {
        regs->sp = value;
    } else if (reg_id == 32) {
        regs->pc = value;
    } else if (reg_id == 33) {
        regs->pstate = value;
    } else {
        return -EINVAL;
    }
#elif defined(CONFIG_X86_64) || defined(CONFIG_X86_32)
    switch (reg_id) {
    case 0:  regs->ax = value; break;
    case 1:  regs->bx = value; break;
    case 2:  regs->cx = value; break;
    case 3:  regs->dx = value; break;
    case 4:  regs->si = value; break;
    case 5:  regs->di = value; break;
    case 6:  regs->bp = value; break;
    case 7:  regs->sp = value; break;
    case 8:  regs->ip = value; break;
    case 9:  regs->flags = value; break;
    default: return -EINVAL;
    }
#elif defined(CONFIG_ARM)
    if (reg_id <= 15) {
        regs->uregs[reg_id] = value;
    } else if (reg_id == 16) {
        regs->uregs[16] = value;
    } else {
        return -EINVAL;
    }
#else
    return -EOPNOTSUPP;
#endif
    return 0;
}

/* ---------- 获取 task_struct ---------- */
static struct task_struct *get_task_by_pid(pid_t pid)
{
    struct task_struct *task = NULL;
    struct pid *p = find_get_pid(pid);
    if (p) {
        task = get_pid_task(p, PIDTYPE_PID);
        put_pid(p);
    }
    return task;
}

/* ---------- 内存读写 ---------- */
static int do_memory_rw(pid_t pid, unsigned long addr, void __user *buf,
                        size_t size, int write)
{
    struct task_struct *task;
    struct mm_struct *mm;
    int ret;

    task = get_task_by_pid(pid);
    if (!task)
        return -ESRCH;
    if (!task->mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    mm = get_task_mm(task);
    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }

    if (write)
        ret = access_process_vm(task, addr, buf, size, FOLL_WRITE);
    else
        ret = access_process_vm(task, addr, buf, size, 0);

    mmput(mm);
    put_task_struct(task);
    return (ret == size) ? 0 : -EFAULT;
}

/* ---------- 获取模块基址 ---------- */
static uintptr_t get_module_base(pid_t pid, char *name)
{
    struct task_struct *task;
    struct mm_struct *mm;
    uintptr_t base = 0;
    struct pid *pid_struct;

    pid_struct = find_get_pid(pid);
    if (!pid_struct)
        return 0;
    task = get_pid_task(pid_struct, PIDTYPE_PID);
    put_pid(pid_struct);
    if (!task)
        return 0;

    mm = get_task_mm(task);
    put_task_struct(task);
    if (!mm)
        return 0;

    mmap_read_lock(mm);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
    {
        struct vma_iterator vmi;
        struct vm_area_struct *vma;
        vma_iter_init(&vmi, mm, 0);
        for_each_vma(vmi, vma) {
#else
    {
        struct vm_area_struct *vma;
        for (vma = mm->mmap; vma; vma = vma->vm_next) {
#endif
            if (vma->vm_file) {
                char buf[256];
                char *path_nm;
                path_nm = d_path(&vma->vm_file->f_path, buf, sizeof(buf) - 1);
                if (!IS_ERR(path_nm)) {
                    const char *basename = kbasename(path_nm);
                    if (strcmp(basename, name) == 0) {
                        base = vma->vm_start;
                        break;
                    }
                }
            }
        }
    }

    mmap_read_unlock(mm);
    mmput(mm);
    return base;
}

/* ---------- 硬件断点回调（中断上下文安全） ---------- */
static void yunwu_bp_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    int i;
    unsigned long flags;

    spin_lock_irqsave(&bp_lock, flags);
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bp_table[i].pevent == bp) {
            bp_hit_index = i;
            bp_hit_info.bp_index = i;
            bp_hit_info.addr = bp_table[i].addr;
            bp_hit_info.type = bp_table[i].type;

            /* 自动修改寄存器 */
            if (bp_table[i].auto_reg_enable && regs) {
                set_user_reg(regs, bp_table[i].reg_id,
                             bp_table[i].reg_value);
            }
            break;
        }
    }
    spin_unlock_irqrestore(&bp_lock, flags);

    wake_up_interruptible(&bp_wait);
}

/* ---------- 安装硬件断点 ---------- */
static int install_hw_bp(struct yunwu_bp_args *args, int *out_index)
{
    struct perf_event_attr attr;
    struct perf_event *pevent;
    struct task_struct *task;
    int idx, free_slot = -1;

    if (!dyn_register_hw_bp)
        return -ENODEV;

    task = get_task_by_pid(args->pid);
    if (!task)
        return -ESRCH;

    spin_lock_irq(&bp_lock);
    for (idx = 0; idx < MAX_BREAKPOINTS; idx++) {
        if (!bp_table[idx].pevent) {
            free_slot = idx;
            break;
        }
    }
    if (free_slot < 0) {
        spin_unlock_irq(&bp_lock);
        put_task_struct(task);
        return -EBUSY;
    }

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
    default:
        spin_unlock_irq(&bp_lock);
        put_task_struct(task);
        return -EINVAL;
    }

    switch (args->type) {
    case 0: attr.bp_type = HW_BREAKPOINT_X; break;
    case 1: attr.bp_type = HW_BREAKPOINT_W; break;
    case 2: attr.bp_type = HW_BREAKPOINT_RW; break;
    default:
        spin_unlock_irq(&bp_lock);
        put_task_struct(task);
        return -EINVAL;
    }

    pevent = dyn_register_hw_bp(&attr, yunwu_bp_handler,
                                NULL, task);
    if (IS_ERR(pevent)) {
        int ret = PTR_ERR(pevent);
        spin_unlock_irq(&bp_lock);
        put_task_struct(task);
        return ret;
    }

    bp_table[free_slot].pevent = pevent;
    bp_table[free_slot].pid = args->pid;
    bp_table[free_slot].addr = args->addr;
    bp_table[free_slot].type = args->type;
    bp_table[free_slot].len = args->len;
    bp_table[free_slot].auto_reg_enable = false;
    bp_table[free_slot].reg_id = 0;
    bp_table[free_slot].reg_value = 0;
    *out_index = free_slot;
    spin_unlock_irq(&bp_lock);
    put_task_struct(task);
    return 0;
}

/* ---------- 删除硬件断点 ---------- */
static int remove_hw_bp(int index)
{
    if (index < 0 || index >= MAX_BREAKPOINTS)
        return -EINVAL;

    spin_lock_irq(&bp_lock);
    if (bp_table[index].pevent) {
        if (dyn_unregister_hw_bp)
            dyn_unregister_hw_bp(bp_table[index].pevent);
        bp_table[index].pevent = NULL;
        bp_table[index].pid = 0;
        bp_table[index].addr = 0;
        bp_table[index].type = 0;
        bp_table[index].len = 0;
        bp_table[index].auto_reg_enable = false;
        bp_table[index].reg_id = 0;
        bp_table[index].reg_value = 0;
    }
    spin_unlock_irq(&bp_lock);
    return 0;
}

/* ---------- ioctl 分发 ---------- */
static long yunwu_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    int ret = 0;

    switch (cmd) {
    case YUNWU_READ_MEM: {
        struct yunwu_mem_args args;
        void __user *buf;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
            return -EFAULT;
        buf = (void __user *)args.data_ptr;
        ret = do_memory_rw(args.pid, args.addr, buf, args.size, 0);
        break;
    }
    case YUNWU_WRITE_MEM: {
        struct yunwu_mem_args args;
        void __user *buf;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
            return -EFAULT;
        buf = (void __user *)args.data_ptr;
        ret = do_memory_rw(args.pid, args.addr, buf, args.size, 1);
        break;
    }
    case YUNWU_MODULE_BASE: {
        struct yunwu_module_base_args args;
        char name[256] = {0};

        if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
            return -EFAULT;
        if (strncpy_from_user(name, (const char __user *)args.name_ptr,
                              sizeof(name) - 1) < 0)
            return -EFAULT;

        args.base = get_module_base(args.pid, name);
        if (copy_to_user((void __user *)arg, &args, sizeof(args)))
            return -EFAULT;
        break;
    }
    case YUNWU_SET_BP: {
        struct yunwu_bp_args bp_args;
        int idx = 0;
        if (copy_from_user(&bp_args, (void __user *)arg, sizeof(bp_args)))
            return -EFAULT;
        ret = install_hw_bp(&bp_args, &idx);
        if (ret == 0 && put_user(idx, (int __user *)arg))
            ret = -EFAULT;
        break;
    }
    case YUNWU_DEL_BP: {
        int index;
        if (get_user(index, (int __user *)arg))
            return -EFAULT;
        ret = remove_hw_bp(index);
        break;
    }
    case YUNWU_WAIT_BP: {
        struct yunwu_bp_event event;
        ret = wait_event_interruptible(bp_wait, bp_hit_index >= 0);
        if (ret)
            return ret;

        spin_lock_irq(&bp_lock);
        event = bp_hit_info;
        bp_hit_index = -1;
        spin_unlock_irq(&bp_lock);

        if (copy_to_user((void __user *)arg, &event, sizeof(event)))
            return -EFAULT;
        break;
    }
    case YUNWU_SET_AUTO_REG: {
        struct yunwu_auto_reg_args args;
        if (copy_from_user(&args, (void __user *)arg, sizeof(args)))
            return -EFAULT;
        if (args.bp_index < 0 || args.bp_index >= MAX_BREAKPOINTS)
            return -EINVAL;

        spin_lock_irq(&bp_lock);
        if (!bp_table[args.bp_index].pevent) {
            spin_unlock_irq(&bp_lock);
            return -EINVAL;
        }
        bp_table[args.bp_index].auto_reg_enable = args.enable;
        bp_table[args.bp_index].reg_id = args.reg_id;
        bp_table[args.bp_index].reg_value = args.value;
        spin_unlock_irq(&bp_lock);
        ret = 0;
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
#ifdef CONFIG_COMPAT
    .compat_ioctl = yunwu_ioctl,
#endif
};

static struct miscdevice yunwu_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "yunwu",
    .fops = &yunwu_fops,
};

/* ---------- 模块初始化和退出 ---------- */
static int __init yunwu_init(void)
{
    int i, ret;

    ret = resolve_hw_bp_symbols();
    if (ret) {
        pr_err("yunwu: failed to resolve hw_breakpoint symbols\n");
        return ret;
    }

    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        bp_table[i].pevent = NULL;
        bp_table[i].auto_reg_enable = false;
    }

    ret = misc_register(&yunwu_dev);
    if (ret)
        pr_err("YunWu: failed to register misc device\n");
    else
        pr_info("YunWu: /dev/yunwu registered\n");
    return ret;
}

static void __exit yunwu_exit(void)
{
    int i;
    spin_lock_irq(&bp_lock);
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bp_table[i].pevent) {
            if (dyn_unregister_hw_bp)
                dyn_unregister_hw_bp(bp_table[i].pevent);
            bp_table[i].pevent = NULL;
        }
    }
    spin_unlock_irq(&bp_lock);
    misc_deregister(&yunwu_dev);
    pr_info("YunWu: unloaded\n");
}

module_init(yunwu_init);
module_exit(yunwu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YunWu Team - 雲YUN");
MODULE_DESCRIPTION("Memory r/w, hardware breakpoints + register modification");
