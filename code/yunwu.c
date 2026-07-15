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
#include <linux/string.h>   // 确保 kbasename 声明
#include "yunwu.h"

#define MAX_BREAKPOINTS 4

struct bp_entry {
    struct perf_event *pevent;
    pid_t pid;
    unsigned long addr;
    unsigned int type;
    unsigned int len;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_MUTEX(bp_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static int bp_hit_index = -1;
static struct yunwu_bp_event bp_hit_info;

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

static void yunwu_bp_handler(struct perf_event *bp,
                             struct perf_sample_data *data,
                             struct pt_regs *regs)
{
    int i;
    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bp_table[i].pevent == bp) {
            bp_hit_index = i;
            bp_hit_info.bp_index = i;
            bp_hit_info.addr = bp_table[i].addr;
            bp_hit_info.type = bp_table[i].type;
            break;
        }
    }
    mutex_unlock(&bp_mutex);
    wake_up_interruptible(&bp_wait);
}

static int install_hw_bp(struct yunwu_bp_args *args, int *out_index)
{
    struct perf_event_attr attr;
    struct perf_event *pevent;
    struct task_struct *task;
    int idx, free_slot = -1;

    task = get_task_by_pid(args->pid);
    if (!task)
        return -ESRCH;

    mutex_lock(&bp_mutex);
    for (idx = 0; idx < MAX_BREAKPOINTS; idx++) {
        if (!bp_table[idx].pevent) {
            free_slot = idx;
            break;
        }
    }
    if (free_slot < 0) {
        mutex_unlock(&bp_mutex);
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
    default: mutex_unlock(&bp_mutex); put_task_struct(task); return -EINVAL;
    }

    switch (args->type) {
    case 0: attr.bp_type = HW_BREAKPOINT_X; break;
    case 1: attr.bp_type = HW_BREAKPOINT_W; break;
    case 2: attr.bp_type = HW_BREAKPOINT_RW; break;
    default: mutex_unlock(&bp_mutex); put_task_struct(task); return -EINVAL;
    }

    pevent = register_user_hw_breakpoint(&attr, yunwu_bp_handler,
                                         NULL, task);
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
    *out_index = free_slot;
    mutex_unlock(&bp_mutex);
    put_task_struct(task);
    return 0;
}

static int remove_hw_bp(int index)
{
    if (index < 0 || index >= MAX_BREAKPOINTS)
        return -EINVAL;

    mutex_lock(&bp_mutex);
    if (bp_table[index].pevent) {
        unregister_hw_breakpoint(bp_table[index].pevent);
        bp_table[index].pevent = NULL;
        bp_table[index].pid = 0;
        bp_table[index].addr = 0;
        bp_table[index].type = 0;
        bp_table[index].len = 0;
    }
    mutex_unlock(&bp_mutex);
    return 0;
}

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

        if (strncpy_from_user(name, (const char __user *)args.name_ptr, sizeof(name) - 1) < 0)
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
        mutex_lock(&bp_mutex);
        event = bp_hit_info;
        bp_hit_index = -1;
        mutex_unlock(&bp_mutex);
        if (copy_to_user((void __user *)arg, &event, sizeof(event)))
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
#ifdef CONFIG_COMPAT
    .compat_ioctl = yunwu_ioctl,
#endif
};

static struct miscdevice yunwu_dev = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "yunwu",
    .fops = &yunwu_fops,
};

static int __init yunwu_init(void)
{
    int i, ret;
    for (i = 0; i < MAX_BREAKPOINTS; i++)
        bp_table[i].pevent = NULL;

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
    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++) {
        if (bp_table[i].pevent) {
            unregister_hw_breakpoint(bp_table[i].pevent);
            bp_table[i].pevent = NULL;
        }
    }
    mutex_unlock(&bp_mutex);
    misc_deregister(&yunwu_dev);
    pr_info("YunWu: unloaded\n");
}

module_init(yunwu_init);
module_exit(yunwu_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("YunWu Project");
MODULE_DESCRIPTION("Kernel driver with memory r/w, hardware breakpoints and module base query");