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
#include <linux/list.h>
#include <asm/ptrace.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/fpsimd.h>
#include <asm/thread_info.h>

#define MAX_BREAKPOINTS    4
#define MAX_HIT_QUEUE      128
#define ENABLE_ANTI_PTRACE 0
#define ENABLE_HIDE_MODULE 0

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

    if (dyn_register_hw_bp && dyn_unregister_hw_bp) return 0;
    return -1;
}

/* ---------- hide / anti-ptrace 占位 ---------- */
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

/* ============================================================
 * 多线程断点数据结构
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
    uint64_t fp_reg_mask;
    uint64_t fp_reg_values[32][2];
    uint8_t fp_reg_size;
    atomic_t hit_total;
    /* 最后命中记录，无锁更新 */
    struct yunwu_hit_detail last_hit;
    /* 保留环形队列定义但不再使用 */
    struct yunwu_hit_detail hit_ring[MAX_HIT_QUEUE];
    atomic_t head;
    atomic_t tail;
    raw_spinlock_t hit_lock;
};

static struct bp_entry bp_table[MAX_BREAKPOINTS];
static DEFINE_MUTEX(bp_mutex);
static DECLARE_WAIT_QUEUE_HEAD(bp_wait);
static atomic64_t global_hook_pc = ATOMIC64_INIT(0);

/* ---------- 辅助 ---------- */
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
 * 物理内存读写（kmap_local_page，6.12 兼容）
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
        if (!pte_read(pte_val)) {
            pte_unmap(pte);
            mmap_read_unlock(mm);
            break;
        }

        page = pte_page(pte_val);
        flush_dcache_page(page);

        vaddr = page_address(page);
        if (!vaddr) {
            vaddr = kmap_local_page(page);
            need_kunmap = true;
        }
        if (!vaddr) {
            pte_unmap(pte);
            mmap_read_unlock(mm);
            break;
        }

        memcpy(kbuf, (char *)vaddr + offset, sz);

        if (need_kunmap)
            kunmap_local(vaddr);
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
        if (!pte_write(pte_val)) {
            pte_unmap(pte);
            mmap_write_unlock(mm);
            break;
        }

        page = pte_page(pte_val);
        vaddr = page_address(page);
        if (!vaddr) {
            vaddr = kmap_local_page(page);
            need_kunmap = true;
        }
        if (!vaddr) {
            pte_unmap(pte);
            mmap_write_unlock(mm);
            break;
        }

        memcpy((char *)vaddr + offset, kbuf, chunk);
        flush_dcache_page(page);

        if (need_kunmap)
            kunmap_local(vaddr);
        pte_unmap(pte);
        mmap_write_unlock(mm);

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
 * 断点命中处理（带频率限制日志）
 * ============================================================ */
static void yunwu_bp_handler(struct perf_event *bp, struct perf_sample_data *data,
                             struct pt_regs *regs) {
    struct bp_entry *entry = bp->overflow_handler_context;
    uint64_t hook_pc;
    int bp_idx;

    if (!entry) return;
    bp_idx = entry->index;

    /* 全局 PC 钩子 */
    hook_pc = atomic64_read(&global_hook_pc);
    if (hook_pc) {
        regs->pc = hook_pc;
        return;
    }

    /* 频率限制日志：每秒最多输出 10 条 */
    pr_info_ratelimited("yunwu: bp hit, idx=%d, pc=0x%llx, tid=%d\n",
                        bp_idx, regs->pc, current->pid);

    /* 通用寄存器自动修改 */
    if (entry->auto_reg_enable && regs)
        set_user_reg(regs, entry->reg_id, entry->reg_value);

    /* 浮点寄存器修改 */
    if (entry->fp_reg_mask) {
        struct user_fpsimd_state *fpsimd;
        int i;

        if (dyn_fpsimd_preserve)
            dyn_fpsimd_preserve();
        fpsimd = &current->thread.uw.fpsimd_state;

        for (i = 0; i < 32; i++) {
            if (entry->fp_reg_mask & (1ULL << i)) {
                __uint128_t val;
                if (entry->fp_reg_size == 0)
                    val = (__uint128_t)(uint32_t)(entry->fp_reg_values[i][0]);
                else if (entry->fp_reg_size == 1)
                    val = (__uint128_t)(entry->fp_reg_values[i][0]);
                else
                    val = ((__uint128_t)entry->fp_reg_values[i][1] << 64) |
                          entry->fp_reg_values[i][0];
                fpsimd->vregs[i] = val;
            }
        }
    }

    /* 递增命中计数 */
    atomic_inc(&entry->hit_total);

    /* 记录最后命中详情（无锁写） */
    {
        struct yunwu_hit_detail d;
        memset(&d, 0, sizeof(d));
        d.task_id = (uint64_t)entry->pid;
        d.hit_addr = regs->pc;
        d.hit_time = ktime_get_real_seconds();
        d.bp_index = bp_idx;
        memcpy(d.regs_info.regs, regs->regs, sizeof(regs->regs));
        d.regs_info.sp = regs->sp;
        d.regs_info.pc = regs->pc;
        d.regs_info.pstate = regs->pstate;
        d.regs_info.orig_x0 = regs->orig_x0;
        d.regs_info.syscallno = regs->syscallno;
        WRITE_ONCE(entry->last_hit, d);
    }
}

/* ============================================================
 * 释放所有线程事件
 * ============================================================ */
static void bp_entry_remove_all_events(struct bp_entry *entry) {
    struct bp_thread_event *pos, *n;
    list_for_each_entry_safe(pos, n, &entry->events, list) {
        if (pos->pevent && dyn_unregister_hw_bp)
            dyn_unregister_hw_bp(pos->pevent);
        if (pos->task)
            put_task_struct(pos->task);
        list_del(&pos->list);
        kfree(pos);
    }
    INIT_LIST_HEAD(&entry->events);
}

/* ============================================================
 * 安装断点（所有线程）
 * ============================================================ */
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
    attr.disabled = 0;
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

    /* 收集所有线程 */
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

    /* 为每个线程注册 */
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

            pr_info("yunwu: registered tid %d, pevent=%px\n", tn->task->pid, ev_node->pevent);
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
    atomic_set(&entry->hit_total, 0);
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

/* ============================================================
 * 删除、挂起、恢复
 * ============================================================ */
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
    list_for_each_entry(pos, &entry->events, list) {
        if (pos->pevent) perf_event_enable(pos->pevent);
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
        return -EAGAIN;   /* 不再支持等待 */
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
        hc.queued_hits = 0;
        if (copy_to_user((void __user *)arg, &hc, sizeof(hc))) return -EFAULT;
        break;
    }
    case YUNWU_GET_HIT_DETAIL: {
        struct yunwu_hit_detail detail;
        if (copy_from_user(&detail, (void __user *)arg, sizeof(detail))) return -EFAULT;
        idx = detail.bp_index;
        if (idx < 0 || idx >= MAX_BREAKPOINTS) return -EINVAL;
        detail = READ_ONCE(bp_table[idx].last_hit);
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
        INIT_LIST_HEAD(&bp_table[i].events);
        atomic_set(&bp_table[i].hit_total, 0);
        memset(&bp_table[i].last_hit, 0, sizeof(bp_table[i].last_hit));
        atomic_set(&bp_table[i].head, 0);
        atomic_set(&bp_table[i].tail, 0);
        raw_spin_lock_init(&bp_table[i].hit_lock);
    }
    if (resolve_symbols() < 0)
        dyn_register_hw_bp = NULL;
    if (misc_register(&yunwu_dev) < 0)
        return -1;
    pr_info("yunwu: loaded (multi-thread BP with ratelimited log)\n");
    return 0;
}

static void __exit yunwu_exit(void) {
    int i;
    disable_anti_ptrace();
    mutex_lock(&bp_mutex);
    for (i = 0; i < MAX_BREAKPOINTS; i++)
        bp_entry_remove_all_events(&bp_table[i]);
    mutex_unlock(&bp_mutex);
    misc_deregister(&yunwu_dev);
    pr_info("yunwu: unloaded\n");
}

module_init(yunwu_init);
module_exit(yunwu_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("YunWu Team");
MODULE_DESCRIPTION("Memory R/W, HW BP with ratelimited log");