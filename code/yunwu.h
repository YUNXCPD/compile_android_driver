#ifndef YUNWU_H
#define YUNWU_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
#include <sys/types.h>   /* pid_t */
#include <stdint.h>
#endif

#define DEVICE_PATH "/dev/yunwu"

struct yunwu_mem_args {
    pid_t pid;
    unsigned long addr;
    unsigned long size;
    unsigned long data_ptr;
};

struct yunwu_bp_args {
    pid_t pid;
    unsigned long addr;
    unsigned int type;      /* 0=执行, 1=写入, 2=读写 */
    unsigned int len;       /* 1,2,4,8 */
    int out_index;          /* 驱动返回的断点索引 */
};

struct yunwu_bp_event {
    int bp_index;
    unsigned long addr;
    unsigned int type;
};

struct yunwu_module_base_args {
    pid_t pid;
    unsigned long name_ptr;
    unsigned long base;
};

struct yunwu_auto_reg_args {
    int bp_index;
    unsigned int reg_id;
    unsigned long value;
    uint8_t enable;

    uint64_t fp_reg_mask;
    uint64_t fp_reg_values[32][2];
    uint8_t fp_reg_size;
};

struct yunwu_hit_detail {
    uint64_t task_id;
    uint64_t hit_addr;
    uint64_t hit_time;
    int bp_index;
    uint32_t __pad;
    struct {
        uint64_t regs[31];
        uint64_t sp;
        uint64_t pc;
        uint64_t pstate;
        uint64_t orig_x0;
        uint64_t syscallno;
    } regs_info;
};

struct yunwu_hit_count {
    int bp_index;
    uint32_t __pad;
    uint64_t total_hits;
    uint64_t queued_hits;
};

#define YUNWU_MAGIC 'Y'
#define YUNWU_READ_MEM       _IOWR(YUNWU_MAGIC, 1, struct yunwu_mem_args)
#define YUNWU_WRITE_MEM      _IOW (YUNWU_MAGIC, 2, struct yunwu_mem_args)
#define YUNWU_SET_BP         _IOWR(YUNWU_MAGIC, 3, struct yunwu_bp_args)
#define YUNWU_DEL_BP         _IOW (YUNWU_MAGIC, 4, int)
#define YUNWU_WAIT_BP        _IOR (YUNWU_MAGIC, 5, struct yunwu_bp_event)
#define YUNWU_MODULE_BASE    _IOWR(YUNWU_MAGIC, 6, struct yunwu_module_base_args)
#define YUNWU_SET_AUTO_REG   _IOW (YUNWU_MAGIC, 7, struct yunwu_auto_reg_args)
#define YUNWU_SUSPEND_BP     _IOW (YUNWU_MAGIC, 8, int)
#define YUNWU_RESUME_BP      _IOW (YUNWU_MAGIC, 9, int)
#define YUNWU_GET_HIT_COUNT  _IOWR(YUNWU_MAGIC, 10, struct yunwu_hit_count)
#define YUNWU_GET_HIT_DETAIL _IOWR(YUNWU_MAGIC, 11, struct yunwu_hit_detail)
#define YUNWU_SET_HOOK_PC    _IOW (YUNWU_MAGIC, 12, unsigned long)
#define YUNWU_HIDE_MODULE    _IO  (YUNWU_MAGIC, 13)

#endif /* YUNWU_H */