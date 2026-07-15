#ifndef YUNWU_H
#define YUNWU_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <sys/ioctl.h>
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
    unsigned int type;
    unsigned int len;
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
    bool enable;
};

#define YUNWU_MAGIC 'Y'
#define YUNWU_READ_MEM    _IOWR(YUNWU_MAGIC, 1, struct yunwu_mem_args)
#define YUNWU_WRITE_MEM   _IOW (YUNWU_MAGIC,  2, struct yunwu_mem_args)
#define YUNWU_SET_BP      _IOWR(YUNWU_MAGIC,  3, struct yunwu_bp_args)
#define YUNWU_DEL_BP      _IOW (YUNWU_MAGIC,  4, int)
#define YUNWU_WAIT_BP     _IOR (YUNWU_MAGIC,  5, struct yunwu_bp_event)
#define YUNWU_MODULE_BASE _IOWR(YUNWU_MAGIC,  6, struct yunwu_module_base_args)
#define YUNWU_SET_AUTO_REG _IOW (YUNWU_MAGIC,  7, struct yunwu_auto_reg_args)

#endif