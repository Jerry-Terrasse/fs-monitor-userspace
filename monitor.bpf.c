#define BPF_NO_GLOBAL_DATA
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define MAX_ENTRIES 10240
#define NUM_OPERATIONS 15
// lookup getattr rename setattr create open release getxattr mkdir unlink opendir readdir releasedir read write
// 0      1       2      3       4      5    6       7        8     9      10      11      12         13   14
static const char* op_names[NUM_OPERATIONS] = {
    "lookup", "getattr", "rename", "setattr", "create", "open", "release", "getxattr", "mkdir", "unlink", "opendir", "readdir", "releasedir", "read", "write"
};

struct record {
    unsigned int pid;
    int ops_cnt[NUM_OPERATIONS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct record);
} record_map SEC(".maps");

static void increase_record(int op_id)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    struct record *recordp = bpf_map_lookup_elem(&record_map, &pid);
    if(!recordp) {
        struct record record = {};
        record.pid = pid;
        ++record.ops_cnt[op_id];
        bpf_map_update_elem(&record_map, &pid, &record, BPF_ANY);
        return;
    }

    ++recordp->ops_cnt[op_id];
    
    // print summary
    // char buffer[256];
    // int len = 0;
    // len += BPF_SNPRINTF(buffer + len, sizeof(buffer) - len, "pid %d, ", recordp->pid);
    // for(size_t i = 0; i < NUM_OPERATIONS; ++i) {
    //     len += BPF_SNPRINTF(buffer + len, sizeof(buffer) - len, "%s %d, ", op_names[i], recordp->ops_cnt[i]);
    // }
    // bpf_printk("%s\n", buffer);
    // bpf_printk(
    //     "pid %d, %s %d, %s %d, %s %d, "
    //     "%s %d, %s %d, %s %d, %s %d, "
    //     "%s %d, %s %d, %s %d, %s %d, "
    //     "%s %d, %s %d, %s %d, %s %d\n",
    //     recordp->pid,
    //     op_names[0], recordp->ops_cnt[0],
    //     op_names[1], recordp->ops_cnt[1],
    //     op_names[2], recordp->ops_cnt[2],
    //     op_names[3], recordp->ops_cnt[3],
    //     op_names[4], recordp->ops_cnt[4],
    //     op_names[5], recordp->ops_cnt[5],
    //     op_names[6], recordp->ops_cnt[6],
    //     op_names[7], recordp->ops_cnt[7],
    //     op_names[8], recordp->ops_cnt[8],
    //     op_names[9], recordp->ops_cnt[9],
    //     op_names[10], recordp->ops_cnt[10],
    //     op_names[11], recordp->ops_cnt[11],
    //     op_names[12], recordp->ops_cnt[12],
    //     op_names[13], recordp->ops_cnt[13],
    //     op_names[14], recordp->ops_cnt[14]
    // );

    // in one line
    // bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[0], recordp->ops_cnt[0], op_names[1], recordp->ops_cnt[1], op_names[2], recordp->ops_cnt[2], op_names[3], recordp->ops_cnt[3], op_names[4], recordp->ops_cnt[4], op_names[5], recordp->ops_cnt[5], op_names[6], recordp->ops_cnt[6], op_names[7], recordp->ops_cnt[7], op_names[8], recordp->ops_cnt[8], op_names[9], recordp->ops_cnt[9], op_names[10], recordp->ops_cnt[10], op_names[11], recordp->ops_cnt[11], op_names[12], recordp->ops_cnt[12], op_names[13], recordp->ops_cnt[13], op_names[14], recordp->ops_cnt[14]);

    // 0 to 2
    // bpf_printk("pid %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[0], recordp->ops_cnt[0], op_names[1], recordp->ops_cnt[1], op_names[2], recordp->ops_cnt[2]);
    // 0 to 4
    bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[0], recordp->ops_cnt[0], op_names[1], recordp->ops_cnt[1], op_names[2], recordp->ops_cnt[2], op_names[3], recordp->ops_cnt[3], op_names[4], recordp->ops_cnt[4]);
    // 5 to 9
    bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[5], recordp->ops_cnt[5], op_names[6], recordp->ops_cnt[6], op_names[7], recordp->ops_cnt[7], op_names[8], recordp->ops_cnt[8], op_names[9], recordp->ops_cnt[9]);
    // 10 to 14
    bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[10], recordp->ops_cnt[10], op_names[11], recordp->ops_cnt[11], op_names[12], recordp->ops_cnt[12], op_names[13], recordp->ops_cnt[13], op_names[14], recordp->ops_cnt[14]);

    // 0 to 7
    // bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[0], recordp->ops_cnt[0], op_names[1], recordp->ops_cnt[1], op_names[2], recordp->ops_cnt[2], op_names[3], recordp->ops_cnt[3], op_names[4], recordp->ops_cnt[4], op_names[5], recordp->ops_cnt[5], op_names[6], recordp->ops_cnt[6], op_names[7], recordp->ops_cnt[7]);
    
    return;
}

// lookup
// SEC("fentry/vfs_lookup")
// int BPF_PROG(vfs_lookup, struct nameidata *nd, struct qstr *name)
// {
//     increase_record(0);
//     return 0;
// }

// getattr
SEC("fentry/vfs_getattr")
int BPF_PROG(vfs_getattr, struct path *path)
{
    increase_record(1);
    return 0;
}

// rename
SEC("fentry/vfs_rename")
int BPF_PROG(vfs_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    increase_record(2);
    return 0;
}

// setattr
// SEC("fentry/vfs_setattr")
// int BPF_PROG(vfs_setattr, struct dentry *dentry, struct iattr *attr)
// {
//     increase_record(3);
//     return 0;
// }

// create
SEC("fentry/vfs_create")
int BPF_PROG(vfs_create, struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
    increase_record(4);
    return 0;
}

// open
SEC("fentry/do_sys_openat2")
int BPF_PROG(do_openat, int dfd, void *pathname, void *how)
{
    increase_record(5);
	return 0;
}

// release
// SEC("fentry/vfs_release")
// int BPF_PROG(vfs_release, struct inode *inode, struct file *filp)
// {
//     increase_record(6);
//     return 0;
// }

// getxattr
SEC("fentry/vfs_getxattr")
int BPF_PROG(vfs_getxattr, struct dentry *dentry, const char *name)
{
    increase_record(7);
    return 0;
}

// mkdir
SEC("fentry/vfs_mkdir")
int BPF_PROG(vfs_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    increase_record(8);
    return 0;
}

// unlink
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    increase_record(9);
	return 0;
}

// opendir
SEC("fentry/vfs_open")
int BPF_PROG(vfs_open, struct inode *inode, struct file *filp)
{
    increase_record(10);
    return 0;
}

// readdir
// SEC("fentry/vfs_readdir")
// int BPF_PROG(vfs_readdir, struct file *file, struct dir_context *ctx)
// {
//     increase_record(11);
//     return 0;
// }

// releasedir
// SEC("fentry/vfs_releasedir")
// int BPF_PROG(vfs_releasedir, struct inode *inode, struct file *filp)
// {
//     increase_record(12);
//     return 0;
// }

// read
SEC("fentry/vfs_read")
int BPF_PROG(vfs_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
    increase_record(13);
    return 0;
}

// write
SEC("fentry/vfs_write")
int BPF_PROG(vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    increase_record(14);
    return 0;
}

// SEC("fexit/do_unlinkat")
// int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
// {
// 	pid_t pid;

// 	pid = bpf_get_current_pid_tgid() >> 32;
// 	bpf_printk("fexit: pid = %d, filename = %s, ret = %ld\n", pid, name->name, ret);
// 	return 0;
// }
