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
#define LOG_OP_NUM 5
#define OP_MASK ((1 << LOG_OP_NUM) - 1)

struct record {
    unsigned int pid;
    int ops_cnt[NUM_OPERATIONS];
    __u64 ops_time[NUM_OPERATIONS];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct record);
} record_map SEC(".maps");

struct timer_event {
    __u64 timestamp;
    // __u32 pid;
    // __u32 operation;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, struct timer_event);
} timer_map SEC(".maps");

static void increase_record(int op_id, __u64 op_time)
{
    __u32 pid = (__u32)bpf_get_current_pid_tgid();
    struct record *recordp = bpf_map_lookup_elem(&record_map, &pid);
    if(!recordp) {
        struct record record = {};
        record.pid = pid;
        record.ops_cnt[op_id] = 1;
        record.ops_time[op_id] = op_time;
        bpf_map_update_elem(&record_map, &pid, &record, BPF_ANY);
        return;
    }

    ++recordp->ops_cnt[op_id];
    recordp->ops_time[op_id] += op_time;
    
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
    // bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[0], recordp->ops_cnt[0], op_names[1], recordp->ops_cnt[1], op_names[2], recordp->ops_cnt[2], op_names[3], recordp->ops_cnt[3], op_names[4], recordp->ops_cnt[4]);
    // // 5 to 9
    // bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[5], recordp->ops_cnt[5], op_names[6], recordp->ops_cnt[6], op_names[7], recordp->ops_cnt[7], op_names[8], recordp->ops_cnt[8], op_names[9], recordp->ops_cnt[9]);
    // // 10 to 14
    // bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[10], recordp->ops_cnt[10], op_names[11], recordp->ops_cnt[11], op_names[12], recordp->ops_cnt[12], op_names[13], recordp->ops_cnt[13], op_names[14], recordp->ops_cnt[14]);

    // 0 to 7
    // bpf_printk("pid %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d, %s %d\n", recordp->pid, op_names[0], recordp->ops_cnt[0], op_names[1], recordp->ops_cnt[1], op_names[2], recordp->ops_cnt[2], op_names[3], recordp->ops_cnt[3], op_names[4], recordp->ops_cnt[4], op_names[5], recordp->ops_cnt[5], op_names[6], recordp->ops_cnt[6], op_names[7], recordp->ops_cnt[7]);

    // only open, read, write
    bpf_printk("[COUNT] pid %d, %s %d, %s %d, %s %d", recordp->pid, op_names[5], recordp->ops_cnt[5], op_names[13], recordp->ops_cnt[13], op_names[14], recordp->ops_cnt[14]);
    // op_time
    bpf_printk("[OTIME] pid %d, %s %llu, %s %llu, %s %llu", recordp->pid, op_names[5], recordp->ops_time[5], op_names[13], recordp->ops_time[13], op_names[14], recordp->ops_time[14]);
    
    return;
}

static void timer_begin(int op_id)
{
    __u32 key = (__u32)bpf_get_current_pid_tgid();
    key = (key << LOG_OP_NUM) | (op_id & OP_MASK);

    struct timer_event event = {};
    event.timestamp = bpf_ktime_get_ns();

    bpf_map_update_elem(&timer_map, &key, &event, BPF_ANY);
}

static __u64 timer_end(int op_id)
{
    __u32 key = (__u32)bpf_get_current_pid_tgid();
    key = (key << LOG_OP_NUM) | (op_id & OP_MASK);

    struct timer_event *eventp = bpf_map_lookup_elem(&timer_map, &key);
    if(!eventp) {
        return 0;
    }

    __u64 delta = bpf_ktime_get_ns() - eventp->timestamp;
    bpf_map_delete_elem(&timer_map, &key);
    return delta;
}
// lookup
// SEC("fentry/vfs_lookup")
// int BPF_PROG(vfs_lookup, struct nameidata *nd, struct qstr *name)
// {
//     timer_begin(0);
//     return 0;
// }
// SEC("fexit/vfs_lookup")
// int BPF_PROG(vfs_lookup_exit, struct nameidata *nd, struct qstr *name, long ret)
// {
//     __u64 op_time = timer_end(0);
//     increase_record(0, op_time);
//     return 0;
// }

// getattr
SEC("fentry/vfs_getattr")
int BPF_PROG(vfs_getattr, struct path *path)
{
    timer_begin(1);
    return 0;
}
SEC("fexit/vfs_getattr")
int BPF_PROG(vfs_getattr_exit, struct path *path, long ret)
{
    __u64 op_time = timer_end(1);
    increase_record(1, op_time);
    return 0;
}

// rename
SEC("fentry/vfs_rename")
int BPF_PROG(vfs_rename, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry)
{
    timer_begin(2);
    return 0;
}
SEC("fexit/vfs_rename")
int BPF_PROG(vfs_rename_exit, struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir, struct dentry *new_dentry, long ret)
{
    __u64 op_time = timer_end(2);
    increase_record(2, op_time);
    return 0;
}

// setattr
// SEC("fentry/vfs_setattr")
// int BPF_PROG(vfs_setattr, struct dentry *dentry, struct iattr *attr)
// {
//     timer_begin(3);
//     return 0;
// }
// SEC("fexit/vfs_setattr")
// int BPF_PROG(vfs_setattr_exit, struct dentry *dentry, struct iattr *attr, long ret)
// {
//     __u64 op_time = timer_end(3);
//     increase_record(3, op_time);
//     return 0;
// }

// create
SEC("fentry/vfs_create")
int BPF_PROG(vfs_create, struct inode *dir, struct dentry *dentry, umode_t mode, bool excl)
{
    timer_begin(4);
    return 0;
}
SEC("fexit/vfs_create")
int BPF_PROG(vfs_create_exit, struct inode *dir, struct dentry *dentry, umode_t mode, bool excl, long ret)
{
    __u64 op_time = timer_end(4);
    increase_record(4, op_time);
    return 0;
}

// open
SEC("fentry/do_sys_openat2")
int BPF_PROG(do_openat, int dfd, void *pathname, void *how)
{
    timer_begin(5);
    return 0;
}
SEC("fexit/do_sys_openat2")
int BPF_PROG(do_openat_exit, int dfd, void *pathname, void *how, long ret)
{
    __u64 op_time = timer_end(5);
    increase_record(5, op_time);
    return 0;
}

// release
// SEC("fentry/vfs_release")
// int BPF_PROG(vfs_release, struct inode *inode, struct file *filp)
// {
//     timer_begin(6);
//     return 0;
// }
// SEC("fexit/vfs_release")
// int BPF_PROG(vfs_release_exit, struct inode *inode, struct file *filp, long ret)
// {
//     __u64 op_time = timer_end(6);
//     increase_record(6, op_time);
//     return 0;
// }

// getxattr
SEC("fentry/vfs_getxattr")
int BPF_PROG(vfs_getxattr, struct dentry *dentry, const char *name)
{
    timer_begin(7);
    return 0;
}
SEC("fexit/vfs_getxattr")
int BPF_PROG(vfs_getxattr_exit, struct dentry *dentry, const char *name, long ret)
{
    __u64 op_time = timer_end(7);
    increase_record(7, op_time);
    return 0;
}

// mkdir
SEC("fentry/vfs_mkdir")
int BPF_PROG(vfs_mkdir, struct inode *dir, struct dentry *dentry, umode_t mode)
{
    timer_begin(8);
    return 0;
}
SEC("fexit/vfs_mkdir")
int BPF_PROG(vfs_mkdir_exit, struct inode *dir, struct dentry *dentry, umode_t mode, long ret)
{
    __u64 op_time = timer_end(8);
    increase_record(8, op_time);
    return 0;
}

// unlink
SEC("fentry/do_unlinkat")
int BPF_PROG(do_unlinkat, int dfd, struct filename *name)
{
    timer_begin(9);
    return 0;
}
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    __u64 op_time = timer_end(9);
    increase_record(9, op_time);
    return 0;
}

// opendir
SEC("fentry/vfs_open")
int BPF_PROG(vfs_open, struct inode *inode, struct file *filp)
{
    timer_begin(10);
    return 0;
}
SEC("fexit/vfs_open")
int BPF_PROG(vfs_open_exit, struct inode *inode, struct file *filp, long ret)
{
    __u64 op_time = timer_end(10);
    increase_record(10, op_time);
    return 0;
}

// readdir
// SEC("fentry/vfs_readdir")
// int BPF_PROG(vfs_readdir, struct file *file, struct dir_context *ctx)
// {
//     timer_begin(11);
//     return 0;
// }
// SEC("fexit/vfs_readdir")
// int BPF_PROG(vfs_readdir_exit, struct file *file, struct dir_context *ctx, long ret)
// {
//     __u64 op_time = timer_end(11);
//     increase_record(11, op_time);
//     return 0;
// }

// releasedir
// SEC("fentry/vfs_releasedir")
// int BPF_PROG(vfs_releasedir, struct inode *inode, struct file *filp)
// {
//     timer_begin(12);
//     return 0;
// }
// SEC("fexit/vfs_releasedir")
// int BPF_PROG(vfs_releasedir_exit, struct inode *inode, struct file *filp, long ret)
// {
//     __u64 op_time = timer_end(12);
//     increase_record(12, op_time);
//     return 0;
// }

// read
SEC("fentry/vfs_read")
int BPF_PROG(vfs_read, struct file *file, char *buf, size_t count, loff_t *pos)
{
    timer_begin(13);
    return 0;
}
SEC("fexit/vfs_read")
int BPF_PROG(vfs_read_exit, struct file *file, char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 op_time = timer_end(13);
    increase_record(13, op_time);
    return 0;
}

// write
SEC("fentry/vfs_write")
int BPF_PROG(vfs_write, struct file *file, const char *buf, size_t count, loff_t *pos)
{
    timer_begin(14);
    return 0;
}
SEC("fexit/vfs_write")
int BPF_PROG(vfs_write_exit, struct file *file, const char *buf, size_t count, loff_t *pos, ssize_t ret)
{
    __u64 op_time = timer_end(14);
    increase_record(14, op_time);
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
