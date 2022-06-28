#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "msg.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct exec_params_t {
    u64 __unused;
    u64 __unused2;

    char *file;
};

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct exec_params_t *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    struct my_msg *msg;

    msg = bpf_ringbuf_reserve(&rb, sizeof(*msg), 0);
    if (!msg) {
        bpf_printk("ERROR: unable to reserve memory\n");
        return 0;
    }

    msg->tgid = BPF_CORE_READ(task, tgid);
    msg->pid = BPF_CORE_READ(task, pid);
    bpf_get_current_comm(&msg->comm, sizeof(msg->comm));
    bpf_probe_read_user_str(msg->file, sizeof(msg->file), params->file);
    bpf_ringbuf_submit(msg, 0);
    bpf_printk("Exec Called\n");
    return 0;
}
