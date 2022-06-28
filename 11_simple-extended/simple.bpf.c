#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_mkdir")
int handle_mkdir(void *params)
{
    struct task_struct *task = (struct task_struct*)bpf_get_current_task();
    int pid = BPF_CORE_READ(task, pid);
    bpf_printk("PID=%d\n", pid);
    return 0;
}
