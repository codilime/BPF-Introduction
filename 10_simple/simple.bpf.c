#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(void *params)
{
    bpf_printk("Codilime!");
    return 0;
}
