#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct mkdir_params_t {
    uint64_t unused1;
    uint64_t unused2;
    const char *pathname;
};

SEC("tp/syscalls/sys_enter_mkdir")
int handle_mkdir(struct mkdir_params_t *params)
{
    bpf_printk("Name: %s", params->pathname);
    return 0;
}
