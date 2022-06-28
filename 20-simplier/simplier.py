from bcc import BPF

bpf_source = """
int handle_new_dir(void *params) {
  bpf_trace_printk("New dir");
  return 0;
}
"""

bpf = BPF(text = bpf_source)
execve_function = bpf.get_syscall_fnname("mkdir")
bpf.attach_kprobe(event = execve_function, fn_name = "handle_new_dir")
bpf.trace_print()
