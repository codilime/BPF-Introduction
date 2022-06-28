all:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c ringbuf.bpf.c -o ringbuf.bpf.o
	@bpftool gen skeleton ringbuf.bpf.o name ringbuf > ringbuf.skel.h
	@clang ringbuf.c -lbpf -lelf -o ringbuf

.PHONY: clean
clean:
	@rm -rf *.o *.skel.h vmlinux.h ringbuf
