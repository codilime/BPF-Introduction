all:
	@bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
	@clang -g -O3 -target bpf -D__TARGET_ARCH_x86_64 -c simple.bpf.c -o simple.bpf.o
	@bpftool gen skeleton simple.bpf.o name simple > simple.skel.h
	@clang simple.c -lbpf -lelf -o simple

.PHONY: clean
clean:
	@rm -rf *.o *.skel.h vmlinux.h simple
