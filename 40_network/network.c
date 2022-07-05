#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <netdb.h>
#include <linux/pkt_cls.h>
#include <linux/if_arp.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <unistd.h>

#include "network.skel.h"

static void bump_memlock_rlimit(void)
{
	struct rlimit rlim_new = {
		.rlim_cur	= RLIM_INFINITY,
		.rlim_max	= RLIM_INFINITY,
	};

	if (setrlimit(RLIMIT_MEMLOCK, &rlim_new)) {
		fprintf(stderr, "Failed to increase RLIMIT_MEMLOCK limit!\n");
		exit(1);
	}
}

bool running;

static void sig_handler(int sig)
{
    running = false;
}

int main(void)
{
	DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = 2, .attach_point = BPF_TC_EGRESS);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .handle = 1, .priority = 1);

    bump_memlock_rlimit();

    struct network *skel = network__open();
    network__load(skel);

    bpf_tc_hook_create(&hook);
    hook.attach_point = BPF_TC_CUSTOM;
    hook.parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    opts.prog_fd = bpf_program__fd(skel->progs.handle_egress);
    opts.prog_id = 0; 
    opts.flags = BPF_TC_F_REPLACE;
    bpf_tc_attach(&hook, &opts);

    running = true;
    
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while(running)
        ;

    opts.flags = 0;
    opts.prog_fd = 0;
    opts.prog_id = 0;
    int dtch = bpf_tc_detach(&hook, &opts);
    int dstr = bpf_tc_hook_destroy(&hook);
	
    return 0;
}
