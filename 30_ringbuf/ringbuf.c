#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "ringbuf.skel.h"
#include "msg.h"

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

static int handle_msg(void *ctx, void *data, size_t sz)
{
    const struct my_msg *msg = data;
    fprintf(stdout, "PID %d, command: %s, path: %s\n", msg->pid, msg->command, msg->pathname);
    return 0;
}

int main(void)
{
    bump_memlock_rlimit();

    struct ringbuf *skel = ringbuf__open();
    ringbuf__load(skel);
    ringbuf__attach(skel);

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_msg, NULL, NULL);

    while(true) {
        ring_buffer__poll(rb, 1000);
    }
    return 0;
}
