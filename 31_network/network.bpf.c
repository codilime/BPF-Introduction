#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;

    if ((void*)eth + sizeof(*eth) + sizeof(struct iphdr) > data_end)
        return 0;

    if (eth->h_proto != bpf_htons(0x0800))
        return 0;       // not IPv4

    bpf_printk("is ipv4");

    struct iphdr *iph = (struct iphdr*)((void*)eth + sizeof(*eth));
    struct tcphdr *tcph = NULL;
    u8 hdr_sz = sizeof(struct iphdr);

    uint32_t dest_addr = bpf_ntohl(iph->daddr);

    // if (dest_addr == 0x1f3c9950)
    //     return 0;  // workaround: filter my SSH traffic

    bpf_printk("dest ip is %x", dest_addr);

    // struct udphdr *udph = NULL;
    // if ((void*)(iph + hdr_sz + sizeof(*udph)) > data_end) {
    //     bpf_printk("no udp");
    //     return NULL;
    // }

    // if ((void*)(iph + hdr_sz + sizeof(*tcph)) > data_end) {
    //     bpf_printk("no tcp");
    //     return 0;
    // }

    struct iphdr *v4 = (struct iphdr*)iph;
    if (v4->protocol != IPPROTO_TCP)
    {
        bpf_printk("not tcp");
        return 0;
    }
    bpf_printk("tcp");
    tcph = (struct tcphdr*)((void*)iph + hdr_sz);



    // bpf_printk("eth %x", BPF_CORE_READ(eth, h_proto));
    return 0;
}
