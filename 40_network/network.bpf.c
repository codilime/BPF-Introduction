#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

//#include <linux/pkt_cls.h>
#define TC_ACT_OK		    0
#define TC_ACT_RECLASSIFY	1
#define TC_ACT_SHOT		    2
#define TC_ACT_PIPE		    3
#define TC_ACT_STOLEN		4
#define TC_ACT_QUEUED		5
#define TC_ACT_REPEAT		6
#define TC_ACT_REDIRECT		7
#define TC_ACT_TRAP		    8

static int show_some_info(struct iphdr *iph)
{
    uint32_t dest_addr = bpf_ntohl(iph->daddr);

    // if (dest_addr == 0xd5bd2fd2)
    //     return 0;  // workaround: filter vscode-server traffic

    switch(iph->protocol)
    {
        case IPPROTO_TCP:
            {
                struct tcphdr *tcph = (struct tcphdr*)((void*)iph + sizeof(struct iphdr));
                int port = bpf_ntohs(tcph->dest);
                bpf_printk("TCP %x:%d", dest_addr, port);
                break;
            }
        case IPPROTO_UDP:
            {
                struct udphdr *udph = (struct udphdr*)((void*)iph + sizeof(struct iphdr));
                int port = bpf_ntohs(udph->dest);
                bpf_printk("UDP %x:%d", dest_addr, port);
                break;
            }
        case IPPROTO_ICMP:
            bpf_printk("ICMP %x", dest_addr);
            break;
    }
    return TC_ACT_OK;
}

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;

    if ((void*)eth + sizeof(*eth) + sizeof(struct iphdr) + sizeof(struct udphdr) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(0x0800))
        return TC_ACT_OK;       // not IPv4

    // IP header
    struct iphdr *iph = (struct iphdr*)((void*)eth + sizeof(*eth));

    // return show_some_info(iph);

    if(iph->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    // UDP header
    struct udphdr *udph = (struct udphdr*)((void*)iph + sizeof(struct iphdr));

    // UDP port
    int port = bpf_ntohs(udph->dest);

    if(port == 53)
    {
        bpf_printk("Block!");
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}
