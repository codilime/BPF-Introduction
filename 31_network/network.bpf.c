#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define DNS_PORT 53

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

SEC("classifier")
int handle_egress(struct __sk_buff *skb)
{
    void *data_end = (void*)(long)skb->data_end;
    struct ethhdr *eth = (struct ethhdr*)(void*)(long)skb->data;

    if ((void*)eth + sizeof(*eth) + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;       // not IP

    if (eth->h_proto != bpf_htons(0x0800))
        return TC_ACT_OK;       // not IPv4

    // IP header
    struct iphdr *iph = (struct iphdr*)((void*)eth + sizeof(*eth));

    // TCP header
    struct tcphdr *tcph = (struct tcphdr*)((void*)iph + sizeof(struct iphdr));

    // destination address
    uint32_t dest_addr = bpf_ntohl(iph->daddr);

    // TCP/UDP port
    int port = bpf_ntohs(BPF_CORE_READ(tcph, dest));

    // if (dest_addr == 0x1f3de1fe)
    //     return 0;  // workaround: filter my SSH traffic

    // switch(iph->protocol)
    // {
    //     case IPPROTO_TCP:
    //         bpf_printk("TCP %x:%d", dest_addr, port);
    //         break;
    //     case IPPROTO_UDP:
    //         bpf_printk("UDP %x:%d", dest_addr, port);
    //         break;
    //     case IPPROTO_ICMP:
    //         bpf_printk("ICMP %x:%d", dest_addr);
    //     default:
    //         return TC_ACT_OK;
    // }

    if(iph->protocol == IPPROTO_UDP && port == DNS_PORT)
    {
        bpf_printk("DNS blocked! %x:%d", dest_addr, port);
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}
