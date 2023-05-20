#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>

SEC("filter")
int hello_world(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;

    if (data + sizeof(struct ethhdr) > data_end)
        return XDP_DROP;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(struct ethhdr);

    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_DROP;

    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    // Print "Hello, World!" to kernel log
    bpf_trace_printk("Hello, World!\\n");

    return XDP_PASS;
}
