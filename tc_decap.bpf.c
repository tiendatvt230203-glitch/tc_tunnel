#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tc_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_cfg);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_WAN);
    __type(key, __u32);
    __type(value, struct wan_cfg);
} wan_map SEC(".maps");

SEC("classifier")
int tc_decap_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;
    if (ip->protocol != IPPROTO_UDP) return TC_ACT_OK;

    struct udphdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    // Kiểm tra tunnel port
    __u16 port = bpf_ntohs(udp->dest);
    int found = 0;
    #pragma unroll
    for (__u32 i = 0; i < MAX_WAN; i++) {
        struct wan_cfg *w = bpf_map_lookup_elem(&wan_map, &i);
        if (w && w->active && w->local_port == port) { found = 1; break; }
    }
    if (!found) return TC_ACT_OK;

    // Kiểm tra magic byte
    struct tunnel_hdr *th = (void *)(udp + 1);
    if ((void *)(th + 1) > data_end) return TC_ACT_OK;
    if (th->magic != MAGIC) return TC_ACT_OK;

    __u32 k = 0;
    struct tunnel_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &k);
    if (!cfg) return TC_ACT_OK;

    // Gỡ 33 bytes header
    if (bpf_skb_adjust_room(skb, -33, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;

    // Set MAC broadcast để kernel nhận
    __builtin_memset(eth->h_dest, 0xff, 6);
    __builtin_memset(eth->h_source, 0, 6);

    // Forward ra local interface
    return bpf_redirect(cfg->local_ifindex, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
