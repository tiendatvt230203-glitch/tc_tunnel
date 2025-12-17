#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
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
    __type(value, struct wan_info);
} wan_map SEC(".maps");

SEC("tc")
int tc_decap_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IPPROTO_UDP)
        return TC_ACT_OK;

    struct udphdr *udp = (void *)ip + (ip->ihl * 4);
    if ((void *)(udp + 1) > data_end)
        return TC_ACT_OK;

    __u32 key0 = 0;
    struct tunnel_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &key0);
    if (!cfg)
        return TC_ACT_OK;

    __u16 dst_port = bpf_ntohs(udp->dest);
    int is_tunnel = 0;

    #pragma unroll
    for (__u32 i = 0; i < MAX_WAN; i++) {
        struct wan_info *wan = bpf_map_lookup_elem(&wan_map, &i);
        if (wan && wan->active && wan->local_port == dst_port) {
            is_tunnel = 1;
            break;
        }
    }

    if (!is_tunnel)
        return TC_ACT_OK;

    struct tunnel_hdr *thdr = (void *)(udp + 1);
    if ((void *)(thdr + 1) > data_end)
        return TC_ACT_OK;

    if (thdr->type != PKT_DATA)
        return TC_ACT_OK;

    int decap_size = sizeof(struct iphdr) + sizeof(struct udphdr) + TUNNEL_HEADER_SIZE;

    __u8 inner_dst_mac[6];
    __u8 inner_src_mac[6];

    void *inner_eth = (void *)thdr + TUNNEL_HEADER_SIZE;
    if (inner_eth + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    struct ethhdr *inner = inner_eth;
    __builtin_memcpy(inner_dst_mac, inner->h_dest, 6);
    __builtin_memcpy(inner_src_mac, inner->h_source, 6);

    if (bpf_skb_adjust_room(skb, -decap_size, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __builtin_memcpy(eth->h_dest, inner_dst_mac, 6);
    __builtin_memcpy(eth->h_source, inner_src_mac, 6);

    return bpf_redirect(cfg->local_ifindex, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
