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
    __uint(max_entries, MAX_WAN);
    __type(key, __u32);
    __type(value, struct wan_cfg);
} wan_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct tunnel_cfg);
} cfg_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct global_state);
} global_map SEC(".maps");

SEC("classifier")
int tc_encap_prog(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP)) return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return TC_ACT_OK;

    __u32 k = 0;
    struct tunnel_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &k);
    if (!cfg || !cfg->wan_count) return TC_ACT_OK;

    // CHỈ encap traffic đi đến REMOTE subnet
    if ((ip->daddr & cfg->remote_mask) != cfg->remote_net)
        return TC_ACT_OK;

    struct global_state *gs = bpf_map_lookup_elem(&global_map, &k);
    if (!gs) return TC_ACT_OK;

    // Round-robin chọn WAN
    __u32 wan_idx = gs->wan_idx % cfg->wan_count;
    __u32 seq = gs->seq++;
    gs->wan_idx++;

    struct wan_cfg *wan = bpf_map_lookup_elem(&wan_map, &wan_idx);
    if (!wan || !wan->active) return TC_ACT_OK;

    // Thêm header: IP(20) + UDP(8) + tunnel(5) = 33 bytes
    if (bpf_skb_adjust_room(skb, 33, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end) return TC_ACT_OK;
    __builtin_memcpy(eth->h_dest, wan->dst_mac, 6);
    __builtin_memcpy(eth->h_source, wan->src_mac, 6);

    struct iphdr *oip = (void *)(eth + 1);
    if ((void *)(oip + 1) > data_end) return TC_ACT_OK;

    oip->version = 4;
    oip->ihl = 5;
    oip->tos = 0;
    oip->tot_len = bpf_htons(skb->len - 14);
    oip->id = 0;
    oip->frag_off = bpf_htons(0x4000);
    oip->ttl = 64;
    oip->protocol = IPPROTO_UDP;
    oip->saddr = wan->local_ip;
    oip->daddr = wan->peer_ip;
    oip->check = 0;

    __u32 sum = 0;
    __u16 *p = (void *)oip;
    #pragma unroll
    for (int i = 0; i < 10; i++) sum += p[i];
    sum = (sum & 0xffff) + (sum >> 16);
    oip->check = ~sum;

    struct udphdr *udp = (void *)(oip + 1);
    if ((void *)(udp + 1) > data_end) return TC_ACT_OK;

    udp->source = bpf_htons(wan->local_port);
    udp->dest = bpf_htons(wan->peer_port);
    udp->len = bpf_htons(skb->len - 34);
    udp->check = 0;

    struct tunnel_hdr *th = (void *)(udp + 1);
    if ((void *)(th + 1) > data_end) return TC_ACT_OK;

    th->magic = MAGIC;
    th->seq = bpf_htonl(seq);

    return bpf_redirect(wan->ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
