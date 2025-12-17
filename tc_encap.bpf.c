#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tc_common.h"

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_WAN);
    __type(key, __u32);
    __type(value, struct wan_info);
} wan_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_entry);
} flow_map SEC(".maps");

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
    __type(value, __u32);
} lb_counter SEC(".maps");

static __always_inline __u32 hash_flow(struct flow_key *key) {
    __u32 hash = key->src_ip ^ key->dst_ip;
    hash ^= ((__u32)key->src_port << 16) | key->dst_port;
    hash ^= key->protocol;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    return hash;
}

static __always_inline __u16 csum_fold(__u32 csum) {
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

static __always_inline __u32 csum_add(__u32 csum, __u32 addend) {
    csum += addend;
    return csum + (csum < addend);
}

SEC("tc")
int tc_encap_prog(struct __sk_buff *skb) {
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

    struct flow_key fkey = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
    };

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
        if ((void *)(tcp + 1) > data_end)
            return TC_ACT_OK;
        fkey.src_port = tcp->source;
        fkey.dst_port = tcp->dest;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)ip + (ip->ihl * 4);
        if ((void *)(udp + 1) > data_end)
            return TC_ACT_OK;
        fkey.src_port = udp->source;
        fkey.dst_port = udp->dest;
    }

    __u32 key0 = 0;
    struct tunnel_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &key0);
    if (!cfg || cfg->wan_count == 0)
        return TC_ACT_OK;

    __u32 wan_idx;
    struct flow_entry *flow = bpf_map_lookup_elem(&flow_map, &fkey);

    if (flow) {
        wan_idx = flow->wan_index;
        flow->seq++;
        flow->last_seen = bpf_ktime_get_ns();
    } else {
        __u32 *counter = bpf_map_lookup_elem(&lb_counter, &key0);
        if (counter) {
            wan_idx = (*counter) % cfg->wan_count;
            (*counter)++;
        } else {
            wan_idx = hash_flow(&fkey) % cfg->wan_count;
        }

        struct flow_entry new_flow = {
            .wan_index = wan_idx,
            .seq = 1,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_map, &fkey, &new_flow, BPF_ANY);
        flow = bpf_map_lookup_elem(&flow_map, &fkey);
    }

    struct wan_info *wan = bpf_map_lookup_elem(&wan_map, &wan_idx);
    if (!wan || !wan->active)
        return TC_ACT_OK;

    __u32 orig_len = skb->len - sizeof(struct ethhdr);
    int encap_size = sizeof(struct iphdr) + sizeof(struct udphdr) + TUNNEL_HEADER_SIZE;

    if (bpf_skb_adjust_room(skb, encap_size, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __builtin_memcpy(eth->h_dest, wan->peer_mac, 6);
    __builtin_memcpy(eth->h_source, wan->local_mac, 6);

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return TC_ACT_OK;

    outer_ip->version = 4;
    outer_ip->ihl = 5;
    outer_ip->tos = 0;
    outer_ip->tot_len = bpf_htons(skb->len - sizeof(struct ethhdr));
    outer_ip->id = bpf_htons(0);
    outer_ip->frag_off = bpf_htons(0x4000);
    outer_ip->ttl = 64;
    outer_ip->protocol = IPPROTO_UDP;
    outer_ip->saddr = wan->local_ip;
    outer_ip->daddr = wan->peer_ip;
    outer_ip->check = 0;

    __u32 csum = 0;
    __u16 *ptr = (__u16 *)outer_ip;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        csum = csum_add(csum, ptr[i]);
    outer_ip->check = csum_fold(csum);

    struct udphdr *outer_udp = (void *)(outer_ip + 1);
    if ((void *)(outer_udp + 1) > data_end)
        return TC_ACT_OK;

    outer_udp->source = bpf_htons(wan->local_port);
    outer_udp->dest = bpf_htons(wan->peer_port);
    outer_udp->len = bpf_htons(skb->len - sizeof(struct ethhdr) - sizeof(struct iphdr));
    outer_udp->check = 0;

    struct tunnel_hdr *thdr = (void *)(outer_udp + 1);
    if ((void *)(thdr + 1) > data_end)
        return TC_ACT_OK;

    thdr->type = PKT_DATA;
    thdr->flow_id = bpf_htonl(hash_flow(&fkey));
    thdr->seq = flow ? bpf_htonl(flow->seq) : bpf_htonl(1);
    thdr->len = bpf_htonl(orig_len);
    thdr->crc32 = 0;
    #pragma unroll
    for (int i = 0; i < 30; i++)
        thdr->reserved[i] = 0;

    return bpf_redirect(wan->ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
