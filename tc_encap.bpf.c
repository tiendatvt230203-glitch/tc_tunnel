#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tc_common.h"

/* CRC32 table stored in BPF map to avoid verifier issues with static arrays */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, __u32);
} crc32_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_WAN);
    __type(key, __u32);
    __type(value, struct wan_cfg);
} wan_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_FLOWS);
    __type(key, struct flow_key);
    __type(value, struct flow_state);
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
    __type(value, struct lb_state);
} lb_map SEC(".maps");

static __always_inline __u32 hash_5tuple(struct flow_key *key) {
    __u32 hash = key->src_ip ^ key->dst_ip;
    hash ^= ((__u32)key->src_port << 16) | key->dst_port;
    hash ^= key->protocol;
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;
    return hash ? hash : 1;
}

static __always_inline __u32 crc32_byte(__u32 crc, __u8 b) {
    __u32 idx = (crc ^ b) & 0xFF;
    __u32 *val = bpf_map_lookup_elem(&crc32_map, &idx);
    if (!val)
        return crc >> 8;
    return *val ^ (crc >> 8);
}

static __always_inline __u16 ip_checksum(void *data, int len) {
    __u32 sum = 0;
    __u16 *p = data;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        sum += p[i];
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return ~sum;
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

    __u32 key0 = 0;
    struct tunnel_cfg *cfg = bpf_map_lookup_elem(&cfg_map, &key0);
    if (!cfg || cfg->wan_count == 0)
        return TC_ACT_OK;

    /* === FILTER: Chỉ encap traffic đến remote subnet === */
    __u32 dst = bpf_ntohl(ip->daddr);

    /* Bỏ qua broadcast */
    if ((dst & 0xFF) == 0xFF)
        return TC_ACT_OK;

    /* Bỏ qua multicast (224.0.0.0/4) */
    if ((dst >> 28) == 0xE)
        return TC_ACT_OK;

    /* Chỉ encap nếu dst thuộc remote subnet */
    if ((ip->daddr & cfg->remote_mask) != cfg->remote_subnet)
        return TC_ACT_OK;

    /* Bỏ qua packet đến peer IP (tunnel traffic) */
    #pragma unroll
    for (__u32 i = 0; i < MAX_WAN; i++) {
        struct wan_cfg *w = bpf_map_lookup_elem(&wan_map, &i);
        if (w && w->active && ip->daddr == w->peer_ip)
            return TC_ACT_OK;
    }

    /* Extract 5-tuple */
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

    __u32 flow_id = hash_5tuple(&fkey);
    __u32 wan_idx;
    __u32 seq;

    struct flow_state *flow = bpf_map_lookup_elem(&flow_map, &fkey);
    if (flow) {
        wan_idx = flow->wan_idx;
        seq = __sync_fetch_and_add(&flow->tx_seq, 1);
        flow->last_seen = bpf_ktime_get_ns();
    } else {
        struct lb_state *lb = bpf_map_lookup_elem(&lb_map, &key0);
        if (lb) {
            wan_idx = lb->wan_idx % cfg->wan_count;
            lb->wan_idx = (lb->wan_idx + 1) % cfg->wan_count;
        } else {
            wan_idx = 0;
        }
        seq = 0;

        struct flow_state new_flow = {
            .wan_idx = wan_idx,
            .tx_seq = 1,
            .last_seen = bpf_ktime_get_ns(),
        };
        bpf_map_update_elem(&flow_map, &fkey, &new_flow, BPF_ANY);
    }

    struct wan_cfg *wan = bpf_map_lookup_elem(&wan_map, &wan_idx);
    if (!wan || !wan->active)
        return TC_ACT_OK;

    __u32 orig_len = skb->len - ETH_HEADER_SIZE;

    int encap_size = IP_HEADER_SIZE + UDP_HEADER_SIZE + TUNNEL_HEADER_SIZE;
    if (bpf_skb_adjust_room(skb, encap_size, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    __builtin_memcpy(eth->h_dest, wan->gw_mac, 6);
    __builtin_memcpy(eth->h_source, wan->local_mac, 6);

    struct iphdr *outer_ip = (void *)(eth + 1);
    if ((void *)(outer_ip + 1) > data_end)
        return TC_ACT_OK;

    outer_ip->version = 4;
    outer_ip->ihl = 5;
    outer_ip->tos = 0;
    outer_ip->tot_len = bpf_htons(skb->len - ETH_HEADER_SIZE);
    outer_ip->id = bpf_htons(0);
    outer_ip->frag_off = bpf_htons(0x4000);
    outer_ip->ttl = 64;
    outer_ip->protocol = IPPROTO_UDP;
    outer_ip->saddr = wan->local_ip;
    outer_ip->daddr = wan->peer_ip;
    outer_ip->check = 0;
    outer_ip->check = ip_checksum(outer_ip, 20);

    struct udphdr *outer_udp = (void *)(outer_ip + 1);
    if ((void *)(outer_udp + 1) > data_end)
        return TC_ACT_OK;

    outer_udp->source = bpf_htons(wan->local_port);
    outer_udp->dest = bpf_htons(wan->peer_port);
    outer_udp->len = bpf_htons(skb->len - ETH_HEADER_SIZE - IP_HEADER_SIZE);
    outer_udp->check = 0;

    struct tunnel_hdr *thdr = (void *)(outer_udp + 1);
    if ((void *)(thdr + 1) > data_end)
        return TC_ACT_OK;

    thdr->type = PKT_DATA;
    thdr->flow_id = bpf_htonl(flow_id);
    thdr->seq = bpf_htonl(seq);
    thdr->len = bpf_htonl(orig_len);

    __u32 crc = 0xFFFFFFFF;
    crc = crc32_byte(crc, thdr->type);
    __u8 *p = (__u8 *)&thdr->flow_id;
    crc = crc32_byte(crc, p[0]); crc = crc32_byte(crc, p[1]);
    crc = crc32_byte(crc, p[2]); crc = crc32_byte(crc, p[3]);
    p = (__u8 *)&thdr->seq;
    crc = crc32_byte(crc, p[0]); crc = crc32_byte(crc, p[1]);
    crc = crc32_byte(crc, p[2]); crc = crc32_byte(crc, p[3]);
    p = (__u8 *)&thdr->len;
    crc = crc32_byte(crc, p[0]); crc = crc32_byte(crc, p[1]);
    crc = crc32_byte(crc, p[2]); crc = crc32_byte(crc, p[3]);
    thdr->crc32 = bpf_htonl(crc ^ 0xFFFFFFFF);

    #pragma unroll
    for (int i = 0; i < TUNNEL_HEADER_RSVD; i++)
        thdr->reserved[i] = 0;

    return bpf_redirect(wan->ifindex, 0);
}

char LICENSE[] SEC("license") = "GPL";
