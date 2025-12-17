#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
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

/* CRC32 byte using map lookup */
static __always_inline __u32 crc32_byte(__u32 crc, __u8 b) {
    __u32 idx = (crc ^ b) & 0xFF;
    __u32 *val = bpf_map_lookup_elem(&crc32_map, &idx);
    if (!val)
        return crc >> 8;
    return *val ^ (crc >> 8);
}

/* Verify CRC32 header */
static __always_inline int verify_crc32(struct tunnel_hdr *thdr) {
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
    return (bpf_ntohl(thdr->crc32) == (crc ^ 0xFFFFFFFF));
}

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

    /* Check nếu là tunnel packet */
    __u16 dst_port = bpf_ntohs(udp->dest);
    int is_tunnel = 0;

    #pragma unroll
    for (__u32 i = 0; i < MAX_WAN; i++) {
        struct wan_cfg *wan = bpf_map_lookup_elem(&wan_map, &i);
        if (wan && wan->active && wan->local_port == dst_port) {
            is_tunnel = 1;
            break;
        }
    }

    if (!is_tunnel)
        return TC_ACT_OK;

    /* Parse tunnel header */
    struct tunnel_hdr *thdr = (void *)(udp + 1);
    if ((void *)(thdr + 1) > data_end)
        return TC_ACT_OK;

    if (thdr->type != PKT_DATA)
        return TC_ACT_OK;

    /* Verify CRC32 */
    if (!verify_crc32(thdr))
        return TC_ACT_OK;

    /* Gỡ outer IP + UDP + tunnel header */
    int decap_size = IP_HEADER_SIZE + UDP_HEADER_SIZE + TUNNEL_HEADER_SIZE;
    if (bpf_skb_adjust_room(skb, -decap_size, BPF_ADJ_ROOM_MAC, 0) < 0)
        return TC_ACT_OK;

    /* Reload pointers */
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;

    eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    /* Set MAC để kernel chấp nhận packet */
    /* dst = broadcast để interface nhận */
    /* src = 0 (kernel sẽ tự xử lý khi forward) */
    __u8 bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    __u8 zero[6] = {0};
    __builtin_memcpy(eth->h_dest, bcast, 6);
    __builtin_memcpy(eth->h_source, zero, 6);

    /* Redirect to local interface */
    return bpf_redirect(cfg->local_ifindex, BPF_F_INGRESS);
}

char LICENSE[] SEC("license") = "GPL";
