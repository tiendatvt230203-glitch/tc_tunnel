#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "tc_common.h"

static const __u32 crc32_tab[256] = {
    0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,0x9E6495A3,
    0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,0xE7B82D07,0x90BF1D91,
    0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
    0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,
    0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
    0x35B5A8FA,0x42B2986C,0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
    0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
    0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
    0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
    0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,0x086D3D2D,0x91646C97,0xE6635C01,
    0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
    0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
    0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,
    0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
    0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,0xCE61E49F,
    0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,0xB7BD5C3B,0xC0BA6CAD,
    0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,0x9DD277AF,0x04DB2615,0x73DC1683,
    0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,
    0xF00F9344,0x8708A3D2,0x1E01F268,0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,
    0xFED41B76,0x89D32BE0,0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,
    0xD6D6A3E8,0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
    0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,0x4669BE79,
    0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,0x220216B9,0x5505262F,
    0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,
    0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,
    0x95BF4A82,0xE2B87A14,0x7BB12BAE,0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,
    0x86D3D2D4,0xF1D4E242,0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,
    0x88085AE6,0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
    0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,0x3E6E77DB,
    0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,0x47B2CF7F,0x30B5FFE9,
    0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,0xCDD70693,0x54DE5729,0x23D967BF,
    0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D
};

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
    return crc32_tab[(crc ^ b) & 0xFF] ^ (crc >> 8);
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
