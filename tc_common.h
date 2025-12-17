#ifndef TC_COMMON_H
#define TC_COMMON_H

#define TUNNEL_PORT         5001
#define TUNNEL_MAGIC        0x544E4C
#define TUNNEL_HEADER_SIZE  47
#define MAX_WAN             8
#define MAX_FLOWS           4096

#define PKT_DATA    0x01
#define PKT_ACK     0x02
#define PKT_NACK    0x03

struct tunnel_hdr {
    __u8  type;
    __u32 flow_id;
    __u32 seq;
    __u32 len;
    __u32 crc32;
    __u8  reserved[30];
} __attribute__((packed));

struct wan_info {
    __u32 local_ip;
    __u32 peer_ip;
    __u16 local_port;
    __u16 peer_port;
    __u32 ifindex;
    __u8  local_mac[6];
    __u8  peer_mac[6];
    __u8  active;
};

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
} __attribute__((packed));

struct flow_entry {
    __u32 wan_index;
    __u32 seq;
    __u64 last_seen;
};

struct tunnel_cfg {
    __u32 local_ifindex;
    __u32 wan_count;
};

#endif
