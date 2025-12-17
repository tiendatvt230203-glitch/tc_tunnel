#ifndef TC_COMMON_H
#define TC_COMMON_H

#define WAN_MTU             1500
#define IP_HEADER_SIZE      20
#define UDP_HEADER_SIZE     8
#define ETH_HEADER_SIZE     14

#define TUNNEL_HEADER_USED  17
#define TUNNEL_HEADER_RSVD  30
#define TUNNEL_HEADER_SIZE  47

#define MAX_FRAME_SIZE      1425
#define LOCAL_MTU           1411

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
    __u8  reserved[TUNNEL_HEADER_RSVD];
} __attribute__((packed));

struct wan_cfg {
    __u32 local_ip;
    __u32 peer_ip;
    __u16 local_port;
    __u16 peer_port;
    __u32 ifindex;
    __u8  local_mac[6];
    __u8  gw_mac[6];
    __u8  active;
    __u8  pad[3];
};

struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u8  pad[3];
};

struct flow_state {
    __u32 wan_idx;
    __u32 tx_seq;
    __u64 last_seen;
};

struct tunnel_cfg {
    __u32 local_ifindex;
    __u32 wan_count;
    __u32 remote_subnet;
    __u32 remote_mask;
};

struct lb_state {
    __u32 wan_idx;
};

#endif
