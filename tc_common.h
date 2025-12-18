#ifndef TC_COMMON_H
#define TC_COMMON_H

#define MAX_WAN 8
#define MAGIC   0xAB

struct tunnel_hdr {
    __u8  magic;
    __u32 seq;
} __attribute__((packed));

struct wan_cfg {
    __u32 local_ip;
    __u32 peer_ip;
    __u16 local_port;
    __u16 peer_port;
    __u32 ifindex;
    __u8  src_mac[6];
    __u8  dst_mac[6];
    __u8  active;
};

struct tunnel_cfg {
    __u32 local_ifindex;
    __u32 wan_count;
    __u32 remote_net;   // Remote subnet (e.g., 192.168.182.0)
    __u32 remote_mask;  // Subnet mask (e.g., 255.255.255.0)
};

struct global_state {
    __u32 seq;
    __u32 wan_idx;
};

#endif
