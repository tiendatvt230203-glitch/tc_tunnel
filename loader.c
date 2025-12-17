#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tc_common.h"

static volatile int running = 1;

/* CRC32 lookup table */
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

static void init_crc32_map(int map_fd) {
    for (__u32 i = 0; i < 256; i++) {
        bpf_map_update_elem(map_fd, &i, &crc32_tab[i], BPF_ANY);
    }
}

static void sig_handler(int sig) {
    running = 0;
}

static int get_ifindex(const char *ifname) {
    return if_nametoindex(ifname);
}

static int get_mac(const char *ifname, __u8 *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return 0;
}

static int get_ip(const char *ifname, __u32 *ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = addr->sin_addr.s_addr;
    close(fd);
    return 0;
}

static int get_gateway_mac(const char *ifname, __u8 *mac) {
    memset(mac, 0xff, 6);
    return 0;
}

static int set_mtu(const char *ifname, int mtu) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;

    int ret = ioctl(fd, SIOCSIFMTU, &ifr);
    close(fd);
    return ret;
}

static int parse_cidr(const char *cidr, __u32 *subnet, __u32 *mask) {
    char ip_str[32];
    int prefix_len;

    if (sscanf(cidr, "%31[^/]/%d", ip_str, &prefix_len) != 2) {
        return -1;
    }

    if (prefix_len < 0 || prefix_len > 32) {
        return -1;
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_str, &addr) != 1) {
        return -1;
    }

    if (prefix_len == 0) {
        *mask = 0;
    } else {
        *mask = htonl(~((1U << (32 - prefix_len)) - 1));
    }

    *subnet = addr.s_addr & *mask;
    return 0;
}

static int attach_tc(int ifindex, int fd, int ingress) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
    );
    bpf_tc_hook_create(&hook);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
    return bpf_tc_attach(&hook, &opts);
}

static void detach_tc(int ifindex, int ingress) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
    );
    bpf_tc_hook_destroy(&hook);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <config_file>\n", argv[0]);
        return 1;
    }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        perror("fopen");
        return 1;
    }

    char local_if[32] = {0};
    struct wan_cfg wans[MAX_WAN];
    int wan_count = 0;
    __u32 remote_subnet = 0;
    __u32 remote_mask = 0;
    memset(wans, 0, sizeof(wans));

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char *cmd = strtok(line, " \t\n");
        if (!cmd) continue;

        if (strcmp(cmd, "local") == 0) {
            char *ifname = strtok(NULL, " \t\n");
            if (ifname) strncpy(local_if, ifname, sizeof(local_if) - 1);
        } else if (strcmp(cmd, "remote") == 0) {
            char *cidr = strtok(NULL, " \t\n");
            if (cidr) {
                if (parse_cidr(cidr, &remote_subnet, &remote_mask) == 0) {
                    struct in_addr addr;
                    addr.s_addr = remote_subnet;
                    printf("[CONFIG] Remote subnet: %s", inet_ntoa(addr));
                    addr.s_addr = remote_mask;
                    printf("/%d\n", __builtin_popcount(ntohl(remote_mask)));
                } else {
                    fprintf(stderr, "[ERROR] Invalid remote CIDR: %s\n", cidr);
                }
            }
        } else if (strcmp(cmd, "wan") == 0) {
            char *local_part = strtok(NULL, " \t\n");
            char *peer_part = strtok(NULL, " \t\n");

            if (local_part && peer_part && wan_count < MAX_WAN) {
                char ifname[32];
                int port;
                char peer_ip[32];
                int peer_port;

                if (sscanf(local_part, "%31[^:]:%d", ifname, &port) == 2 &&
                    sscanf(peer_part, "%31[^:]:%d", peer_ip, &peer_port) == 2) {

                    struct wan_cfg *w = &wans[wan_count];
                    w->ifindex = get_ifindex(ifname);
                    w->local_port = port;
                    w->peer_port = peer_port;
                    inet_pton(AF_INET, peer_ip, &w->peer_ip);
                    get_ip(ifname, &w->local_ip);
                    get_mac(ifname, w->local_mac);
                    get_gateway_mac(ifname, w->gw_mac);
                    w->active = 1;

                    struct in_addr addr;
                    addr.s_addr = w->local_ip;
                    printf("[CONFIG] WAN %d: %s port %d -> ", wan_count, ifname, port);
                    addr.s_addr = w->peer_ip;
                    printf("%s:%d\n", inet_ntoa(addr), peer_port);

                    wan_count++;
                }
            }
        }
    }
    fclose(fp);

    if (local_if[0] == 0 || wan_count == 0) {
        fprintf(stderr, "[ERROR] Missing local interface or WAN config\n");
        return 1;
    }

    if (remote_subnet == 0 && remote_mask == 0) {
        fprintf(stderr, "[ERROR] Missing remote subnet (e.g., remote 192.168.2.0/24)\n");
        return 1;
    }

    struct bpf_object *encap_obj = bpf_object__open_file("tc_encap.bpf.o", NULL);
    if (!encap_obj) return 1;
    if (bpf_object__load(encap_obj) < 0) return 1;

    struct bpf_object *decap_obj = bpf_object__open_file("tc_decap.bpf.o", NULL);
    if (!decap_obj) return 1;
    if (bpf_object__load(decap_obj) < 0) return 1;

    struct bpf_program *encap_prog = bpf_object__find_program_by_name(encap_obj, "tc_encap_prog");
    struct bpf_program *decap_prog = bpf_object__find_program_by_name(decap_obj, "tc_decap_prog");
    if (!encap_prog || !decap_prog) return 1;

    int encap_fd = bpf_program__fd(encap_prog);
    int decap_fd = bpf_program__fd(decap_prog);

    int wan_map_fd = bpf_object__find_map_fd_by_name(encap_obj, "wan_map");
    int cfg_map_fd = bpf_object__find_map_fd_by_name(encap_obj, "cfg_map");
    int lb_map_fd = bpf_object__find_map_fd_by_name(encap_obj, "lb_map");
    int crc32_map_fd = bpf_object__find_map_fd_by_name(encap_obj, "crc32_map");
    int decap_cfg_fd = bpf_object__find_map_fd_by_name(decap_obj, "cfg_map");
    int decap_wan_fd = bpf_object__find_map_fd_by_name(decap_obj, "wan_map");
    int decap_crc32_fd = bpf_object__find_map_fd_by_name(decap_obj, "crc32_map");

    /* Initialize CRC32 lookup tables */
    if (crc32_map_fd >= 0) {
        init_crc32_map(crc32_map_fd);
        printf("[CONFIG] Initialized CRC32 table for encap\n");
    }
    if (decap_crc32_fd >= 0) {
        init_crc32_map(decap_crc32_fd);
        printf("[CONFIG] Initialized CRC32 table for decap\n");
    }

    struct tunnel_cfg cfg = {
        .local_ifindex = get_ifindex(local_if),
        .wan_count = wan_count,
        .remote_subnet = remote_subnet,
        .remote_mask = remote_mask,
    };

    printf("[CONFIG] Local interface: %s (ifindex %d)\n", local_if, cfg.local_ifindex);
    printf("[CONFIG] WAN count: %d\n", wan_count);

    if (set_mtu(local_if, LOCAL_MTU) == 0) {
        printf("[CONFIG] Set %s MTU to %d\n", local_if, LOCAL_MTU);
    } else {
        fprintf(stderr, "[WARN] Failed to set MTU on %s (need root)\n", local_if);
    }

    __u32 key0 = 0;
    bpf_map_update_elem(cfg_map_fd, &key0, &cfg, BPF_ANY);
    bpf_map_update_elem(decap_cfg_fd, &key0, &cfg, BPF_ANY);

    struct lb_state lb = { .wan_idx = 0 };
    bpf_map_update_elem(lb_map_fd, &key0, &lb, BPF_ANY);

    for (int i = 0; i < wan_count; i++) {
        __u32 idx = i;
        bpf_map_update_elem(wan_map_fd, &idx, &wans[i], BPF_ANY);
        bpf_map_update_elem(decap_wan_fd, &idx, &wans[i], BPF_ANY);
    }

    int local_ifindex = get_ifindex(local_if);

    printf("[ATTACH] tc_encap on %s (egress)\n", local_if);
    if (attach_tc(local_ifindex, encap_fd, 0) < 0) {
        fprintf(stderr, "[ERROR] Failed to attach encap on %s\n", local_if);
    }

    for (int i = 0; i < wan_count; i++) {
        printf("[ATTACH] tc_decap on ifindex %d (ingress)\n", wans[i].ifindex);
        if (attach_tc(wans[i].ifindex, decap_fd, 1) < 0) {
            fprintf(stderr, "[ERROR] Failed to attach decap on ifindex %d\n", wans[i].ifindex);
        }
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    printf("\n[RUNNING] Tunnel active. Press Ctrl+C to stop.\n");

    while (running) sleep(1);

    detach_tc(local_ifindex, 0);
    for (int i = 0; i < wan_count; i++) {
        detach_tc(wans[i].ifindex, 1);
    }

    bpf_object__close(encap_obj);
    bpf_object__close(decap_obj);
    return 0;
}
