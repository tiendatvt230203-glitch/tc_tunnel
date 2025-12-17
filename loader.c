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

static int attach_tc(int ifindex, int fd, int ingress) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook,
        .ifindex = ifindex,
        .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS,
    );

    bpf_tc_hook_create(&hook);

    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts,
        .prog_fd = fd,
    );

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
    if (!fp) return 1;

    char local_if[32] = {0};
    struct wan_info wans[MAX_WAN];
    int wan_count = 0;

    memset(wans, 0, sizeof(wans));

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;

        char *cmd = strtok(line, " \t\n");
        if (!cmd) continue;

        if (strcmp(cmd, "local") == 0) {
            char *ifname = strtok(NULL, " \t\n");
            if (ifname) strncpy(local_if, ifname, sizeof(local_if) - 1);
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

                    struct wan_info *w = &wans[wan_count];
                    w->ifindex = get_ifindex(ifname);
                    w->local_port = port;
                    w->peer_port = peer_port;
                    inet_pton(AF_INET, peer_ip, &w->peer_ip);
                    get_ip(ifname, &w->local_ip);
                    get_mac(ifname, w->local_mac);
                    memset(w->peer_mac, 0xff, 6);
                    w->active = 1;
                    wan_count++;
                }
            }
        }
    }
    fclose(fp);

    if (local_if[0] == 0 || wan_count == 0) return 1;

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
    int flow_map_fd = bpf_object__find_map_fd_by_name(encap_obj, "flow_map");
    int cfg_map_fd = bpf_object__find_map_fd_by_name(encap_obj, "cfg_map");
    int lb_counter_fd = bpf_object__find_map_fd_by_name(encap_obj, "lb_counter");

    int decap_cfg_fd = bpf_object__find_map_fd_by_name(decap_obj, "cfg_map");
    int decap_wan_fd = bpf_object__find_map_fd_by_name(decap_obj, "wan_map");

    struct tunnel_cfg cfg = {
        .local_ifindex = get_ifindex(local_if),
        .wan_count = wan_count,
    };

    __u32 key0 = 0;
    bpf_map_update_elem(cfg_map_fd, &key0, &cfg, BPF_ANY);
    bpf_map_update_elem(decap_cfg_fd, &key0, &cfg, BPF_ANY);

    __u32 counter = 0;
    bpf_map_update_elem(lb_counter_fd, &key0, &counter, BPF_ANY);

    for (int i = 0; i < wan_count; i++) {
        __u32 idx = i;
        bpf_map_update_elem(wan_map_fd, &idx, &wans[i], BPF_ANY);
        bpf_map_update_elem(decap_wan_fd, &idx, &wans[i], BPF_ANY);
    }

    int local_ifindex = get_ifindex(local_if);
    attach_tc(local_ifindex, encap_fd, 0);

    for (int i = 0; i < wan_count; i++) {
        attach_tc(wans[i].ifindex, decap_fd, 1);
    }

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    while (running) {
        sleep(1);
    }

    detach_tc(local_ifindex, 0);
    for (int i = 0; i < wan_count; i++) {
        detach_tc(wans[i].ifindex, 1);
    }

    bpf_object__close(encap_obj);
    bpf_object__close(decap_obj);

    return 0;
}
