#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "tc_common.h"

static volatile int running = 1;
static void sig_handler(int sig) { running = 0; }

static int get_mac(const char *ifname, __u8 *mac) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIFHWADDR, &ifr);
    if (ret == 0) memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);
    close(fd);
    return ret;
}

static int get_ip(const char *ifname, __u32 *ip) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
    int ret = ioctl(fd, SIOCGIFADDR, &ifr);
    if (ret == 0) *ip = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    close(fd);
    return ret;
}

static int attach_tc(int ifindex, int fd, int ingress) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
        .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS);
    bpf_tc_hook_create(&hook);
    DECLARE_LIBBPF_OPTS(bpf_tc_opts, opts, .prog_fd = fd);
    return bpf_tc_attach(&hook, &opts);
}

static void detach_tc(int ifindex, int ingress) {
    DECLARE_LIBBPF_OPTS(bpf_tc_hook, hook, .ifindex = ifindex,
        .attach_point = ingress ? BPF_TC_INGRESS : BPF_TC_EGRESS);
    bpf_tc_hook_destroy(&hook);
}

int main(int argc, char **argv) {
    if (argc < 2) { printf("Usage: %s <config>\n", argv[0]); return 1; }

    FILE *fp = fopen(argv[1], "r");
    if (!fp) { perror("fopen"); return 1; }

    char local_if[32] = {0};
    struct wan_cfg wans[MAX_WAN] = {0};
    int wan_count = 0;
    __u32 remote_net = 0, remote_mask = 0;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        char *cmd = strtok(line, " \t\n");
        if (!cmd) continue;

        if (strcmp(cmd, "local") == 0) {
            char *s = strtok(NULL, " \t\n");
            if (s) strncpy(local_if, s, 31);
        } else if (strcmp(cmd, "remote") == 0) {
            char *s = strtok(NULL, " \t\n");
            if (s) {
                char ip[32]; int prefix;
                if (sscanf(s, "%31[^/]/%d", ip, &prefix) == 2) {
                    struct in_addr a;
                    inet_pton(AF_INET, ip, &a);
                    remote_mask = htonl(prefix ? ~((1U << (32 - prefix)) - 1) : 0);
                    remote_net = a.s_addr & remote_mask;
                    printf("Remote: %s/%d\n", ip, prefix);
                }
            }
        } else if (strcmp(cmd, "wan") == 0 && wan_count < MAX_WAN) {
            char *lp = strtok(NULL, " \t\n");
            char *pp = strtok(NULL, " \t\n");
            if (lp && pp) {
                char ifn[32], pip[32]; int port, pport;
                if (sscanf(lp, "%31[^:]:%d", ifn, &port) == 2 &&
                    sscanf(pp, "%31[^:]:%d", pip, &pport) == 2) {
                    struct wan_cfg *w = &wans[wan_count];
                    w->ifindex = if_nametoindex(ifn);
                    w->local_port = port;
                    w->peer_port = pport;
                    inet_pton(AF_INET, pip, &w->peer_ip);
                    get_ip(ifn, &w->local_ip);
                    get_mac(ifn, w->src_mac);
                    memset(w->dst_mac, 0xff, 6);
                    w->active = 1;
                    printf("WAN%d: %s:%d -> %s:%d\n", wan_count, ifn, port, pip, pport);
                    wan_count++;
                }
            }
        }
    }
    fclose(fp);

    if (!local_if[0] || !wan_count || !remote_net) {
        fprintf(stderr, "Missing config (need: local, remote, wan)\n");
        return 1;
    }

    struct bpf_object *enc = bpf_object__open_file("tc_encap.bpf.o", NULL);
    struct bpf_object *dec = bpf_object__open_file("tc_decap.bpf.o", NULL);
    if (!enc || !dec || bpf_object__load(enc) || bpf_object__load(dec)) {
        fprintf(stderr, "Failed to load BPF\n"); return 1;
    }

    int enc_fd = bpf_program__fd(bpf_object__find_program_by_name(enc, "tc_encap_prog"));
    int dec_fd = bpf_program__fd(bpf_object__find_program_by_name(dec, "tc_decap_prog"));

    int local_idx = if_nametoindex(local_if);
    struct tunnel_cfg cfg = { local_idx, wan_count, remote_net, remote_mask };
    struct global_state gs = {0};
    __u32 k = 0;

    bpf_map_update_elem(bpf_object__find_map_fd_by_name(enc, "cfg_map"), &k, &cfg, 0);
    bpf_map_update_elem(bpf_object__find_map_fd_by_name(enc, "global_map"), &k, &gs, 0);
    bpf_map_update_elem(bpf_object__find_map_fd_by_name(dec, "cfg_map"), &k, &cfg, 0);

    for (int i = 0; i < wan_count; i++) {
        __u32 idx = i;
        bpf_map_update_elem(bpf_object__find_map_fd_by_name(enc, "wan_map"), &idx, &wans[i], 0);
        bpf_map_update_elem(bpf_object__find_map_fd_by_name(dec, "wan_map"), &idx, &wans[i], 0);
    }

    printf("Local: %s (idx %d)\n", local_if, local_idx);
    attach_tc(local_idx, enc_fd, 0);
    for (int i = 0; i < wan_count; i++) attach_tc(wans[i].ifindex, dec_fd, 1);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    printf("\nRunning... Ctrl+C to stop\n");

    while (running) sleep(1);

    detach_tc(local_idx, 0);
    for (int i = 0; i < wan_count; i++) detach_tc(wans[i].ifindex, 1);
    bpf_object__close(enc);
    bpf_object__close(dec);
    printf("Stopped\n");
    return 0;
}
