#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/socket.h>
#include <linux/string.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// --- SUPPRESSION ---
// On enlève l'include qui pose problème
// #include <bcc/proto.h>

#define DEBUG 1

struct connection_tuple {
    __u32 dst_ip; // Doit être en network byte order
};



struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct connection_tuple);
    __type(value, char[16]);
} key_cong_map SEC(".maps");




SEC("sockops")
int bpf_basertt(struct bpf_sock_ops *skops)
{
    int op = (int)skops->op;

    // On utilise directement l'IP en network byte order
    __u32 remote_ip_nbo = skops->remote_ip4;

    switch (op)
    {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        bpf_printk("enter BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB for IP: %u\n", remote_ip_nbo);

        struct connection_tuple cc_id;
        cc_id.dst_ip = remote_ip_nbo; // Utiliser l'IP en network byte order

        char *con_str = bpf_map_lookup_elem(&key_cong_map, &cc_id);

        if (con_str != NULL) {
            bpf_printk("Rule found for %u, setting CCA to %s\n", remote_ip_nbo, con_str);
            bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 16);
        } else {
            bpf_printk("No rule for %u\n", remote_ip_nbo);


        }
        break;
    }

    return 1;
}

char _license[] SEC("license") = "GPL";