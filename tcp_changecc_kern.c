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

// Map pour tracker les connexions déjà configurées
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u8);
} configured_connections SEC(".maps");

SEC("sockops")
int bpf_basertt(struct bpf_sock_ops *skops)
{
    int op = (int)skops->op;
    __u32 remote_ip_nbo = skops->remote_ip4;
    __u8 *already_configured;
    struct connection_tuple cc_id;
    char *con_str;
    int ret;
    __u8 flag;
    //bpf_printk("sockops op=%d\n", op);

    //bpf_printk("test read trace pipe");
    switch (op)
    {
    //case BPF_SOCK_OPS_TCP_ACK_CB:
    //case BPF_SOCK_OPS_TCL_CLOSE_CB:

    //case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: {
        int flags=0;

        flags = BPF_SOCK_OPS_RTT_CB_FLAG;

        int ret = bpf_sock_ops_cb_flags_set(skops, flags);
        bpf_printk("cb_flags_set: flags=0x%x ret=%d\n", flags, ret);
        break;
    }
    case BPF_SOCK_OPS_RTT_CB:
        // Vérifier si cette connexion a déjà été configurée
        already_configured = bpf_map_lookup_elem(&configured_connections, &remote_ip_nbo);
        
        if (already_configured != NULL) {
            // Déjà configurée, ne rien faire
            //bpf_printk("CCA already set");
            return 1;
        }

        bpf_printk("ACK for IP: %u\n", remote_ip_nbo);

        cc_id.dst_ip = remote_ip_nbo;
        
        con_str = bpf_map_lookup_elem(&key_cong_map, &cc_id);

        if (con_str != NULL) {
            bpf_printk("Setting CCA to %s for IP: %u (FIRST TIME)\n", con_str, remote_ip_nbo);
            char cong[16];
            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
            bpf_printk("before cc:%s\n", cong);

            ret = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 16);

            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
            bpf_printk("after cc:%s\n", cong);
            
            if (ret == 0) {
                // Marquer cette connexion comme configurée
                flag = 1;
                bpf_map_update_elem(&configured_connections, &remote_ip_nbo, &flag, BPF_ANY);
                bpf_printk("✅ CCA %s applied successfully\n", con_str);
            } else {
                bpf_printk("❌ Failed to apply CCA %s (ret=%d)\n", con_str, ret);
            }
        }
        else {
            bpf_printk("Fail to set CCA to %s for IP: %u (FIRST TIME)\n", con_str, remote_ip_nbo);
        }
        break;
    }

    return 1;
}

char _license[] SEC("license") = "GPL";