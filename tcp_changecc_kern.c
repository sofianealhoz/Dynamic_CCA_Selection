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

// Structure pour une entrée de log
struct log_entry {
    __u32 timestamp;        // timestamp en millisecondes
    __u32 remote_ip;        // IP de la connexion
    __u32 op;              // Opération sockops
    char message[48];       // Message de log
    int ret_code;          // Code de retour (pour les erreurs)
};

// Map circulaire pour stocker les logs (consultable avec bpftool)
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 100);  // 100 entrées de log max
    __type(key, __u32);
    __type(value, struct log_entry);
} bpf_logs SEC(".maps");

// Index circulaire pour la map des logs
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} log_index SEC(".maps");

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

// Helper pour ajouter un log dans la map
static void add_log(const char *msg, __u32 remote_ip, __u32 op, int ret_code) {
    __u32 zero = 0;
    __u32 *current_index_ptr = bpf_map_lookup_elem(&log_index, &zero);
    if (!current_index_ptr) {
        // Initialiser l'index à 0 si pas trouvé
        __u32 init_index = 0;
        bpf_map_update_elem(&log_index, &zero, &init_index, BPF_ANY);
        current_index_ptr = &init_index;
    }
    
    __u32 current_index = *current_index_ptr;
    __u32 slot = current_index % 100;  // Index circulaire (0-99)
    
    struct log_entry entry = {
        .timestamp = bpf_ktime_get_ns() / 1000000,  // ms
        .remote_ip = remote_ip,
        .op = op,
        .ret_code = ret_code
    };
    
    // Copier le message (sécurisé)
    #pragma unroll
    for (int i = 0; i < 47; i++) {
        if (msg[i] == '\0') break;
        entry.message[i] = msg[i];
    }
    entry.message[47] = '\0';  // Assurer null termination
    
    // Sauvegarder l'entrée
    bpf_map_update_elem(&bpf_logs, &slot, &entry, BPF_ANY);
    
    // Incrémenter l'index
    __u32 new_index = current_index + 1;
    bpf_map_update_elem(&log_index, &zero, &new_index, BPF_ANY);
}

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
    add_log("sockops_event", remote_ip_nbo, op, 0);

    switch (op)
    {
    //case BPF_SOCK_OPS_TCP_ACK_CB:
    //case BPF_SOCK_OPS_TCL_CLOSE_CB:

    //case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        add_log("inside_passive_established", remote_ip_nbo, op, 0);
        // Vérifier si cette connexion a déjà été configurée
        already_configured = bpf_map_lookup_elem(&configured_connections, &remote_ip_nbo);
        
        if (already_configured != NULL) {
            // Déjà configurée, ne rien faire
            return 1;
        }

        add_log("first_connection_detected", remote_ip_nbo, op, 0);

        cc_id.dst_ip = remote_ip_nbo;
        
        con_str = bpf_map_lookup_elem(&key_cong_map, &cc_id);

        if (con_str != NULL) {
            add_log("cca_rule_found", remote_ip_nbo, op, 0);
            char cong[16];
            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
            add_log("before_cca_change", remote_ip_nbo, op, 0);

            ret = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 16);

            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
            add_log("after_cca_change", remote_ip_nbo, op, ret);
            
            if (ret == 0) {
                // Marquer cette connexion comme configurée
                flag = 1;
                bpf_map_update_elem(&configured_connections, &remote_ip_nbo, &flag, BPF_ANY);
                add_log("cca_applied_successfully", remote_ip_nbo, op, 0);
            } else {
                add_log("cca_apply_failed", remote_ip_nbo, op, ret);
            }
        }
        break;
    }

    return 1;
}

char _license[] SEC("license") = "GPL";