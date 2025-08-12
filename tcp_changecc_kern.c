#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/socket.h>
#include <linux/string.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define DEBUG 1

struct connection_tuple {
    __u32 dst_ip;
};

// Structure pour les événements (SANS chaînes constantes)
struct log_event {
    __u64 timestamp;
    __u32 remote_ip;
    __u32 op;
    __u32 event_type;  // ← Numéro au lieu de chaîne
    __u32 ret_code;
    char cca_name[16]; // ← Pour le nom du CCA seulement
};

// Codes d'événements (au lieu de chaînes)
#define EVENT_SOCKOPS           1
#define EVENT_PASSIVE_EST       2
#define EVENT_ALREADY_CONFIG    3
#define EVENT_FIRST_CONNECTION  4
#define EVENT_RULE_FOUND        5
#define EVENT_RULE_NOT_FOUND    6
#define EVENT_BEFORE_CHANGE     7
#define EVENT_AFTER_CHANGE      8
#define EVENT_SUCCESS           9
#define EVENT_FAILED           10

// Ring buffer
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} log_events SEC(".maps");

// Helper pour envoyer un log
static inline void send_log(__u32 event_type, __u32 remote_ip, __u32 op, __u32 ret_code, const char *cca) {
    struct log_event *event;
    
    event = bpf_ringbuf_reserve(&log_events, sizeof(*event), 0);
    if (!event)
        return;
    
    event->timestamp = bpf_ktime_get_ns();
    event->remote_ip = remote_ip;
    event->op = op;
    event->event_type = event_type;
    event->ret_code = ret_code;
    
    // Copier le nom CCA si fourni
    if (cca) {
        int i;
        for (i = 0; i < 15 && cca[i] != '\0'; i++) {
            event->cca_name[i] = cca[i];
        }
        event->cca_name[i] = '\0';
    } else {
        event->cca_name[0] = '\0';
    }
    
    bpf_ringbuf_submit(event, 0);
}

// Maps existantes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct connection_tuple);
    __type(value, char[16]);
} key_cong_map SEC(".maps");

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
    
    // Log événement sockops
    send_log(EVENT_SOCKOPS, remote_ip_nbo, op, 0, NULL);

    switch (op)
    {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
        send_log(EVENT_PASSIVE_EST, remote_ip_nbo, op, 0, NULL);
        
        already_configured = bpf_map_lookup_elem(&configured_connections, &remote_ip_nbo);
        
        if (already_configured != NULL) {
            send_log(EVENT_ALREADY_CONFIG, remote_ip_nbo, op, 0, NULL);
            return 1;
        }

        send_log(EVENT_FIRST_CONNECTION, remote_ip_nbo, op, 0, NULL);

        cc_id.dst_ip = remote_ip_nbo;
        con_str = bpf_map_lookup_elem(&key_cong_map, &cc_id);

        if (con_str != NULL) {
            send_log(EVENT_RULE_FOUND, remote_ip_nbo, op, 0, con_str);
            
            char cong_before[16] = {0};
            char cong_after[16] = {0};
            
            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong_before, sizeof(cong_before));
            send_log(EVENT_BEFORE_CHANGE, remote_ip_nbo, op, 0, cong_before);

            ret = bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 16);

            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong_after, sizeof(cong_after));
            send_log(EVENT_AFTER_CHANGE, remote_ip_nbo, op, ret, cong_after);
            
            if (ret == 0) {
                flag = 1;
                bpf_map_update_elem(&configured_connections, &remote_ip_nbo, &flag, BPF_ANY);
                send_log(EVENT_SUCCESS, remote_ip_nbo, op, 0, cong_after);
            } else {
                send_log(EVENT_FAILED, remote_ip_nbo, op, ret, con_str);
            }
        } else {
            send_log(EVENT_RULE_NOT_FOUND, remote_ip_nbo, op, 0, NULL);
        }
        break;
    }

    return 1;
}

char _license[] SEC("license") = "GPL";