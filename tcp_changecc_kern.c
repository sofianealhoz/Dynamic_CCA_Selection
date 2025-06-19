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

struct connection_event {
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct connection_tuple);
    __type(value, char[16]);  
} key_cong_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} connection_events SEC(".maps");

SEC("sockops")
int bpf_basertt(struct bpf_sock_ops *skops)
{
    int op = (int)skops->op;
    __u32 dport = (__u32)bpf_ntohl(skops->remote_port);
    __u16 lport = (__u16)skops->local_port;
    __u32 ndip = (__u32)bpf_ntohl(skops->remote_ip4);
    
    bpf_printk("ndip:%u\n", ndip);
    
    switch (op)
    {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    //case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    //case BPF_SOCK_OPS_TCP_ACK_CB:
        bpf_printk("enter BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB\n");

        struct connection_tuple cc_id;
        cc_id.dst_ip = ndip;
        
        bpf_printk("cc_id: dst_ip=%u", cc_id.dst_ip);
        
        char *con_str = bpf_map_lookup_elem(&key_cong_map, &cc_id);
        bpf_printk("constr: %s\n", con_str);
        


        if (con_str != NULL) {
            char cong[20];
            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
            bpf_printk("before cc:%s\n", cong);
            bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 16);
            bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
            bpf_printk("after cc:%s\n", cong);
            break;

        } else {
            bpf_printk("No rule, sending event to collect", ndip);

            // Étape 5: On sonne la cloche
            struct connection_event event = {};
            event.dst_ip = ndip;
            event.src_port = skops->local_port;
            event.dst_port = bpf_ntohl(skops->remote_port);

            bpf_perf_event_output(skops, &connection_events, BPF_F_CURRENT_CPU, &event, sizeof(event));
        }

    }
    
    int rv = 0;
    skops->reply = rv;
    return 1;
}

char _license[] SEC("license") = "GPL";
