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
    __u32 src_ip;    
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

SEC("sockops")
int bpf_basertt(struct bpf_sock_ops *skops)
{
    int op = (int)skops->op;
    __u32 dport = (__u32)bpf_ntohl(skops->remote_port);
    __u16 lport = (__u16)skops->local_port;
    __u32 nlip = (__u32)bpf_ntohl(skops->local_ip4);
    __u32 ndip = (__u32)bpf_ntohl(skops->remote_ip4);
    
    bpf_printk("dport :%u lport:%u\n", dport, lport);
    bpf_printk("nlip :%u ndip:%u\n", nlip, ndip);
    
    switch (op)
    {
    case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
    //case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
    //case BPF_SOCK_OPS_TCP_ACK_CB:
        bpf_printk("enter BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB\n");

        struct connection_tuple cc_id;
        cc_id.src_ip = nlip;     
        cc_id.dst_ip = ndip;    
        cc_id.src_port = lport;           
        cc_id.dst_port = dport;
        
        bpf_printk("cc_id: src_ip=%x dst_ip=%x", cc_id.src_ip, cc_id.dst_ip);
        bpf_printk("cc_id: src_port=%u dst_port=%u", cc_id.src_port, cc_id.dst_port);
        
        char *con_str = bpf_map_lookup_elem(&key_cong_map, &cc_id);
        bpf_printk("constr: %s\n", con_str);
        
        char cong[20];
        bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
        bpf_printk("before cc:%s\n", cong);

        if (con_str == NULL)
        {
            return 1;
        }
        
        bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 16);
        bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
        bpf_printk("after cc:%s\n", cong);
        break;
    }
    
    int rv = 0;
    skops->reply = rv;
    return 1;
}

char _license[] SEC("license") = "GPL";
