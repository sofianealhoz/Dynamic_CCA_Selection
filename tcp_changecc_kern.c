
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
    long src_ip;    
    long dst_ip;    
    long src_port;    
    long dst_port;   
};


struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 20);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct connection_tuple);
    __type(value, char[10]);
} key_cong_map SEC(".maps");

const char RENO[] = "reno";
const char CUBIC[] = "cubic";
const char ILLINOIS[] = "illinois";
const char VEGAS[] = "vegas";
const char BBR[] = "bbr";
const char WESTWOOD[] = "westwood";
const char HIGHSPEED[] = "highspeed";
const char HYBLA[] = "hybla";
const char SCALABLE[] = "scalable";
const char YEAH[] = "yeah";
const char DCTCP[] = "dctcp";

static inline void init_map()
{

    long common_ip = 0x7F000001;  
    long common_src_port = 5001;   
    

    struct connection_tuple tuple0;
    tuple0.src_ip = common_ip;
    tuple0.dst_ip = common_ip;
    tuple0.src_port = common_src_port;
    tuple0.dst_port = 0;      
    

    bpf_map_update_elem(&key_cong_map, &tuple0, RENO, BPF_ANY);


    struct connection_tuple tuple1;

    tuple1.src_ip = common_ip;
    tuple1.dst_ip = common_ip;
    tuple1.src_port = common_src_port;
    tuple1.dst_port = 5004;   
    

    bpf_map_update_elem(&key_cong_map, &tuple1, CUBIC, BPF_ANY);


    struct connection_tuple tuple2;

    tuple2.src_ip = common_ip;
    tuple2.dst_ip = common_ip;
    tuple2.src_port = common_src_port;
    tuple2.dst_port = 5005;   
    

    bpf_map_update_elem(&key_cong_map, &tuple2, ILLINOIS, BPF_ANY);


    struct connection_tuple tuple3;

    tuple3.src_ip = common_ip;
    tuple3.dst_ip = common_ip;
    tuple3.src_port = common_src_port;
    tuple3.dst_port = 5006;   
    

    bpf_map_update_elem(&key_cong_map, &tuple3, VEGAS, BPF_ANY);


    struct connection_tuple tuple4;

    tuple4.src_ip = common_ip;
    tuple4.dst_ip = common_ip;
    tuple4.src_port = common_src_port;
    tuple4.dst_port = 5007;   
    

    bpf_map_update_elem(&key_cong_map, &tuple4, BBR, BPF_ANY);


    struct connection_tuple tuple5;

    tuple5.src_ip = common_ip;
    tuple5.dst_ip = common_ip;
    tuple5.src_port = common_src_port;
    tuple5.dst_port = 5008;   
    

    bpf_map_update_elem(&key_cong_map, &tuple5, WESTWOOD, BPF_ANY);


    struct connection_tuple tuple6;

    tuple6.src_ip = common_ip;
    tuple6.dst_ip = common_ip;
    tuple6.src_port = common_src_port;
    tuple6.dst_port = 5009;   
    

    bpf_map_update_elem(&key_cong_map, &tuple6, HIGHSPEED, BPF_ANY);


    struct connection_tuple tuple7;

    tuple7.src_ip = common_ip;
    tuple7.dst_ip = common_ip;
    tuple7.src_port = common_src_port;
    tuple7.dst_port = 5010;   
    

    bpf_map_update_elem(&key_cong_map, &tuple7, HYBLA, BPF_ANY);


    struct connection_tuple tuple8;

    tuple8.src_ip = common_ip;
    tuple8.dst_ip = common_ip;
    tuple8.src_port = common_src_port;
    tuple8.dst_port = 5011;   
    

    bpf_map_update_elem(&key_cong_map, &tuple8, SCALABLE, BPF_ANY);


    struct connection_tuple tuple9;

    tuple9.src_ip = common_ip;
    tuple9.dst_ip = common_ip;
    tuple9.src_port = common_src_port;
    tuple9.dst_port = 5012;   
    

    bpf_map_update_elem(&key_cong_map, &tuple9, YEAH, BPF_ANY);


    struct connection_tuple tuple10;

    tuple10.src_ip = common_ip;
    tuple10.dst_ip = common_ip;
    tuple10.src_port = common_src_port;
    tuple10.dst_port = 5013;   
    

    bpf_map_update_elem(&key_cong_map, &tuple10, DCTCP, BPF_ANY);
}
SEC("sockops")
int bpf_basertt(struct bpf_sock_ops *skops)
{
	init_map();
	int op = (int)skops->op;
	long dport = (long)bpf_ntohl(skops->remote_port);
	long lport = (long)skops->local_port;
	long nlip = (long)bpf_ntohl(skops->local_ip4);
	long ndip = (long)bpf_ntohl(skops->remote_ip4);
	bpf_printk("dport :%ld lport:%ld\n", dport, lport);
	bpf_printk("nlip :%ld ndip:%ld\n", nlip, ndip);
	switch (op)
	{
	case BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB:
	//case BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB:
	//case BPF_SOCK_OPS_TCP_ACK_CB:
		bpf_printk("enter BPF_SOCK_OPS_TCP_ACK_CB\n");

		//long cc_id = dport;
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
		bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION,
					   cong, sizeof(cong));
		bpf_printk("before cc:%s\n", cong);

		if (con_str == NULL)
		{
			return 1;
		}
		
		bpf_setsockopt(skops, SOL_TCP, TCP_CONGESTION, con_str, 10);
		bpf_getsockopt(skops, SOL_TCP, TCP_CONGESTION, cong, sizeof(cong));
		//int r = bpf_map_delete_elem(&cong_map, &cc_id);
		//if (r == 0)
			//bpf_printk("Element deleted from the map\n");
		//else
		//	bpf_printk("Failed to delete element from the map: %d\n", r);
		//break;

		bpf_printk("after cc:%s\n", cong);

		break;
	
	}
	char nv[] = "nv";
	int rv = 0, n;
	skops->reply = rv;
	return 1;
}
char _license[] SEC("license") = "GPL";
