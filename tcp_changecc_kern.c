
#include <uapi/linux/bpf.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <linux/socket.h>
#include <linux/string.h>

#include "/home/sofiane007/linux-6.11/samples/bpf/libbpf/include/bpf/bpf_helpers.h"
#include "/home/sofiane007/linux-6.11/samples/bpf/libbpf/include/bpf/bpf_endian.h"




#define DEBUG 1

struct connection_tuple {
    long src_ip;    // Adresse IP source (format réseau)
    long dst_ip;    // Adresse IP destination (format réseau)
    long src_port;   // Port source 
    long dst_port;   // Port destination
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(long));
	__uint(value_size, 10);
	__uint(max_entries, 100);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cong_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, sizeof(long));
	__uint(value_size, 10);
	__uint(max_entries, 100);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} ip_cong_map SEC(".maps");

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
    // Adresse IP commune pour toutes les entrées: 172.20.10.3
    long common_ip = 0x7F000001;  // 172.20.10.3
    long common_src_port = 5001;   // Port source 5001
    
    // Tuple 0 - port destination 0 - pour Reno
    struct connection_tuple tuple0;
    tuple0.src_ip = common_ip;
    tuple0.dst_ip = common_ip;
    tuple0.src_port = common_src_port;
    tuple0.dst_port = 0;      // Port destination 0
    

    bpf_map_update_elem(&key_cong_map, &tuple0, RENO, BPF_ANY);

    // Tuple 1 - port destination 5004 - pour Cubic
    struct connection_tuple tuple1;

    tuple1.src_ip = common_ip;
    tuple1.dst_ip = common_ip;
    tuple1.src_port = common_src_port;
    tuple1.dst_port = 5004;   // Port destination 5004
    

    bpf_map_update_elem(&key_cong_map, &tuple1, CUBIC, BPF_ANY);

    // Tuple 2 - port destination 5005 - pour Illinois
    struct connection_tuple tuple2;

    tuple2.src_ip = common_ip;
    tuple2.dst_ip = common_ip;
    tuple2.src_port = common_src_port;
    tuple2.dst_port = 5005;   // Port destination 5005
    

    bpf_map_update_elem(&key_cong_map, &tuple2, ILLINOIS, BPF_ANY);

    // Tuple 3 - port destination 5006 - pour Vegas
    struct connection_tuple tuple3;

    tuple3.src_ip = common_ip;
    tuple3.dst_ip = common_ip;
    tuple3.src_port = common_src_port;
    tuple3.dst_port = 5006;   // Port destination 5006
    

    bpf_map_update_elem(&key_cong_map, &tuple3, VEGAS, BPF_ANY);

    // Tuple 4 - port destination 5007 - pour BBR
    struct connection_tuple tuple4;

    tuple4.src_ip = common_ip;
    tuple4.dst_ip = common_ip;
    tuple4.src_port = common_src_port;
    tuple4.dst_port = 5007;   // Port destination 5007
    

    bpf_map_update_elem(&key_cong_map, &tuple4, BBR, BPF_ANY);

    // Tuple 5 - port destination 5008 - pour Westwood
    struct connection_tuple tuple5;

    tuple5.src_ip = common_ip;
    tuple5.dst_ip = common_ip;
    tuple5.src_port = common_src_port;
    tuple5.dst_port = 5008;   // Port destination 5008
    

    bpf_map_update_elem(&key_cong_map, &tuple5, WESTWOOD, BPF_ANY);

    // Tuple 6 - port destination 5009 - pour Highspeed
    struct connection_tuple tuple6;

    tuple6.src_ip = common_ip;
    tuple6.dst_ip = common_ip;
    tuple6.src_port = common_src_port;
    tuple6.dst_port = 5009;   // Port destination 5009
    

    bpf_map_update_elem(&key_cong_map, &tuple6, HIGHSPEED, BPF_ANY);

    // Tuple 7 - port destination 5010 - pour Hybla
    struct connection_tuple tuple7;

    tuple7.src_ip = common_ip;
    tuple7.dst_ip = common_ip;
    tuple7.src_port = common_src_port;
    tuple7.dst_port = 5010;   // Port destination 5010
    

    bpf_map_update_elem(&key_cong_map, &tuple7, HYBLA, BPF_ANY);

    // Tuple 8 - port destination 5011 - pour Scalable
    struct connection_tuple tuple8;

    tuple8.src_ip = common_ip;
    tuple8.dst_ip = common_ip;
    tuple8.src_port = common_src_port;
    tuple8.dst_port = 5011;   // Port destination 5011
    

    bpf_map_update_elem(&key_cong_map, &tuple8, SCALABLE, BPF_ANY);

    // Tuple 9 - port destination 5012 - pour Yeah
    struct connection_tuple tuple9;

    tuple9.src_ip = common_ip;
    tuple9.dst_ip = common_ip;
    tuple9.src_port = common_src_port;
    tuple9.dst_port = 5012;   // Port destination 5012
    

    bpf_map_update_elem(&key_cong_map, &tuple9, YEAH, BPF_ANY);

    // Tuple 10 - port destination 5013 - pour DCTCP
    struct connection_tuple tuple10;

    tuple10.src_ip = common_ip;
    tuple10.dst_ip = common_ip;
    tuple10.src_port = common_src_port;
    tuple10.dst_port = 5013;   // Port destination 5013
    

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
	    
	        // Notez la conversion des types et formats:
	        // Les adresses IP sont stockées en format réseau (big-endian)
	        cc_id.src_ip = nlip;     // Déjà en format réseau
	        cc_id.dst_ip = ndip;    // Déjà en format réseau
	    
	        // Pour les ports, attention à l'endianness
	        cc_id.src_port = lport;           // Besoin de vérifier le format
	        cc_id.dst_port = dport;
	        bpf_printk("cc_id: src_ip=%x dst_ip=%x", cc_id.src_ip, cc_id.dst_ip);
		// Puis dans un appel séparé:
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
