#!/usr/libexec/platform-python

from bcc import BPF
import time
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import ctypes as ct
import csv
import os
import ipaddress
import sys



# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <net/tcp.h>


// separate data structs for ipv4 and ipv6
struct ipv4_data_t {
    u32 pid;
    u64 ip;
    u32 saddr;
    u32 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 tcp_state;
    u64 srtt;
    u64 rtt;
    u64 mdev;
    u64 mdev_max;
    u64 rttvar;
    u64 min_rtt;
    u64 inflight;
    u64 lost;
    u64 recv_rtt;
    u64 tsoffset;
    u64 retrans_out;
    u64 total_lost;
    u64 sack_out;
    u64 total_retrans;
    u64 tstamp;
    u64 rcv_buf;
    u64 snd_buf;
    u64 snd_cwnd;
    u64 sk_max_pacing_rate;
    u64 sk_pacing_rate;
    u64 delivered;

};
BPF_PERF_OUTPUT(ipv4_events);

struct ipv6_data_t {
    u32 pid;
    u64 ip;
    unsigned __int128 saddr;
    unsigned __int128 daddr;
    u16 lport;
    u16 dport;
    u64 state;
    u64 tcp_state;
    u64 srtt;
    u64 rtt;
    u64 mdev;
    u64 mdev_max;
    u64 rttvar;
    u64 min_rtt;
    u64 inflight;
    u64 lost;
    u64 recv_rtt;
    u64 tsoffset;
    u64 retrans_out;
    u64 total_lost;
    u64 sack_out;
    u64 total_retrans;
    u64 tstamp;
    u64 rcv_buf;
    u64 snd_buf;
    u64 snd_cwnd;
    u64 sk_max_pacing_rate;
    u64 sk_pacing_rate;
    u64 delivered;
};
BPF_PERF_OUTPUT(ipv6_events);


static int trace_event(struct pt_regs *ctx, struct sock *skp)
{
    if (skp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (skp->__sk_common.skc_num != 5201)
    {
        return 0;
    }

    // or:
    //u32 target_saddr = 0;  
    //u32 target_daddr = 0;  
    //u16 target_lport = 49152;  
    //u16 target_dport = 443;

    // verify if the 4-tuple that identifies a connexion matches
    //if (skp->__sk_common.skc_rcv_saddr != target_saddr ||
        //skp->__sk_common.skc_daddr != target_daddr ||
        //skp->__sk_common.skc_num != target_lport ||
        //ntohs(skp->__sk_common.skc_dport) != target_dport) {
        //return 0;
    //}

    // pull in details
    u16 family = skp->__sk_common.skc_family;
    u16 lport = skp->__sk_common.skc_num;
    u16 dport = skp->__sk_common.skc_dport;
    char state = skp->__sk_common.skc_state;
    struct tcp_sock *tp = (struct tcp_sock *)skp;
    struct tcp_rack rack = tp->rack;
    struct minmax min = tp->rtt_min;
    //struct inet_connection_sock *icsk = inet_csk(skp);
    struct inet_connection_sock *icsk = (struct inet_connection_sock *)skp;
    u64 tcp_state=0;

    if (family == AF_INET) {
        IPV4_INIT
        IPV4_CORE
    } else if (family == AF_INET6) {
        IPV6_INIT
        IPV6_CORE
    }
    return 0;
}

int trace_ack(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk);
    return 0;
}
"""

struct_init = {'ipv4':
                   {'trace':
                        """
                        struct ipv4_data_t data4 = {};
                        data4.delivered = tp->delivered;
                        data4.pid = pid;
                        data4.ip = 4;
                        data4.sk_pacing_rate = skp->sk_pacing_rate;
                        data4.sk_max_pacing_rate = skp-> sk_max_pacing_rate;
                        data4.srtt = tp->srtt_us;
                        data4.rtt = rack.rtt_us;
                        data4.mdev = tp->mdev_us;
                        data4.mdev_max = tp->mdev_max_us;
                        data4.rttvar = tp->rttvar_us;
                        data4.min_rtt = min.s[0].v;
                        data4.inflight = tp->packets_out;
                        data4.lost = tp->lost_out;
                        data4.recv_rtt = tp->rcv_rtt_est.rtt_us;
                        data4.saddr = skp->__sk_common.skc_rcv_saddr;
                        data4.daddr = skp->__sk_common.skc_daddr;
                        data4.tcp_state = tcp_state;
                        // lport is host order
                        data4.lport = lport;
                        data4.dport = ntohs(dport);
                        data4.tsoffset = tp->tsoffset;
                        data4.retrans_out = tp->retrans_out;
                        data4.total_lost = tp->lost;
                        data4.sack_out = tp->sacked_out;
                        data4.total_retrans = tp->total_retrans;
                        data4.tstamp = tp->lsndtime;
                        data4.snd_cwnd = tp->snd_cwnd;
                        data4.rcv_buf = skp->sk_rcvbuf;
                        data4.snd_buf = skp->sk_sndbuf;
                        data4.state = state; """
                    },
               'ipv6':
                   {'trace': """
                    struct ipv6_data_t data6 = {};
                    data6.delivered = tp->delivered;
                    data6.pid = pid;
                    data6.ip = 6;
                    data6.srtt = tp->srtt_us;
                    data6.sk_pacing_rate = skp->sk_pacing_rate;
                    data6.sk_max_pacing_rate = skp-> sk_max_pacing_rate;
                    data6.rtt = rack.rtt_us;
                    data6.mdev = tp->mdev_us;
                    data6.mdev_max = tp->mdev_max_us;
                    data6.rttvar = tp->rttvar_us;
                    data6.tcp_state = tcp_state;
                    data6.min_rtt = min.s[0].v;
                    data6.inflight = tp->packets_out;
                    data6.lost = tp->lost_out;
                    data6.recv_rtt = tp->rcv_rtt_est.rtt_us;
                    data6.saddr = skp->__sk_common.skc_rcv_saddr;
                    data6.daddr = skp->__sk_common.skc_daddr;
                    data6.tsoffset = tp->tsoffset;
                    data6.retrans_out = tp->retrans_out;
                    data6.total_lost = tp->lost;
                    data6.sack_out = tp->sacked_out;
                    data6.total_retrans = tp->total_retrans;
                    bpf_probe_read(&data6.saddr, sizeof(data6.saddr),
                        skp->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
                    bpf_probe_read(&data6.daddr, sizeof(data6.daddr),
                        skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
                    // lport is host order
                    data6.lport = lport;
                    data6.dport = ntohs(dport);
                    data6.tstamp = tp->lsndtime;
                    data6.snd_cwnd = tp->snd_cwnd;
                    data6.rcv_buf = skp->sk_rcvbuf;
                    data6.snd_buf = skp->sk_sndbuf;
                    data6.state = state;"""
                    }
               }



# replacement before the bpf code is compiled and charged in the kernel
bpf_text = bpf_text.replace("IPV4_INIT", struct_init['ipv4']['trace']) #prepare data
bpf_text = bpf_text.replace("IPV6_INIT", struct_init['ipv6']['trace'])
bpf_text = bpf_text.replace("IPV4_CORE", "ipv4_events.perf_submit(ctx, &data4, sizeof(data4));") #send 
bpf_text = bpf_text.replace("IPV6_CORE", "ipv6_events.perf_submit(ctx, &data6, sizeof(data6));")


# event data
class Data_ipv4(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ip", ct.c_ulonglong),
        ("saddr", ct.c_uint),
        ("daddr", ct.c_uint),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ulonglong),
        ("tcp_state", ct.c_ulonglong),
        ("srtt", ct.c_ulonglong),
        ("rtt", ct.c_ulonglong),
        ("mdev", ct.c_ulonglong),
        ("mdev_max", ct.c_ulonglong),
        ("rttvar", ct.c_ulonglong),
        ("min_rtt", ct.c_ulonglong),
        ("inflight", ct.c_ulonglong),
        ("lost", ct.c_ulonglong),
        ("recv_rtt", ct.c_ulonglong),
        ("tsoffset", ct.c_ulonglong),
        ("retrans_out", ct.c_ulonglong),
        ("total_lost", ct.c_ulonglong),
        ("sack_out", ct.c_ulonglong),
        ("total_retrans", ct.c_ulonglong),
        ("tstamp", ct.c_ulonglong),
        ("rcv_buf", ct.c_ulonglong),
        ("snd_buf", ct.c_ulonglong),
        ("snd_cwnd", ct.c_ulonglong),
        ("sk_max_pacing_rate", ct.c_ulonglong),
        ("sk_pacing_rate", ct.c_ulonglong),
        ("delivered", ct.c_ulonglong)
        
    ]


class Data_ipv6(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint),
        ("ip", ct.c_ulonglong),
        ("saddr", (ct.c_ulonglong * 2)),
        ("daddr", (ct.c_ulonglong * 2)),
        ("lport", ct.c_ushort),
        ("dport", ct.c_ushort),
        ("state", ct.c_ulonglong),
        ("tcp_state", ct.c_ulonglong),
        ("rtt", ct.c_ulonglong),
        ("srtt", ct.c_ulonglong),
        ("mdev", ct.c_ulonglong),
        ("mdev_max", ct.c_ulonglong),
        ("rttvar", ct.c_ulonglong),
        ("min_rtt", ct.c_ulonglong),
        ("inflight", ct.c_ulonglong),
        ("lost", ct.c_ulonglong),
        ("recv_rtt", ct.c_ulonglong),
        ("tsoffset", ct.c_ulonglong),
        ("retrans_out", ct.c_ulonglong),
        ("total_lost", ct.c_ulonglong),
        ("sack_out", ct.c_ulonglong),
        ("total_retrans", ct.c_ulonglong),
        ("tstamp", ct.c_ulonglong),
        ("rcv_buf", ct.c_ulonglong),
        ("snd_buf", ct.c_ulonglong),
        ("snd_cwnd", ct.c_ulonglong),
        ("sk_max_pacing_rate", ct.c_ulonglong),
        ("sk_pacing_rate", ct.c_ulonglong),
        ("delivered", ct.c_ulonglong)

    ]



# from include/net/tcp_states.h:
tcpstate = {}
tcpstate[1] = 'ESTABLISHED'
tcpstate[2] = 'SYN_SENT'
tcpstate[3] = 'SYN_RECV'
tcpstate[4] = 'FIN_WAIT1'
tcpstate[5] = 'FIN_WAIT2'
tcpstate[6] = 'TIME_WAIT'
tcpstate[7] = 'CLOSE'
tcpstate[8] = 'CLOSE_WAIT'
tcpstate[9] = 'LAST_ACK'
tcpstate[10] = 'LISTEN'
tcpstate[11] = 'CLOSING'
tcpstate[12] = 'NEW_SYN_RECV'

state = {}
state[0] = 'open'
state[1] = 'disorder'
state[2] = 'cwr'
state[3] = 'recovery'
state[4] = 'loss'

LABEL = sys.argv[1]
ip = sys.argv[2] if len(sys.argv) > 2 else None
DURATION = 15.0 

start_ts = int(time.time())
#filename = f"new_data_macbook_{LABEL}_iperf3_{int(DURATION)}s.csv"


ipv4_samples = []
ipv6_samples = []

# Global variables to store all samples
all_ipv4_samples = []
all_ipv6_samples = []
last_ipv4_sample = None
last_ipv6_sample = None

def store_ipv4_event(cpu, data, size):
    global last_ipv4_sample
    event = ct.cast(data, ct.POINTER(Data_ipv4)).contents
    last_ipv4_sample = event

def store_ipv6_event(cpu, data, size):
    global last_ipv6_sample
    event = ct.cast(data, ct.POINTER(Data_ipv6)).contents
    last_ipv6_sample = event

def clean_ipv6_mapped_addr(addr):
    if addr.startswith("::ffff:"):
        return addr[7:]  
    return addr

def get_stored_samples():
    """Return all stored samples"""
    return {
        'ipv4': all_ipv4_samples.copy(),
        'ipv6': all_ipv6_samples.copy()
    }

def clear_stored_samples():
    """Clear all stored samples"""
    global all_ipv4_samples, all_ipv6_samples
    all_ipv4_samples.clear()
    all_ipv6_samples.clear()

def start_collection(duration=15.0, sample_interval=0.1):
    """Start collecting TCP data for specified duration"""
    global all_ipv4_samples, all_ipv6_samples, last_ipv4_sample, last_ipv6_sample
    
    # Clear previous data
    clear_stored_samples()
    
    # Initialize BPF
    b = BPF(text=bpf_text)
    b.attach_kprobe(event="tcp_ack", fn_name="trace_ack")
    b["ipv4_events"].open_perf_buffer(store_ipv4_event, page_cnt=256)
    b["ipv6_events"].open_perf_buffer(store_ipv6_event, page_cnt=256)

    start_ts = time.time()
    last_sample_time = time.time()
    end_time = start_ts + duration
    sample_count = 0

    print(f"Start sampling: every {sample_interval*1000:.0f}ms")
    print(f"Expected: {int(duration/sample_interval)} samples for {duration:.0f} seconds")

    try:
        while time.time() < end_time:
            current_time = time.time()
            
            if current_time - last_sample_time >= sample_interval:
                b.perf_buffer_poll(timeout=0)
                
                if last_ipv4_sample:
                    # Create a copy to store
                    sample_copy = type(last_ipv4_sample)()
                    ct.memmove(ct.addressof(sample_copy), ct.addressof(last_ipv4_sample), ct.sizeof(last_ipv4_sample))
                    all_ipv4_samples.append(sample_copy)
                    sample_count += 1
                    last_ipv4_sample = None
                
                if last_ipv6_sample:
                    # Create a copy to store
                    sample_copy = type(last_ipv6_sample)()
                    ct.memmove(ct.addressof(sample_copy), ct.addressof(last_ipv6_sample), ct.sizeof(last_ipv6_sample))
                    all_ipv6_samples.append(sample_copy)
                    sample_count += 1
                    last_ipv6_sample = None
                    
                last_sample_time = current_time
                
            else:
                time_to_next_sample = sample_interval - (current_time - last_sample_time)
                sleep_time = min(time_to_next_sample, 0.01)
                if sleep_time > 0:
                    time.sleep(sleep_time)

    except KeyboardInterrupt:
        print("Sampling interrupted by user.")
    finally:
        duration_actual = time.time() - start_ts
        print(f"Collection done in {duration_actual:.1f}s")
        print(f"Samples collected: {sample_count}")
        print(f"Average frequency: {sample_count/duration_actual:.1f} samples/second")
        
        return {
            'ipv4': all_ipv4_samples,
            'ipv6': all_ipv6_samples,
            'duration': duration_actual,
            'sample_count': sample_count
        }

# If run as standalone script
if __name__ == "__main__":
    LABEL = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    DURATION = float(sys.argv[2]) if len(sys.argv) > 2 else 15.0
    
    result = start_collection(DURATION)
    print(f"Collection completed. IPv4 samples: {len(result['ipv4'])}, IPv6 samples: {len(result['ipv6'])}")
