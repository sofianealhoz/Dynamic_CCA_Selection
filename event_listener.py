#!/usr/libexec/platform-python

from bcc import BPF
import time
from struct import pack
import ctypes as ct
import csv
import os
import ipaddress
import sys
import socket
import subprocess
from socket import inet_ntop, AF_INET, AF_INET6
import threading

# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <net/tcp.h>

struct ipv4_event_t {
    u32 daddr;
};

struct ipv6_event_t {
    unsigned __int128 daddr;
};

BPF_PERF_OUTPUT(ipv4_events);
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

    u16 family = skp->__sk_common.skc_family;
    
    if (family == AF_INET) {
        struct ipv4_event_t event4 = {};
        event4.daddr = skp->__sk_common.skc_daddr;
        ipv4_events.perf_submit(ctx, &event4, sizeof(event4));
    } else if (family == AF_INET6) {
        struct ipv6_event_t event6 = {};
        bpf_probe_read(&event6.daddr, sizeof(event6.daddr),
            skp->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        ipv6_events.perf_submit(ctx, &event6, sizeof(event6));
    }
    
    return 0;
}

int trace_ack(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk);
    return 0;
}
"""

class IPv4Event(ct.Structure):
    _fields_ = [("daddr", ct.c_uint32)]

class IPv6Event(ct.Structure):
    _fields_ = [("daddr", (ct.c_ulonglong * 2))]

def clean_ipv6_mapped_addr(addr):
    if addr.startswith("::ffff:"):
        return addr[7:]  
    return addr

class Connection:
    processed_ips = set()
    analysis_in_progress = False

# Global functions for handling events
def handle_ipv4_event(cpu, data, size):
    try:
        event = ct.cast(data, ct.POINTER(IPv4Event)).contents
        dst_ip = inet_ntop(AF_INET, pack("I", event.daddr))
        print(f"IPv4 event received: {dst_ip}")
        trigger_analysis(dst_ip)

    except Exception as e:
        print(f"Error during handle_ipv4_event: {e}")

def handle_ipv6_event(cpu, data, size):
    try:
        event = ct.cast(data, ct.POINTER(IPv6Event)).contents
        dst_ip = inet_ntop(AF_INET6, event.daddr)
        dst_ip = clean_ipv6_mapped_addr(dst_ip)
        #print(f"IPv6 event received: {dst_ip}")
        trigger_analysis(dst_ip)

    except Exception as e:
        print(f"Error during handle_ipv6_event: {e}")

def run_analysis(dst_ip_str):
    try:
        print(f"1. Launching write_socket_data.py for: {dst_ip_str}")
        subprocess.run(
            ["python3", "write_socket_data.py", "unknown", dst_ip_str],
            check=True, timeout=20
        )
        print("   Collection finished.")

        print("2. Launching modif.py")
        subprocess.run(
            ["python3", "modif.py", f"data_prod_{dst_ip_str.replace(':', '_')}.csv"],
            check=True, timeout=20
        )
        print("   Modification finished.")

        print("3. Launching predict_cca.py")
        subprocess.run(
            ["python3", "predict_cca.py", dst_ip_str],
            check=True, timeout=10
        )
        print(f"--- ✅ Prediction for: {dst_ip_str} terminated ---")

    except Exception as e:
        print(f"   ❌ An error occurred during the process: {e}")
    finally:
        Connection.analysis_in_progress = False

def trigger_analysis(dst_ip_str):
    if Connection.analysis_in_progress:
        #print(f"Already processing, skipping: {dst_ip_str}")
        return
        
    if dst_ip_str in Connection.processed_ips:
        return
        
    Connection.processed_ips.add(dst_ip_str)
    Connection.analysis_in_progress = True
    
    try:
        print(f"\n--- Process start for: {dst_ip_str} ---")
        # Run analysis in a separate thread
        thread = threading.Thread(target=run_analysis, args=(dst_ip_str,))
        thread.daemon = True
        thread.start()
        
    except Exception as e:
        print(f"   ❌ An error occurred during trigger_analysis: {e}")
        Connection.analysis_in_progress = False

# initialize BPF
print("Initialising BPF program")
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_ack", fn_name="trace_ack")
b["ipv4_events"].open_perf_buffer(handle_ipv4_event, page_cnt=64)
b["ipv6_events"].open_perf_buffer(handle_ipv6_event, page_cnt=64)

print("Waiting for TCP events on port 5201")

try:
    while True:
        b.perf_buffer_poll(timeout=0)
        
except KeyboardInterrupt:
    print("\nKeyboard interruption by the user, exiting...")