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
import shutil


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

processed_ips = set()
analysis_in_progress = False
benchmark_type = sys.argv[1]
duration_predict = 0.25
duration_benchmark = 10 - 0.25  ######################
duration_total = duration_benchmark + duration_predict
algo = "sol2" #############################
env = "fibre"  #############################
SOURCE = algo + "-" + env
if benchmark_type == 's':
    col = str(int(duration_total)) + 'min_solution'
else:
    col = str(int(duration_total)) + 'min_algo'
#SOURCE = "vm-fibre___"  
filename = f"benchmarck_{benchmark_type}_{SOURCE}_{int(duration_total)}min.csv"

def trigger_analysis(dst_ip_str):
    global analysis_in_progress
    
    if analysis_in_progress:
        print(f"Already proccessing, skiping: {dst_ip_str}")
        return
        
    if dst_ip_str in processed_ips:
        return
        
    processed_ips.add(dst_ip_str)
    analysis_in_progress = True
    
    print(f"\n--- Process start for: {dst_ip_str} ---")
    if benchmark_type == 's' :
        try:
            # Phase 1: Prédiction

            print(f"1. Launching get_socket_data.py to predict cca for: {dst_ip_str}")
            subprocess.run(
                ["python3", "get_socket_data.py", "unknown", filename, "s1", str(duration_benchmark), SOURCE],
                check=True, timeout=20
            )
            print("   Collection to predict cca finished.")


            print("2. Launching modif.py")
            subprocess.run(
                ["python3", "modif.py", filename],  # ← Nom correct
                check=True, timeout=20
            )
            print("   Modification finished.")

            copy = f"copy_{filename}"
            shutil.copyfile(filename, copy)
            print(f"Copie créée : {copy}")

            print(f"4. Launching get_socket_data.py for benchmark for: {dst_ip_str}")
            p1 = subprocess.Popen(
                ["python3", "get_socket_data.py", "unknown", filename, "s2", str(duration_benchmark), SOURCE]
            )
            print("   Collection for benchmark started.")

            time.sleep(2)

            print("3. Launching predict_cca.py")
            subprocess.run(
                ["python3", "predict_cca.py", copy],
                check=True, timeout=10
            )
            print(f"--- ✅ Prediction for: {dst_ip_str} terminated ---")
            p1.wait()
            print("2. Launching modif.py")
            subprocess.run(
                ["python3", "modif.py", filename],  # ← Nom correct
                check=True, timeout=20
            )
            print("   Modification finished.")
            subprocess.run(
            #["python3", "aggregate_csv.py", f"cubic5_{filename}", copy, filename],
            ["python3", "aggregate_csv.py", f"f_{filename}", copy, filename],
            check=True, timeout=10
            )
            print(f"--- ✅ Prediction for: {dst_ip_str} terminated ---")
            subprocess.run(
            ["python3", "calculate_averages.py", f"f_{filename}", "benchmark_data_troughput_and_srtt.csv", algo, env, col],
            check=True, timeout=10
            )
            print(f"--- ✅ Benchmark done ---")
    

        except Exception as e:
            print(f"   ❌ An error occured durung the process: {e}")
        finally:
            analysis_in_progress = False
    else:
        try:

            print(f"1. Launching get_socket_data.py for fixed cca analysis for: {dst_ip_str}")
            subprocess.run(
                ["python3", "get_socket_data.py", "unknown", filename, "c", str(duration_benchmark), SOURCE],
                check=True
            )
            print("   Collection for fixed cca analysis finished.")


            print("2. Launching modif.py for fixed cca analysis")
            subprocess.run(
                ["python3", "modif.py", filename],  # ← Nom correct
                check=True, timeout=20
            )
            print("   Modification finished.")

    
            subprocess.run(
            #["python3", "calculate_averages.py", f"cubic5_{filename}"],
            ["python3", "calculate_averages.py", filename, "benchmark_data_troughput_and_srtt.csv", algo, env, col],
            check=True, timeout=10
            )
            print(f"--- ✅ Benchmark for fixed cca done ---")
    

        except Exception as e:
            print(f"   ❌ An error occured durung the process: {e}")
        finally:
            analysis_in_progress = False


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
        #print(f"Événement IPv6 reçu pour IP: {dst_ip}")
        trigger_analysis(dst_ip)
    except Exception as e:
        print(f"Error during handle_ipv6_event: {e}")

# initialize BPF
print("Initialising BPF program")
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_ack", fn_name="trace_ack")
b["ipv4_events"].open_perf_buffer(handle_ipv4_event, page_cnt=512)
b["ipv6_events"].open_perf_buffer(handle_ipv6_event, page_cnt=512)

print("Waiting for TCP events on port 5201")

try:
    while True:
        b.perf_buffer_poll(timeout=0)
        
except KeyboardInterrupt:
    print("\nKeyboard interruption by the user, exiting...")