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
from datetime import datetime
import signal
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

processed_ips = set()
analysis_in_progress = False
benchmark_type = sys.argv[1]


#env = "datacenter"  #############################
#algo = "dctcp_" #############################

dur = sys.argv[2]
algo = sys.argv[3]
env = sys.argv[4]

duration_predict = 0.25
duration_benchmark = float(dur) - 0.25  ######################
duration_total = duration_benchmark + duration_predict
SOURCE = algo + "-" + env
current_time = datetime.now().strftime("%I%p").lower()

def start_load_sock_ops():
    print("🚀 Starting load_sock_ops with full logging...")
    proc = subprocess.Popen(
        ["/root/bbr/samples/bpf/load_sock_ops", "-l", "/tmp/cgroupv2/foo", "/root/bbr/samples/bpf/tcp_changecc_kern.o"],
        start_new_session=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Thread 1: Logs du binaire
    def print_proc_logs():
        for line in proc.stdout:
            print(f"[load_sock_ops] {line.strip()}")
    threading.Thread(target=print_proc_logs, daemon=True).start()
    
    # Thread 2: Logs BPF (trace_pipe)
    def print_bpf_logs():
        trace_path = "/sys/kernel/debug/tracing/trace_pipe"
        if os.path.exists(trace_path):
            try:
                with open(trace_path, 'r') as f:
                    for line in f:
                        if "bpf_basertt" in line or "CCA" in line:
                            print(f"[BPF] {line.strip()}")
            except Exception as e:
                print(f"⚠️ Cannot read trace_pipe: {e}")
    threading.Thread(target=print_bpf_logs, daemon=True).start()
    
    time.sleep(2)
    if proc.poll() is not None:
        print(f"❌ load_sock_ops crashed (rc={proc.returncode})")
        return None
    print(f"✅ load_sock_ops started (PID {proc.pid})")
    return proc

def stop_load_sock_ops(proc, reason="normal"):
    if not proc:
        return
    if proc.poll() is not None:
        # déjà mort
        return
    print(f"🧹 Stopping load_sock_ops ({reason})...")
    # Lire ce qui traîne pour éviter blocage sur pipe plein
    def drain():
        try:
            out, err = proc.communicate(timeout=0.05)
            if out:
                print(f"[load_sock_ops stdout tail]\n{out[-400:]}")
            if err:
                print(f"[load_sock_ops stderr tail]\n{err[-400:]}")
        except Exception:
            pass

    signals = [signal.SIGINT, signal.SIGTERM, signal.SIGKILL]
    for sig in signals:
        try:
            pgid = os.getpgid(proc.pid)
        except Exception:
            pgid = proc.pid
        try:
            os.killpg(pgid, sig)
            print(f"  Sent {sig.name} to PGID {pgid}")
        except ProcessLookupError:
            break
        # Attendre qu’il meure
        for _ in range(10):
            if proc.poll() is not None:
                print(f"  ✅ Stopped with {sig.name} (rc={proc.returncode})")
                drain()
                return
            time.sleep(0.1)
        drain()
    if proc.poll() is None:
        print("  ❌ Could not stop load_sock_ops after escalation")

if benchmark_type == 's':
    col = str(int(duration_total)) + 'min_solution'
else:
    col = str(int(duration_total)) + 'min_algo'
#SOURCE = "vm-fibre___"  
#filename = f"2benchmarck_{benchmark_type}_{SOURCE}_{int(duration_total)}min.csv"
filename = f"mbpsfauto_benchmarck_{benchmark_type}_{SOURCE}_{int(duration_total)}min_{current_time}.csv"

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
        p_ebpf = start_load_sock_ops()
        if p_ebpf is None:
            analysis_in_progress = False
            return


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
            stop_load_sock_ops(p_ebpf, reason="post-processing")
            p_ebpf = None  # Marqué comme arrêté


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
            ["python3", "calculate_averages.py", f"f_{filename}", "benchmark_data_troughput_and_srtt.csv", algo, env, col, benchmark_type],
            check=True, timeout=10
            )
            print(f"--- ✅ Benchmark done ---")
    #f_ --> checker dans vm: les f_auto / f_... voir si pas pb de nom
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
            ["python3", "calculate_averages.py", filename, "benchmark_data_troughput_and_srtt.csv", algo, env, col, benchmark_type],
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