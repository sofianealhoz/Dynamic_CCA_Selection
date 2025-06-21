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
from socket import inet_ntop, AF_INET6



# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/tcp.h>
#include <net/tcp.h>

struct ack_event_t {
    u32 daddr;
};

BPF_PERF_OUTPUT(ack_events);

static int trace_event(struct pt_regs *ctx, struct sock *skp)
{
    if (skp == NULL)
        return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (skp->__sk_common.skc_num != 5201)
    {
        return 0;
    }

    // Envoyer un simple signal
    struct ack_event_t event = {};
    event.daddr = skp->__sk_common.skc_daddr;
    ack_events.perf_submit(ctx, &event, sizeof(event));
    
    return 0;
}

int trace_ack(struct pt_regs *ctx, struct sock *sk)
{
    trace_event(ctx, sk);
    return 0;
}
"""

processed_ips = set()

def trigger_analysis(dst_ip_str):
    """Lance la séquence d'analyse pour une IP donnée."""
    if dst_ip_str in processed_ips:
        return
        
    processed_ips.add(dst_ip_str)
    print(f"\n--- Début de l'analyse pour l'IP: {dst_ip_str} ---")

    try:
        print(f"1. Lancement de la collecte de données pour {dst_ip_str}...")
        subprocess.run(
            ["python3", "get_socket_data.py", "unknown"],
            check=True, timeout=20
        )
        print("   Collecte terminée.")

        print("modifying dataset")
        subprocess.run(
            ["python3", "modif.py", "data_prod.csv"],
            check=True, timeout=20
        )
        print("   modification finished.")

        print("2. Lancement de la prédiction...")
        subprocess.run(
            ["python3", "predict_cca.py"],
            check=True, timeout=10
        )
        print(f"--- ✅ Analyse pour {dst_ip_str} terminée ---")

    except Exception as e:
        print(f"   ❌ Une erreur est survenue durant l'analyse: {e}")
    finally:
        time.sleep(30)
        processed_ips.discard(dst_ip_str)

def handle_ack_event(cpu, data, size):
    # Lire l'événement et extraire l'IP
    event = b["ack_events"].event(data)
    dst_ip = inet_ntop(AF_INET6, event.daddr)
    trigger_analysis(dst_ip)

# initialize BPF
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_ack", fn_name="trace_ack")
b["ack_events"].open_perf_buffer(handle_ack_event, page_cnt=64)



try:
    while True:
        b.perf_buffer_poll(timeout=100)
        
except KeyboardInterrupt:
    print("Interrupted by user.")