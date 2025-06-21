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

def trigger_analysis(dst_ip_str):
    """Lance la séquence d'analyse pour une IP donnée."""
    global analysis_in_progress
    
    if analysis_in_progress:
        print(f"Analyse déjà en cours, ignorant {dst_ip_str}")
        return
        
    if dst_ip_str in processed_ips:
        #print(f"IP {dst_ip_str} déjà analysée, ignorant")
        return
        
    processed_ips.add(dst_ip_str)
    analysis_in_progress = True
    
    print(f"\n--- Début de l'analyse pour l'IP: {dst_ip_str} ---")

    try:
        print(f"1. Lancement de la collecte de données pour {dst_ip_str}...")
        subprocess.run(
            ["python3", "get_socket_data.py", "unknown"],
            check=True, timeout=20
        )
        print("   Collecte terminée.")

        print("2. Modification du dataset...")
        subprocess.run(
            ["python3", "modif.py", "data_prod.csv"],
            check=True, timeout=20
        )
        print("   Modification terminée.")

        print("3. Lancement de la prédiction...")
        subprocess.run(
            ["python3", "predict_cca.py"],
            check=True, timeout=10
        )
        print(f"--- ✅ Analyse pour {dst_ip_str} terminée ---")

    except Exception as e:
        print(f"   ❌ Une erreur est survenue durant l'analyse: {e}")
    finally:
        analysis_in_progress = False

def handle_ipv4_event(cpu, data, size):
    try:
        event = ct.cast(data, ct.POINTER(IPv4Event)).contents
        dst_ip = inet_ntop(AF_INET, pack("I", event.daddr))
        print(f"Événement IPv4 reçu pour IP: {dst_ip}")
        trigger_analysis(dst_ip)
    except Exception as e:
        print(f"Erreur lors du traitement IPv4: {e}")

def handle_ipv6_event(cpu, data, size):
    try:
        event = ct.cast(data, ct.POINTER(IPv6Event)).contents
        dst_ip = inet_ntop(AF_INET6, event.daddr)
        dst_ip = clean_ipv6_mapped_addr(dst_ip)
        #print(f"Événement IPv6 reçu pour IP: {dst_ip}")
        trigger_analysis(dst_ip)
    except Exception as e:
        print(f"Erreur lors du traitement IPv6: {e}")

# initialize BPF
print("Initialisation du programme BPF...")
b = BPF(text=bpf_text)
b.attach_kprobe(event="tcp_ack", fn_name="trace_ack")
b["ipv4_events"].open_perf_buffer(handle_ipv4_event, page_cnt=64)
b["ipv6_events"].open_perf_buffer(handle_ipv6_event, page_cnt=64)

print("En attente d'événements TCP...")

try:
    while True:
        b.perf_buffer_poll(timeout=0)
        
except KeyboardInterrupt:
    print("\nInterrompu par l'utilisateur.")