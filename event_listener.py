import ctypes as ct
from bcc import BPF
import socket
import subprocess
import time
import sys
import os

# S'assurer que le script est lancé avec sudo
if os.geteuid() != 0:
    print("Ce script doit être lancé avec sudo.")
    sys.exit(1)

# 1. Définir un programme BPF minimaliste.
#    Son seul but est de déclarer une map avec le même nom que celle dans le noyau.
bpf_text = """
BPF_PERF_OUTPUT(conn_events);
"""

# 2. Définir la structure de l'événement en Python.
#    Elle doit correspondre à celle envoyée par tcp_changecc_kern.c pour lire le buffer.
class ConnectionEvent(ct.Structure):
    _fields_ = [
        ("dst_ip", ct.c_uint32),
    ]

# 3. Charger notre mini-programme BPF.
#    BCC va créer un handle Python pour la map "conn_events".
try:
    b = BPF(text=bpf_text)
except Exception as e:
    print(f"Erreur lors de l'initialisation de BPF: {e}")
    sys.exit(1)

processed_ips = set()

def trigger_analysis(dst_ip_str):
    """Lance la séquence d'analyse pour une IP donnée."""
    if dst_ip_str in processed_ips:
        return
        
    processed_ips.add(dst_ip_str)
    print(f"\n--- Début de l'analyse pour l'IP: {dst_ip_str} ---")

    try:
        print(f"1. Lancement de la collecte de données pour {dst_ip_str}...")
        # CORRECTION: On passe l'IP au script get_socket_data.py
        subprocess.run(
            ["python3", "get_socket_data.py", "unknown", dst_ip_str],
            check=True, timeout=20
        )
        print("   Collecte terminée.")

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

def handle_event(cpu, data, size):
    """Callback appelé chaque fois qu'un événement arrive."""
    # Même si nous voulons juste un "signal", nous devons lire les données
    # pour que le buffer soit vidé correctement.
    event = ct.cast(data, ct.POINTER(ConnectionEvent)).contents
    dst_ip_str = socket.inet_ntoa(event.dst_ip.to_bytes(4, 'little'))
    
    print(f"🔔 Signal reçu pour la connexion vers: {dst_ip_str}")
    trigger_analysis(dst_ip_str)

# 4. S'attacher au buffer de performance.
#    BCC va utiliser le handle qu'il a créé pour s'attacher à la map
#    existante dans le noyau.
try:
    b["conn_events"].open_perf_buffer(handle_event)
except Exception as e:
    print(f"Erreur lors de l'ouverture du buffer d'événements: {e}")
    print("Assurez-vous que 'sudo ./load_sock_ops' est en cours d'exécution.")
    sys.exit(1)

print("👂 En attente de signaux... Lancez du trafic réseau.")

# 5. Boucle principale pour écouter les signaux.
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🛑 Arrêt de l'écouteur...")