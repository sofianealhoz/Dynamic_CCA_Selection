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

# Définir la structure de l'événement pour qu'elle corresponde à celle en C
class ConnectionEvent(ct.Structure):
    _fields_ = [
        ("dst_ip", ct.c_uint32),
        ("src_port", ct.c_uint16),
        ("dst_port", ct.c_uint16),
    ]

processed_ips = set()

def trigger_analysis(dst_ip_str):
    """Lance la séquence d'analyse pour une IP donnée."""
    
    # Éviter de traiter la même IP plusieurs fois en moins de 30 secondes
    if dst_ip_str in processed_ips:
        print(f"   ⏭️  IP {dst_ip_str} already analysed")
        return
        
    processed_ips.add(dst_ip_str)
    print(f"\n--- Début de l'analyse pour l'IP: {dst_ip_str} ---")

    try:
        # Étape A: Collecter les données avec get_socket_data.py
        print(f"1. Lancement de la collecte de données pour {dst_ip_str}...")
        subprocess.run(
            ["python3", "get_socket_data.py", "unknown"],
            check=True, timeout=20
        )
        print("   Collecte terminée.")

        # Étape B: Lancer la prédiction et la mise à jour de la map
        print("2. Lancement de la prédiction...")
        subprocess.run(
            ["python3", "predict_cca.py"],
            check=True, timeout=10
        )
        print(f"--- ✅ Analyse pour {dst_ip_str} terminée ---")

    except Exception as e:
        print(f"   ❌ Une erreur est survenue durant l'analyse: {e}")
    finally:
        # Permettre une nouvelle analyse de cette IP après 30 secondes
        time.sleep(30)
        processed_ips.discard(dst_ip_str)


def handle_event(cpu, data, size):
    """Callback appelé par bcc chaque fois qu'un événement arrive."""
    event = ct.cast(data, ct.POINTER(ConnectionEvent)).contents
    dst_ip_str = socket.inet_ntoa(event.dst_ip.to_bytes(4, 'little'))
    print(f"🔔 Événement reçu: Nouvelle connexion vers l'IP {dst_ip_str}")
    trigger_analysis(dst_ip_str)

# --- Point d'entrée ---

# S'attacher à la map d'événements qui a été épinglée par load_sock_ops
try:
    event_map = BPF.get_pinned_map(b"/sys/fs/bpf/connection_events")
except Exception as e:
    print("Erreur: Impossible de trouver la map d'événements épinglée.")
    print("Assurez-vous que 'sudo ./load_sock_ops' est en cours d'exécution dans un autre terminal.")
    sys.exit(1)

# Ouvrir le canal d'événements et lier la fonction de callback
event_map.open_perf_buffer(handle_event)
print("👂 En attente d'événements du noyau... Lancez du trafic réseau.")
print("   Appuyez sur Ctrl+C pour arrêter.")

# Boucle principale pour écouter les événements
try:
    while True:
        event_map.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🛑 Arrêt de l'écouteur.")