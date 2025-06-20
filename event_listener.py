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

BPF_OBJECT_FILE = "/home/salhoz/v2/bbr/samples/bpf"

# Définir la structure de l'événement pour qu'elle corresponde à celle en C
class ConnectionEvent(ct.Structure):
    _fields_ = [
        ("dst_ip", ct.c_uint32),
    ]

# Charger l'objet BPF.
# Nous ne l'attachons pas, nous le chargeons juste pour accéder aux maps.
try:
    b = BPF(obj=BPF_OBJECT_FILE)
except Exception as e:
    print(f"Erreur lors du chargement de {BPF_OBJECT_FILE}: {e}")
    print("Assurez-vous d'avoir compilé avec 'make'.")
    sys.exit(1)

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
    b["conn_events"].open_perf_buffer(handle_event)
except Exception as e:
    print(f"Erreur lors de l'ouverture du buffer d'événements: {e}")
    print("Assurez-vous que 'load_sock_ops' est lancé et a épinglé la map 'conn_events'.")
    sys.exit(1)

print("👂 En attente d'événements... Lancez du trafic réseau.")

# 4. Boucle principale pour écouter les événements.
try:
    while True:
        b.perf_buffer_poll()
except KeyboardInterrupt:
    print("\n🛑 Arrêt de l'écouteur...")