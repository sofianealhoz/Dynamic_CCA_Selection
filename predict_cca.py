import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
from collections import Counter 
import os
import ctypes
import ctypes.util
from bcc import BPF
import socket

class ConnectionTuple(ctypes.Structure):
    _fields_ = [
        ("dst_ip", ctypes.c_uint32),
    ]

connection_id_str = None

def load_and_predict(data_file):
    artifacts = joblib.load('trained_classifier.pkl')
    data_prod = pd.read_csv(data_file)

    global connection_id_str
    connection_id_str = data_prod['connection_id'][20]

    label_encoder_conn = LabelEncoder()
    data_prod['connection_id_encoded'] = label_encoder_conn.fit_transform(data_prod['connection_id'])

    #print("Mapping labels:")
    #for i, label in enumerate(label_encoder_label.classes_):
    #    print(f"{i}: {label}")
    print(artifacts['label_encoder'])
    for i, label in enumerate(artifacts['label_encoder'].classes_):
        print(f"{i}: {label}")
    data_prod = data_prod.drop(['label', 'connection_id'], axis=1)

    predictions = artifacts['model'].predict(data_prod)

    return(predictions)

def parse_connection_id_to_tuple(conn_str):
    """
    Analyse la chaîne 'dst_ip;src_port;dst_port' et la convertit en une
    instance de ConnectionTuple avec les valeurs en ordre réseau (network byte order).
    """
    try:
        dst_ip_str = conn_str.strip()

        dst_ip_nbo = int.from_bytes(socket.inet_aton(dst_ip_str), 'big')

        

        # Crée et retourne l'instance de la structure ctypes
        return ConnectionTuple(
            dst_ip=dst_ip_nbo
        )
    except Exception as e:
        print(f"Erreur lors de l'analyse de '{conn_str}': {e}")
        return None

def update_pinned_map(connection_prediction):
    """Using pinned map"""

    global connection_id_str
    if not connection_id_str:
        print("Erreur: connection_id_str n'est pas défini.")
        return

    connection_key = parse_connection_id_to_tuple(connection_id_str)
    if not connection_key:
        return
    
    connection_type_CCA_map = {
        'wifi': 'cubic',
        'fibre': 'bbr',
        'mobile': 'bbr', 
        'datacenter': 'dctcp',
        'satellite' : 'bbrv2',
        'dsl' : 'cubic'
    }
    
    recommended_cca = connection_type_CCA_map.get(connection_prediction, 'cubic')
    
    map_path = b"/sys/fs/bpf/key_cong_map"
    map_fd = -1

    # Ouvrir la map épinglée
    try:
        libbpf = ctypes.CDLL(ctypes.util.find_library("bpf"))
        libbpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
        libbpf.bpf_obj_get.restype = ctypes.c_int
        
        map_fd = libbpf.bpf_obj_get(map_path)
        
        if map_fd >= 0:
            print(f"Mise à jour de la map pour la clé {connection_key} avec CCA: {recommended_cca}")
            update_bpf_map(map_fd, connection_key, recommended_cca)
        else:
            errno = ctypes.get_errno()
            print(f"Erreur: Impossible de trouver la map BPF à {map_path.decode()}: {os.strerror(errno)}")
            
    except Exception as e:
        print(f"Erreur lors de l'accès à la map épinglée: {e}")
    finally:
        if map_fd >= 0:
            os.close(map_fd)

def update_bpf_map(map_fd, key_struct, cca_algo):
    """Met à jour la map BPF avec la nouvelle règle CCA"""
    
    try:
        libbpf = ctypes.CDLL(ctypes.util.find_library("bpf"))
        libbpf.bpf_map_update_elem.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint64]
        libbpf.bpf_map_update_elem.restype = ctypes.c_int

        # La valeur est un char[16]
        value_bytes = cca_algo.encode('utf-8')
        value_buffer = ctypes.create_string_buffer(value_bytes, 16)
        
        BPF_ANY = 0
        
        ret = libbpf.bpf_map_update_elem(
            map_fd,
            ctypes.byref(key_struct),
            ctypes.byref(value_buffer),
            ctypes.c_uint64(BPF_ANY)
        )
        
        if ret == 0:
            print(f"✅ Map mise à jour: {key_struct} -> {cca_algo}")
            return True
        else:
            errno = ctypes.get_errno()
            print(f"❌ Échec mise à jour map: code {ret}, errno: {errno} ({os.strerror(errno)})")
            return False
    except Exception as e:
        print(f"Erreur dans update_bpf_map: {e}")
        return False

predictions = load_and_predict('data_prod.csv')
most_common = Counter(predictions).most_common(1)[0][0]
update_pinned_map(most_common)