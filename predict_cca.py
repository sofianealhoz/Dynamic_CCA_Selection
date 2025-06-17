import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder
import joblib
from collections import Counter 
import os
import ctypes
import ctypes.util

def load_and_predict(data_file):
    artifacts = joblib.load('trained_classifier.pkl')
    data_prod = pd.read_csv(data_file)

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



def update_pinned_map(connection_prediction):
    """Using pinned map"""
    
    connection_type_CCA_map = {
        'wifi': 'cubic',
        'fibre': 'bbr',
        'mobile': 'bbr', 
        'datacenter': 'dctcp',
        'satellite' : 'bbrv2',
        'dsl' : 'cubic'
    }
    
    recommended_cca = connection_type_CCA_map.get(connection_prediction, 'cubic')
    
    # Ouvrir la map épinglée
    try:
        libbpf = ctypes.CDLL("libbpf.so")
        map_fd = libbpf.bpf_obj_get(b"/sys/fs/bpf/key_cong_map")
        
        if map_fd > 0:
            # Utiliser votre update_bpf_map() ici
            print(f"updating with: {recommended_cca}")
            # update_bpf_map(map_fd, "127.0.0.1", 5001, 5004, recommended_cca)
        else:
            print("Map not found")
            
    except Exception as e:
        print(f"Error: {e}")

predictions = load_and_predict('data_prod.csv')
most_common = Counter(predictions).most_common(1)[0][0]
update_pinned_map(most_common)