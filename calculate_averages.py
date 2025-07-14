import pandas as pd
import numpy as np
import sys

def calculate_rtt_averages(csv_file):
    """
    Calculate the average of srtt, rtt, and throughput (using delivered) from a CSV file
    """
    try:
        df = pd.read_csv(csv_file)
        if 'srtt' not in df.columns or 'rtt' not in df.columns:
            print("Error: 'srtt' and/or 'rtt' columns do not exist in the file")
            return None

        srtt_mean = df['srtt'].mean()
        rtt_mean = df['rtt'].mean()

        # Throughput: mean of delivered difference per sample
        if 'delivered' in df.columns:
            delivered_diff = df['delivered'].diff().dropna()
            delivered_diff = delivered_diff[delivered_diff > 0]
            throughput_mean = delivered_diff.mean()
            throughput_min = delivered_diff.min()
            print(f"Average throughput (delivered per sample): {throughput_mean:.2f}")
            print(f"Min throughput (delivered per sample): {throughput_min:.2f}")
        else:
            throughput_mean = None

        print(f"Average SRTT: {srtt_mean:.2f} µs")
        print(f"Average RTT:  {rtt_mean:.2f} µs")
        return {'srtt_mean': round(srtt_mean,2), 'rtt_mean': round(rtt_mean,2), 'throughput_mean': round(throughput_mean,2)}

    except FileNotFoundError:
        print(f"Error: File {csv_file} not found")
        return None
    except Exception as e:
        print(f"Error during processing: {e}")
        return None

def upsert_value(g_csv_file, algo, env, colonne, valeurs):
    df = pd.read_csv(g_csv_file)
    metrics = ['throughput', 'srtt']  
    for i in range (2):
        metric = metrics[i] 
        valeur = valeurs[f"{metric}_mean"] 
        # 2. Création du masque pour trouver la ligne
        mask = (df['algo'] == algo) & (df['env'] == env) & (df['metric'] == metric)

        # 3. Si la ligne existe, on la met à jour
        if mask.any():
            df.loc[mask, colonne] = valeur
        else:
            # On prépare une nouvelle ligne vide
            nouvelle_ligne = {
                'algo': algo,
                'env': env,
                'metric': metric,
                '1min_algo': None,
                '1min_solution': None,
                '5min_algo': None,
                '5min_solution': None,
                '10min_algo': None,
                '10min_solution': None
            }
            nouvelle_ligne[colonne] = valeur
            df = pd.concat([df, pd.DataFrame([nouvelle_ligne])], ignore_index=True)

    df.to_csv(g_csv_file, index=False)
    print(f"Ajout/modif de la valeur {valeur} dans '{colonne}' pour {algo},{env},{metric} OK !")



if __name__ == "__main__":
    csv_file = sys.argv[1]
    graph_csv_file = sys.argv[2]
    results = calculate_rtt_averages(csv_file)
    upsert_value(graph_csv_file, sys.argv[3], sys.argv[4], sys.argv[5], calculate_rtt_averages(csv_file))