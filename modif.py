import pandas as pd
import sys

# Vérifier si un fichier est fourni
filename = sys.argv[1]

# Lire le CSV
df = pd.read_csv(filename)

# Ajouter la colonne Label en première position avec la valeur "Wi-Fi"
#df.insert(0, 'Label', 'Wi-Fi')

# for i in range(533, 1072):
#     df[i][0] = 'Mobile'
# for i in range(1072, 1639):
#     df[i][0] = 'Fibre'
# df.loc[533:1071, 'Label'] = 'Mobile'
# df.loc[1072:1638, 'Label'] = 'Fibre'
#df = df.drop('tstamp', axis=1)
df.insert(0,'label','wi-fi')

# Sauvegarder directement dans le même fichier
df.to_csv(filename, index=False)
#print(f"Colonne 'Label' ajoutée avec la valeur 'Wi-Fi' pour {len(df)} lignes")
#print(f"Fichier {filename} modifié")
