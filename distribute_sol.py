import pandas as pd

def distribute_solution_values():
    """
    Répartir les valeurs de la solution 'sol' dans les colonnes solution appropriées
    """
    
    # Lire le fichier CSV
    df = pd.read_csv('data/benchmark_data_troughput_and_srtt.csv')
    
    print("Avant modification:")
    print(f"Nombre total de lignes: {len(df)}")
    print(f"Lignes avec 'sol': {len(df[df['algo'] == 'sol'])}")
    
    # Extraire les valeurs de la solution
    sol_data = df[df['algo'] == 'sol'].copy()
    
    print("\nValeurs de la solution trouvées:")
    for _, row in sol_data.iterrows():
        env = row['env']
        metric = row['metric']
        for period in ['1min', '5min', '10min']:
            solution_col = f'{period}_solution'
            value = row[solution_col]
            if pd.notna(value):
                print(f"  {env} - {metric} - {period}: {value}")
    
    # Pour chaque ligne de solution, mettre à jour les lignes correspondantes
    for _, sol_row in sol_data.iterrows():
        env = sol_row['env']
        metric = sol_row['metric']
        
        # Trouver toutes les lignes qui correspondent à cet environnement et cette métrique
        # (sauf les lignes 'sol' elles-mêmes)
        matching_rows = df[(df['env'] == env) & 
                          (df['metric'] == metric) & 
                          (df['algo'] != 'sol')]
        
        print(f"\nTraitement: {env} - {metric}")
        print(f"  Lignes correspondantes trouvées: {len(matching_rows)}")
        
        # Pour chaque période, copier la valeur de solution
        for period in ['1min', '5min', '10min']:
            solution_col = f'{period}_solution'
            sol_value = sol_row[solution_col]
            
            if pd.notna(sol_value):
                # Mettre à jour toutes les lignes correspondantes
                mask = (df['env'] == env) & (df['metric'] == metric) & (df['algo'] != 'sol')
                df.loc[mask, solution_col] = sol_value
                
                print(f"    {period}: {sol_value} → appliqué à {mask.sum()} lignes")
    
    # Supprimer les lignes 'sol' car elles ne sont plus nécessaires
    df_cleaned = df[df['algo'] != 'sol'].copy()
    
    print(f"\nAprès nettoyage:")
    print(f"Lignes supprimées (sol): {len(df) - len(df_cleaned)}")
    print(f"Nombre final de lignes: {len(df_cleaned)}")
    
    # Trier par algorithme pour garder l'ordre
    df_cleaned = df_cleaned.sort_values(by='algo')
    
    # Sauvegarder le fichier modifié
    df_cleaned.to_csv('data/benchmark_data_troughput_and_srtt.csv', index=False)
    
    print("\nFichier mis à jour et sauvegardé!")
    
    # Vérification : afficher quelques exemples de lignes mises à jour
    print("\nExemples de lignes mises à jour:")
    print("=" * 80)
    
    # Vérifier mobile + srtt
    mobile_srtt = df_cleaned[(df_cleaned['env'] == 'mobile') & (df_cleaned['metric'] == 'srtt')]
    if not mobile_srtt.empty:
        print("Mobile + SRTT:")
        for _, row in mobile_srtt.head(3).iterrows():
            print(f"  {row['algo']}: 1min_solution={row['1min_solution']}, 5min_solution={row['5min_solution']}, 10min_solution={row['10min_solution']}")
    
    # Vérifier wi-fi + throughput
    wifi_throughput = df_cleaned[(df_cleaned['env'] == 'wi-fi') & (df_cleaned['metric'] == 'throughput')]
    if not wifi_throughput.empty:
        print("\nWi-Fi + Throughput:")
        for _, row in wifi_throughput.head(3).iterrows():
            print(f"  {row['algo']}: 1min_solution={row['1min_solution']}, 5min_solution={row['5min_solution']}, 10min_solution={row['10min_solution']}")
    
    return df_cleaned

def verify_solution_distribution():
    """
    Vérifier que la distribution a été faite correctement
    """
    df = pd.read_csv('data/benchmark_data_troughput_and_srtt.csv')
    
    print("\nVérification de la distribution:")
    print("=" * 50)
    
    # Vérifier chaque combinaison env/metric
    combinations = df[['env', 'metric']].drop_duplicates()
    
    for _, combo in combinations.iterrows():
        env = combo['env']
        metric = combo['metric']
        
        subset = df[(df['env'] == env) & (df['metric'] == metric)]
        
        print(f"\n{env} - {metric}:")
        
        for period in ['1min', '5min', '10min']:
            solution_col = f'{period}_solution'
            
            # Compter les valeurs non-nulles
            non_null_count = subset[solution_col].notna().sum()
            total_count = len(subset)
            
            # Obtenir les valeurs uniques
            unique_values = subset[solution_col].dropna().unique()
            
            if len(unique_values) > 0:
                print(f"  {period}: {non_null_count}/{total_count} lignes remplies, valeur(s): {unique_values}")
            else:
                print(f"  {period}: 0/{total_count} lignes remplies")

if __name__ == "__main__":
    # Exécuter la distribution
    df_result = distribute_solution_values()
    
    # Vérifier le résultat
    verify_solution_distribution()
    
    print("\n" + "="*80)
    print("TERMINÉ!")
    print("Le fichier 'data/benchmark_data_troughput_and_srtt.csv' a été mis à jour.")
    print("Les valeurs de la solution ont été distribuées dans les colonnes appropriées.")