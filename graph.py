import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Configure matplotlib to not use interactive display
plt.ioff()

# Read the data file
df = pd.read_csv('benchmark_data_troughput_and_srtt.csv')
df = df.sort_values(by='algo')  # On trie, df devient un DataFrame trié
df.to_csv('benchmark_data_troughput_and_srtt.csv', index=False)  # On sauvegarde, mais on ne change PAS df !# Function to calculate gain percentage
def calculate_gain(algo_value, solution_value):
    return ((solution_value - algo_value) / algo_value) * 100

# Prepare data for graphs
#total_algos = ['cubic', 'cubic_', 'cubic_codel', 'bbr', 'bbr_', 'bbr_codel', 'reno','dctcp','dctcp_','bbr2','highspeed','hybla','illinois','scalable','vegas','westwood']
total_algos = ['cubic','bbr','reno','dctcp','bbr2','highspeed','hybla','illinois','scalable','vegas','westwood',"sol"]


algorithms = {
    "algos1": ['bbr', 'bbr2', 'highspeed', 'westwood'],
    "algos2":    ['cubic', 'reno', 'scalable', 'illinois'],
    "algos3":   ['dctcp', 'hybla', 'vegas']
}#algos1 = ['bbr', 'bbr2', 'highspeed', 'westwood']
#algos2 = ['cubic', 'reno', 'scalable', 'illinois']
#algos3 = ['dctcp', 'hybla', 'vegas']
#environments = ['fibre', 'datacenter','wi-fi']
#environments = ['fibre', 'datacenter', 'wi-fi', 'mobile']
environments = ['datacenter','wi-fi','wi-fi_limit','mobile', 'fibre', 'fibre2', 'fibre_limit'] 
metrics = ['throughput', 'srtt']
time_periods = ['1min', '3min', '5min', 'total']

def create_algorithms_values_chart_by_environment(environment, dur):
    """Créer un graphique avec les valeurs absolues de throughput et SRTT pour un environnement spécifique"""
    
    # Préparer les données - calculer les moyennes pour chaque algorithme dans cet environnement
    algo_stats = {}
    
    # Pour chaque algorithme, calculer les valeurs pour cet environnement
    for algo in total_algos:
        algo_stats[algo] = {'throughput': 0, 'srtt': 0}
        
        for metric in metrics:
            algo_data = df[(df['algo'] == algo) & (df['metric'] == metric) & (df['env'] == environment)]
            
            if not algo_data.empty:
                if dur == 'total':
                    # Mode moyenne (comportement original)
                    values = []
                    for p in time_periods[:-1]:
                        algo_col = f'{p}_algo'
                        if not pd.isna(algo_data[algo_col].values[0]):
                            values.append(algo_data[algo_col].values[0])
                    
                    if values:
                        algo_stats[algo][metric] = np.mean(values)
                else:
                    # Mode période spécifique
                    algo_col = f'{dur}_algo'
                    if not pd.isna(algo_data[algo_col].values[0]):
                        algo_stats[algo][metric] = algo_data[algo_col].values[0]

        # Calculer les moyennes pour la solution dans cet environnement
    solution_stats = {'throughput': 0, 'srtt': 0}
    
    for metric in metrics:
        if dur == 'total':
            # Mode moyenne
            values = []
            for algo in total_algos:
                algo_data = df[(df['algo'] == algo) & (df['metric'] == metric) & (df['env'] == environment)]
                
                if not algo_data.empty:
                    for p in time_periods[:-1]:
                        solution_col = f'{p}_solution'
                        if not pd.isna(algo_data[solution_col].values[0]):
                            values.append(algo_data[solution_col].values[0])
            
            if values:
                solution_stats[metric] = np.mean(values)
        else:
            # Mode période spécifique
            values = []
            for algo in total_algos:
                algo_data = df[(df['algo'] == algo) & (df['metric'] == metric) & (df['env'] == environment)]
                
                if not algo_data.empty:
                    solution_col = f'{dur}_solution'
                    if not pd.isna(algo_data[solution_col].values[0]):
                        values.append(algo_data[solution_col].values[0])
            
            if values:
                solution_stats[metric] = np.mean(values)
    
    
    # Filtrer uniquement les algorithmes qui ont des données pour cet environnement
    available_algos = [algo for algo in total_algos if algo_stats[algo]['throughput'] > 0 or algo_stats[algo]['srtt'] > 0]
    
    if not available_algos:
        print(f"No data available for environment: {environment}")
        return
    
    # Créer le graphique avec deux sous-graphiques (un pour throughput, un pour SRTT)
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(16, 12))
    fig.suptitle(f'Algorithms Performance Comparison - {environment.title()} Environment', fontsize=16, fontweight='bold')
    
    # Préparer les données pour l'affichage
    all_algos_with_solution = available_algos + ['SOLUTION']
    
    # === THROUGHPUT CHART ===
    throughput_values = []
    for algo in available_algos:
        throughput_values.append(algo_stats[algo]['throughput'])
    throughput_values.append(solution_stats['throughput'])
    
    # Créer les barres pour throughput
    x_pos = np.arange(len(all_algos_with_solution))
    bars1 = ax1.bar(x_pos, throughput_values, alpha=0.8, color='lightblue', edgecolor='navy', linewidth=1)
    
    # Mettre en évidence la solution
    bars1[-1].set_color('darkgreen')
    bars1[-1].set_alpha(0.9)
    print("wshsmrtest")

# Dans create_algorithms_values_chart_by_environment()
# Remplacer la section échelle throughput par :

    valid_throughput = [v for v in throughput_values if v > 0]
    if valid_throughput:
        min_val = min(valid_throughput)
        max_val = max(valid_throughput)
        range_val = max_val - min_val
        
        print(f"🔧 DEBUG - Min: {min_val:.0f}, Max: {max_val:.0f}, Range: {range_val:.0f}")

        # ✅ ADAPTATION pour des valeurs Mbps (milliers)
        if range_val < 1000:         # < 1000 Mbps de différence
            margin = 200             # Marge de 200 Mbps
            step = 200               # Graduations tous les 200 Mbps
            print(f"🔧 DEBUG - Using small range settings (Mbps)")
        elif range_val < 3000:       # < 3000 Mbps de différence  
            margin = 500             # Marge de 500 Mbps
            step = 500               # Graduations tous les 500 Mbps
            print(f"🔧 DEBUG - Using medium range settings (Mbps)")
        elif range_val < 10000:      # < 10000 Mbps de différence
            margin = 1000            # Marge de 1000 Mbps
            step = 1000              # Graduations tous les 1000 Mbps
            print(f"🔧 DEBUG - Using large range settings (Mbps)")
        else:                        # > 10000 Mbps de différence
            margin = 2000            # Marge de 2000 Mbps
            step = 2000              # Graduations tous les 2000 Mbps
            print(f"🔧 DEBUG - Using very large range settings (Mbps)")

        y_min = max(0, min_val - margin)  
        y_max = max_val + margin
        
        ax1.set_ylim(y_min, y_max)
        
        # Créer les graduations
        ticks = np.arange(y_min, y_max + step, step)
        ax1.set_yticks(ticks)
        
        print(f"📊 Throughput scale: {y_min:.0f} to {y_max:.0f} Mbps (step: {step})")

    # ✅ CORRECTION : Changer le label de l'axe Y
    ax1.set_ylabel('Throughput (Mbps)', fontsize=12)  # ← Gbps au lieu de Mbps !
    ax1.set_title(f'Average Throughput by Algorithm - {environment.title()}', fontsize=14, fontweight='bold')
    ax1.set_xticks(x_pos)
    ax1.set_xticklabels([algo.upper() for algo in all_algos_with_solution], rotation=45, ha='right')
    ax1.grid(True, alpha=0.3, axis='y')

    # Ajouter les valeurs sur les barres throughput
    for bar, value in zip(bars1, throughput_values):
        if value > 0:  # Only show label if value exists
            height = bar.get_height()
            ax1.annotate(f'{value:.0f}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom',
                        fontsize=10, fontweight='bold')
    
    # === SRTT CHART ===
    srtt_values = []
    for algo in available_algos:
        srtt_values.append(algo_stats[algo]['srtt'])
    srtt_values.append(solution_stats['srtt'])
    
    # Créer les barres pour SRTT
    bars2 = ax2.bar(x_pos, srtt_values, alpha=0.8, color='lightcoral', edgecolor='darkred', linewidth=1)
    
    # Mettre en évidence la solution
    bars2[-1].set_color('darkgreen')
    bars2[-1].set_alpha(0.9)


    # Personnaliser le graphique SRTT
    ax2.set_ylabel('SRTT (µs)', fontsize=12)
    ax2.set_title(f'Average SRTT by Algorithm - {environment.title()}', fontsize=14, fontweight='bold')
    ax2.set_xticks(x_pos)
    ax2.set_xticklabels([algo.upper() for algo in all_algos_with_solution], rotation=45, ha='right')
    ax2.grid(True, alpha=0.3, axis='y')
    
    # Ajouter les valeurs sur les barres SRTT
    for bar, value in zip(bars2, srtt_values):
        if value > 0:  # Only show label if value exists
            height = bar.get_height()
            ax2.annotate(f'{value:.0f}',
                        xy=(bar.get_x() + bar.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom',
                        fontsize=10, fontweight='bold')
    
    # Ajuster l'espacement
    plt.tight_layout()

    # Sauvegarder le graphique
    filename = f'auto_algorithms_values_comparison_{environment}3_{dur}.png'
    plt.savefig(filename, dpi=300, bbox_inches='tight')
    print(f"Algorithms values comparison chart saved as '{filename}'")
    
    # Afficher les statistiques
    print(f"\nAlgorithms Performance Values - {environment.title()} Environment:")
    print("=" * 60)
    print(f"{'Algorithm':<12} {'Throughput (Mbps)':<18} {'SRTT (µs)':<12}")
    print("-" * 60)
    for algo in available_algos:
        throughput_val = algo_stats[algo]['throughput']
        srtt_val = algo_stats[algo]['srtt']
        throughput_str = f"{throughput_val:.1f}" if throughput_val > 0 else "N/A"
        srtt_str = f"{srtt_val:.1f}" if srtt_val > 0 else "N/A"
        print(f"{algo.upper():<12} {throughput_str:<18} {srtt_str:<12}")
    
    solution_throughput_str = f"{solution_stats['throughput']:.1f}" if solution_stats['throughput'] > 0 else "N/A"
    solution_srtt_str = f"{solution_stats['srtt']:.1f}" if solution_stats['srtt'] > 0 else "N/A"
    print(f"{'SOLUTION':<12} {solution_throughput_str:<18} {solution_srtt_str:<12}")
    print("=" * 60)
    
    plt.close()

# Créer les nouveaux graphiques pour chaque environnement
for dur in time_periods:
    for env in environments:
        create_algorithms_values_chart_by_environment(env,dur)









# =============================================================================
# DETAILED COMPARISON CHART - CORRECTION
# =============================================================================
for file_name, algos in algorithms.items():
    # Create figure with subplots
    fig, axes = plt.subplots(2, len(algos), figsize=(18, 12))
    fig.suptitle("Solution's gain", fontsize=16)

    for i, metric in enumerate(metrics):
        for j, algo in enumerate(algos):
            ax = axes[i, j]
            
            # Filter data for current algorithm and metric
            algo_data = df[(df['algo'] == algo) & (df['metric'] == metric)]
            
            gains_fibre = []
            gains_datacenter = []
            gains_wifi = []
            gains_mobile = []
            labels = []
            
            for period in time_periods:
                algo_col = f'{period}_algo'
                solution_col = f'{period}_solution'
                
                # # Data for fibre
                # fibre_row = algo_data[algo_data['env'] == 'fibre']
                # if not fibre_row.empty:
                #     algo_val = fibre_row[algo_col].values[0]
                #     solution_val = fibre_row[solution_col].values[0]
                #     gain_fibre = calculate_gain(algo_val, solution_val)
                #     gains_fibre.append(gain_fibre)
                # else:
                #     gains_fibre.append(0)
                
                # Data for datacenter
                datacenter_row = algo_data[algo_data['env'] == 'datacenter']
                if not datacenter_row.empty:
                    algo_val = datacenter_row[algo_col].values[0]
                    solution_val = datacenter_row[solution_col].values[0]
                    gain_datacenter = calculate_gain(algo_val, solution_val)
                    gains_datacenter.append(gain_datacenter)
                else:
                    gains_datacenter.append(0)

                # Data for wi-fi
                wifi_row = algo_data[algo_data['env'] == 'wi-fi']
                if not wifi_row.empty:
                    algo_val = wifi_row[algo_col].values[0]
                    solution_val = wifi_row[solution_col].values[0]
                    gain_wifi = calculate_gain(algo_val, solution_val)
                    gains_wifi.append(gain_wifi)
                else:
                    gains_wifi.append(0)

                # # Data for mobile
                # mobile_row = algo_data[algo_data['env'] == 'mobile']
                # if not mobile_row.empty:
                #     algo_val = mobile_row[algo_col].values[0]
                #     solution_val = mobile_row[solution_col].values[0]
                #     gain_mobile = calculate_gain(algo_val, solution_val)
                #     gains_mobile.append(gain_mobile)
                # else:
                #     gains_mobile.append(0)
                
                # labels.append(period.replace('min', ' min'))
            
            # CORRECTION : Créer un graphique avec 4 barres côte à côte
            x = np.arange(len(labels))
            width = 0.2  # Réduire la largeur pour faire place aux 4 barres
            
            # Positionner les 4 barres côte à côte
            bars1 = ax.bar(x - 1.5*width, gains_fibre, width, label='Fibre', alpha=0.8, color='skyblue')
            bars2 = ax.bar(x - 0.5*width, gains_datacenter, width, label='Datacenter', alpha=0.8, color='lightcoral')
            bars3 = ax.bar(x + 0.5*width, gains_wifi, width, label='Wi-Fi', alpha=0.8, color='mediumseagreen')
            bars4 = ax.bar(x + 1.5*width, gains_mobile, width, label='Mobile', alpha=0.8, color='orange')
            bars5 = ax.bar(x + 1.5*width, gains_mobile, width, label='Wi-Fi_limit', alpha=0.8, color='orange')
            bars6 = ax.bar(x + 1.5*width, gains_mobile, width, label='Fibre2', alpha=0.8, color='orange')
            bars7 = ax.bar(x + 1.5*width, gains_mobile, width, label='Fibre_limit', alpha=0.8, color='orange')

            
            # Customize the chart
            ax.set_xlabel('Time period')
            ax.set_ylabel('Gain (%)')
            ax.set_title(f'{metric.title()} - Solution vs {algo.upper()}')
            ax.set_xticks(x)
            ax.set_xticklabels(labels)
            ax.legend(loc='best', fontsize=8)  # Réduire la taille de la légende
            ax.grid(True, alpha=0.3)
            ax.axhline(y=0, color='black', linestyle='-', linewidth=0.5)
            
            # Invert Y-axis for SRTT (lower values are better)
            if metric == 'srtt':
                ax.invert_yaxis()
            
            # Add value labels on bars (optionnel car ça peut être illisible avec 4 barres)
            def add_value_labels(bars, size=7):
                for bar in bars:
                    height = bar.get_height()
                    if abs(height) > 1:  # Afficher seulement si la valeur est significative
                        ax.annotate(f'{height:.0f}%',
                                xy=(bar.get_x() + bar.get_width() / 2, height),
                                xytext=(0, 3 if height >= 0 else -15),
                                textcoords="offset points",
                                ha='center', va='bottom' if height >= 0 else 'top',
                                fontsize=size)
            
            # Ajouter les labels avec une taille réduite
            add_value_labels(bars1)
            add_value_labels(bars2)
            add_value_labels(bars3)
            add_value_labels(bars4)

    plt.tight_layout()
    plt.savefig(f'auto_gains_comparison_{file_name}3.png', dpi=300, bbox_inches='tight')
    print(f"Detailed chart saved as 'auto_gains_comparison_{file_name}3.png'")













# =============================================================================
# GLOBAL COMPARISON CHART
# =============================================================================

# Calculate all gains for global view
all_gains = {}

for algo in total_algos:
    all_gains[algo] = []
    
    for metric in metrics:
        algo_data = df[(df['algo'] == algo) & (df['metric'] == metric)]
        
        for env in environments:
            env_data = algo_data[algo_data['env'] == env]
            
            for period in time_periods:
                if not env_data.empty:
                    algo_col = f'{period}_algo'
                    solution_col = f'{period}_solution'
                    
                    algo_val = env_data[algo_col].values[0]
                    solution_val = env_data[solution_col].values[0]
                    gain = calculate_gain(algo_val, solution_val)
                    
                    # Invert gain for SRTT (lower is better)
                    if metric == 'srtt':
                        gain = -gain
                    
                    all_gains[algo].append(gain)

# Calculate average gains for each algorithm
avg_gains = {}
for algo in total_algos:
    avg_gains[algo] = np.mean(all_gains[algo])

# Calculate overall average
overall_avg = np.mean(list(avg_gains.values()))

# Create the global comparison chart
fig2, ax2 = plt.subplots(1, 1, figsize=(10, 8))

# Prepare data for plotting
labels = [algo.upper() for algo in total_algos] + ['OVERALL\nAVERAGE']
values = list(avg_gains.values()) + [overall_avg]
colors = ['lightblue', 'lightgreen', 'lightcoral', 'gold']

# Create bar chart
bars = ax2.bar(labels, values, color=colors, alpha=0.8, edgecolor='black', linewidth=1)

# Customize the chart
ax2.set_ylabel('Average Gain (%)', fontsize=12)
ax2.set_title('Global Performance Comparison - Average Gains', fontsize=14, fontweight='bold')
ax2.grid(True, alpha=0.3, axis='y')
ax2.axhline(y=0, color='black', linestyle='-', linewidth=1)

# Add value labels on bars
for bar in bars:
    height = bar.get_height()
    ax2.annotate(f'{height:.1f}%',
               xy=(bar.get_x() + bar.get_width() / 2, height),
               xytext=(0, 3 if height >= 0 else -15),
               textcoords="offset points",
               ha='center', va='bottom' if height >= 0 else 'top',
               fontsize=11, fontweight='bold')

# Add some styling
y_min = min(values)
y_max = max(values)
y_range = y_max - y_min

# Ensure we have a reasonable range for visualization
if y_range < 5:  # If the range is too small, expand it
    y_padding = 5
else:
    y_padding = y_range * 0.2

ax2.set_ylim(y_min - y_padding, y_max + y_padding)

plt.tight_layout()

# Save the global chart
plt.savefig('auto_global_comparison3.png', dpi=300, bbox_inches='tight')
print("Global comparison chart saved as 'auto_global_comparison3.png'")

# Print summary statistics
print("\nGlobal Performance Summary:")
print("=" * 40)
for algo in algorithms:
    print(f"{algo.upper()}: {avg_gains[algo]:.2f}% average gain")
print(f"OVERALL: {overall_avg:.2f}% average gain")
print("=" * 40)
#plt.show()