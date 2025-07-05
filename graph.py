import pandas as pd
import matplotlib.pyplot as plt
import numpy as np

# Configure matplotlib to not use interactive display
plt.ioff()

# Read the data file
df = pd.read_csv('benchmark_data_troughput_and_srtt.csv')

# Function to calculate gain percentage
def calculate_gain(algo_value, solution_value):
    return ((solution_value - algo_value) / algo_value) * 100

# Prepare data for graphs
algorithms = ['cubic', 'bbr', 'reno']
environments = ['fibre', 'datacenter']
metrics = ['throughput', 'srtt']
time_periods = ['1min', '5min', '10min']

# =============================================================================
# DETAILED COMPARISON CHART
# =============================================================================

# Create figure with subplots
fig, axes = plt.subplots(2, 3, figsize=(18, 12))
fig.suptitle("Solution's gain", fontsize=16)

for i, metric in enumerate(metrics):
    for j, algo in enumerate(algorithms):
        ax = axes[i, j]
        
        # Filter data for current algorithm and metric
        algo_data = df[(df['algo'] == algo) & (df['metric'] == metric)]
        
        gains_fibre = []
        gains_datacenter = []
        labels = []
        
        for period in time_periods:
            algo_col = f'{period}_algo'
            solution_col = f'{period}_solution'
            
            # Data for fibre
            fibre_row = algo_data[algo_data['env'] == 'fibre']
            if not fibre_row.empty:
                algo_val = fibre_row[algo_col].values[0]
                solution_val = fibre_row[solution_col].values[0]
                gain_fibre = calculate_gain(algo_val, solution_val)
                gains_fibre.append(gain_fibre)
            else:
                gains_fibre.append(0)
            
            # Data for datacenter
            datacenter_row = algo_data[algo_data['env'] == 'datacenter']
            if not datacenter_row.empty:
                algo_val = datacenter_row[algo_col].values[0]
                solution_val = datacenter_row[solution_col].values[0]
                gain_datacenter = calculate_gain(algo_val, solution_val)
                gains_datacenter.append(gain_datacenter)
            else:
                gains_datacenter.append(0)
            
            labels.append(period.replace('min', ' min'))
        
        # Create bar chart
        x = np.arange(len(labels))
        width = 0.35
        
        bars1 = ax.bar(x - width/2, gains_fibre, width, label='Fibre', alpha=0.8, color='skyblue')
        bars2 = ax.bar(x + width/2, gains_datacenter, width, label='Datacenter', alpha=0.8, color='lightcoral')
        
        # Customize the chart
        ax.set_xlabel('Time period')
        ax.set_ylabel('Gain (%)')
        ax.set_title(f'{metric.title()} - Solution vs {algo.upper()}')
        ax.set_xticks(x)
        ax.set_xticklabels(labels)
        ax.legend()
        ax.grid(True, alpha=0.3)
        ax.axhline(y=0, color='black', linestyle='-', linewidth=0.5)
        
        # Invert Y-axis for SRTT (lower values are better)
        if metric == 'srtt':
            ax.invert_yaxis()
        
        # Add value labels on bars
        def add_value_labels(bars):
            for bar in bars:
                height = bar.get_height()
                ax.annotate(f'{height:.1f}%',
                           xy=(bar.get_x() + bar.get_width() / 2, height),
                           xytext=(0, 3 if height >= 0 else -15),
                           textcoords="offset points",
                           ha='center', va='bottom' if height >= 0 else 'top',
                           fontsize=9)
        
        add_value_labels(bars1)
        add_value_labels(bars2)

plt.tight_layout()

# Save the detailed chart
plt.savefig('gains_comparison.png', dpi=300, bbox_inches='tight')
print("Detailed chart saved as 'gains_comparison.png'")

# =============================================================================
# GLOBAL COMPARISON CHART
# =============================================================================

# Calculate all gains for global view
all_gains = {}

for algo in algorithms:
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
for algo in algorithms:
    avg_gains[algo] = np.mean(all_gains[algo])

# Calculate overall average
overall_avg = np.mean(list(avg_gains.values()))

# Create the global comparison chart
fig2, ax2 = plt.subplots(1, 1, figsize=(10, 8))

# Prepare data for plotting
labels = [algo.upper() for algo in algorithms] + ['OVERALL\nAVERAGE']
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
plt.savefig('global_comparison.png', dpi=300, bbox_inches='tight')
print("Global comparison chart saved as 'global_comparison.png'")

# Print summary statistics
print("\nGlobal Performance Summary:")
print("=" * 40)
for algo in algorithms:
    print(f"{algo.upper()}: {avg_gains[algo]:.2f}% average gain")
print(f"OVERALL: {overall_avg:.2f}% average gain")
print("=" * 40)
plt.show()