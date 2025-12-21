import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from scipy.signal import savgol_filter, correlate
from scipy.fft import fft, fftfreq

def load_and_prep_data(filename):
    """Charge et prépare les données pour l'analyse scientifique."""
    df = pd.read_csv(filename)
    
    # Si les colonnes ne sont pas exactement celles-ci, ajustez-les
    # On suppose ici que le CSV contient 'time', 'srtt', 'throughput'
    # Si throughput n'existe pas, trouver la courbe dont la somme des carrés des écarts entre les points mesurés et la courbe est minimale.on peut le dériver de 'delivered'
    if 'throughput' not in df.columns and 'delivered' in df.columns:
        # Calcul du débit instantané : diff(delivered) / diff(time)
        df['throughput'] = df['delivered'].diff().fillna(0) / df['time'].diff().fillna(0.1)
    
    # Conversion SRTT de microsecondes vers millisecondes pour lisibilité
    df['srtt_ms'] = df['srtt'] / 1000.0
    
    # Normalisation du temps (commencer à t=0)
    df['rel_time'] = df['time'] - df['time'].iloc[0]
    
    return df

def analyze_signal_smoothing(df):
    """
    Applique un filtre de Savitzky-Golay pour débruiter le signal RTT.
    C'est mieux qu'une moyenne mobile car cela préserve les extrema locaux.
    """
    # Window length doit être impair, polyorder est l'ordre du polynôme
    df['srtt_smooth'] = savgol_filter(df['srtt_ms'], window_length=51, polyorder=3)
    
    plt.figure(figsize=(12, 6))
    plt.plot(df['rel_time'], df['srtt_ms'], label='Raw SRTT (Noise)', alpha=0.5, color='gray')
    plt.plot(df['rel_time'], df['srtt_smooth'], label='Savitzky-Golay Filter (Signal)', color='red', linewidth=2)
    plt.title("Extraction du Signal de Latence via Filtrage Polynomial")
    plt.xlabel("Temps (s)")
    plt.ylabel("SRTT (ms)")
    plt.legend()
    plt.grid(True, alpha=0.3)
    plt.savefig('analysis_smoothing.png')
    print("✅ Analyse de lissage terminée (analysis_smoothing.png)")

def analyze_frequency_domain(df, sampling_rate=0.1):
    """
    Effectue une FFT (Fast Fourier Transform) pour détecter les oscillations
    périodiques du débit (caractéristique de TCP Cubic vs BBR).
    """
    # On s'assure d'avoir un signal sans NaN
    signal = df['throughput'].fillna(0).values
    N = len(signal)
    
    # Transformée de Fourier
    yf = fft(signal)
    xf = fftfreq(N, sampling_rate)[:N//2]
    
    # Spectre de puissance (Power Spectrum)
    power = 2.0/N * np.abs(yf[0:N//2])
    
    plt.figure(figsize=(12, 6))
    plt.plot(xf, power)
    plt.title("Analyse Spectrale du Débit (FFT)")
    plt.xlabel("Fréquence (Hz)")
    plt.ylabel("Puissance (Amplitude)")
    plt.grid(True)
    plt.xlim(0, 5) # On regarde les basses fréquences (0-5 Hz)
    
    # Annotation du pic dominant
    peak_freq = xf[np.argmax(power[1:]) + 1] # Ignorer la composante DC (0Hz)
    plt.axvline(x=peak_freq, color='r', linestyle='--', label=f'Fréquence dominante: {peak_freq:.2f} Hz')
    plt.legend()
    
    plt.savefig('analysis_fft.png')
    print(f"✅ Analyse fréquentielle terminée. Fréquence dominante: {peak_freq:.2f} Hz")

def analyze_cross_correlation(df):
    """
    Calcule la corrélation croisée normalisée pour voir si le RTT impacte le débit
    avec un retard (lag).
    """
    # Normalisation (Z-score) pour comparer des unités différentes
    rtt_norm = (df['srtt_ms'] - df['srtt_ms'].mean()) / df['srtt_ms'].std()
    tput_norm = (df['throughput'] - df['throughput'].mean()) / df['throughput'].std()
    
    # Cross-correlation
    lags = np.arange(-len(df) + 1, len(df))
    corr = correlate(rtt_norm, tput_norm, mode='full')
    corr /= len(df) # Normalisation par la taille
    
    # Trouver le lag où la corrélation est maximale (ou minimale inverse)
    max_corr_idx = np.argmax(np.abs(corr))
    optimal_lag = lags[max_corr_idx]
    
    plt.figure(figsize=(12, 6))
    plt.plot(lags, corr)
    plt.title("Corrélation Croisée : RTT vs Throughput")
    plt.xlabel("Décalage (Lag en échantillons)")
    plt.ylabel("Coefficient de Corrélation")
    plt.axvline(x=optimal_lag, color='r', linestyle='--', label=f'Lag optimal: {optimal_lag}')
    plt.legend()
    plt.grid(True)
    plt.savefig('analysis_correlation.png')
    print(f"✅ Analyse de corrélation terminée. Lag optimal: {optimal_lag}")

if __name__ == "__main__":
    # Remplacez par le chemin réel de votre fichier
    FILENAME = "benchmark_data_troughput_and_srtt.csv" 
    
    try:
        print("Chargement des données...")
        # Création d'un dataset dummy si le fichier n'existe pas pour tester
        # df = pd.DataFrame({
        #     'time': np.arange(0, 100, 0.1),
        #     'srtt': np.random.normal(20000, 5000, 1000) + np.sin(np.arange(1000)/10)*5000,
        #     'throughput': np.random.normal(100, 10, 1000) + np.cos(np.arange(1000)/10)*20
        # })
        
        df = load_and_prep_data(FILENAME)
        
        analyze_signal_smoothing(df)
        analyze_frequency_domain(df)
        analyze_cross_correlation(df)
        

        
    except FileNotFoundError:
        print(f"Erreur: Le fichier {FILENAME} n'a pas été trouvé.")
    except Exception as e:
        print(f"Une erreur est survenue: {e}")