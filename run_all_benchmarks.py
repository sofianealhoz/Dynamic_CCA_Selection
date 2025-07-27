#!/usr/bin/env python3

import subprocess
import time
import sys
import os
import tempfile
from datetime import datetime

def run_all_benchmarks():
    """
    Orchestrateur pour tous les benchmarks
    """

    bench_type = "c"
    durations = [1, 3, 5]  # minutes
    algos = ["bbr", "bbr2", "cubic", "dctcp", "highspeed", "hybla", 
             "illinois", "reno", "scalable", "vegas", "westwood", "yeah", "sol"]
   
    #####################################
    #####################################

    env = "datacenter"
    
    #####################################
    #####################################


    
    
    total_tests = len(durations) * len(algos)
    current_test = 0
    
    print(f" Starting {total_tests} benchmarks")
    print(f"⏱  Durations: {durations} minutes")
    print(f" Algorithms: {algos}")
    print(f" Environment: {env}")
    print(f" Type: {bench_type}")
    print("=" * 70)
    
    

    
    for duration_min in durations:
        for algo in algos:
            current_test += 1
            
            if algo == "sol":
                bench_type = "s"
                algo = "cubic"

            print(f"\n Test {current_test}/{total_tests}")
            print(f"Algorithm: {algo}")
            print(f"Duration: {duration_min} minutes")
            print("-" * 50)
            
            # Créer un event_listener modifié pour ce test
            call_event_listener(str(bench_type), str(duration_min), str(algo), str(env))
            
            start_time = datetime.now()
            
             # NOUVEAU : Changer le CCA système
            print(f"🔄 Preparing system for {algo}...")
            

            
            # Changer le CCA système
            if not set_default_congestion_control(algo):
                print(f"⚠️  Could not set {algo} as default, continuing anyway...")
                # On continue quand même car le BPF peut forcer l'algorithme

            # 3. Délai supplémentaire
            print(f"⏳ Final preparation (2s)...")
            time.sleep(2)

            # Vérifier que le changement a pris effet
            current_cca = verify_congestion_control()
            try:
                print(f"🔄 Starting event_listener...")
                print(f"💡 Please run: iperf3 -c <target_ip> -p 5201 -t {duration_min * 60}")
                
                # Lancer event_listener avec timeout
                timeout_seconds = (duration_min * 60) + 120  # +2min marge
                

                
                end_time = datetime.now()
                duration_actual = (end_time - start_time).total_seconds()
                
                
            except subprocess.TimeoutExpired:
                print(f"{algo} - {duration_min}min TIMEOUT after {timeout_seconds}s")
                
                    
            except KeyboardInterrupt:
                print(f"\n⏸️  Interrupted by user")
                choice = input("Continue with next test? (y/n): ")
                if choice.lower() != 'y':
                    print(" Stopping all tests")
                    break
                    
            except Exception as e:
                print(f" Unexpected error: {e}")
               
            

            
            # Pause entre tests pour stabilité
            if current_test < total_tests:
                print(f" Waiting 20s before next test...")
                time.sleep(20)
    
    print(f"\n Benchmark suite completed!")
    print(f" Generate graphs with: python3 graph.py")


def set_default_congestion_control(algo):
    """
    Changer l'algorithme de contrôle de congestion par défaut du système
    """
    try:
        print(f"🔧 Setting system default CCA to: {algo}")
        
        # Commande pour changer l'algorithme par défaut
        cmd = ["sudo", "sysctl", "-w", f"net.ipv4.tcp_congestion_control={algo}"]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            print(f"✅ System CCA changed to: {algo}")

            # NOUVEAU : Délai pour stabilisation
            print(f" Waiting 3s for CCA stabilization...")
            time.sleep(3)

            return True
        else:
            print(f"❌ Failed to change CCA: {result.stderr}")
            return False
            
    except subprocess.TimeoutExpired:
        print(f" Timeout setting CCA to {algo}")
        return False
    except Exception as e:
        print(f" Error setting CCA: {e}")
        return False

def verify_congestion_control():
    """
    Vérifier quel est l'algorithme actuellement configuré
    """
    try:
        result = subprocess.run(
            ["sysctl", "net.ipv4.tcp_congestion_control"],
            capture_output=True, text=True, timeout=5
        )
        
        if result.returncode == 0:
            current_cca = result.stdout.strip().split('=')[1].strip()
            print(f" Current system CCA: {current_cca}")
            return current_cca
        else:
            print(f"❌ Could not verify current CCA")
            return None
            
    except Exception as e:
        print(f" Error verifying CCA: {e}")
        return None

def call_event_listener(bench_type, duration_min, algo, env):
    """
    Créer un event_listener temporaire avec les bons paramètres
    """
    try:
        subprocess.run(
                ["python3", "event_listener.py", bench_type, duration_min, algo, env],  # ← Nom correct
                check=True, timeout=20
            )
        print("   Modification finished.")
        
    except Exception as e:
            print(f"   ❌ An error occured durung the process: {e}")

    
    return 

if __name__ == "__main__":
    run_all_benchmarks()