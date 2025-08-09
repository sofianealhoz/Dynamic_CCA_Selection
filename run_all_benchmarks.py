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
    algos = ["sol", "cubic", "bbr", "bbr2", "dctcp", "highspeed", "hybla", 
             "illinois", "reno", "scalable", "vegas", "westwood", "yeah"]
   
    #####################################
    #####################################

    env = "wifi30"
    
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
            else:
                bench_type = "c"


            print(f"\n Test {current_test}/{total_tests}")
            print(f"Algorithm: {algo}")
            print(f"Duration: {duration_min} minutes")
            print("-" * 50)
            

            
            start_time = datetime.now()
            
             # NOUVEAU : Changer le CCA système
            print(f" Preparing system for {algo}...")
            

            
            # Changer le CCA système
            if not set_default_congestion_control(algo):
                print(f"  Could not set {algo} as default, continuing anyway...")
                continue
                # On continue quand même car le BPF peut forcer l'algorithme
            restart_iperf3_server()  # ← AJOUT

            # 3. Délai supplémentaire
            #print(f" Final preparation (2s)...")
            #time.sleep(2)

            # Vérifier que le changement a pris effet
            #current_cca = verify_congestion_control()
            
            print(f" Starting event_listener...")
            try:
                print(f" Please run: iperf3 -c <target_ip> -p 5201 -t {duration_min * 60}")
                
                # Lancer event_listener avec le CCA déjà configuré
                success = call_event_listener(str(bench_type), str(duration_min), str(algo), str(env))
                
                end_time = datetime.now()
                duration_actual = (end_time - start_time).total_seconds()
                
                if success:
                    print(f"✅ {algo} - {duration_min}min completed in {duration_actual:.1f}s")
                else:
                    print(f"❌ {algo} - {duration_min}min failed")
                    
            except KeyboardInterrupt:
                print(f"\n⏸  Interrupted by user")
                choice = input("Continue with next test? (y/n): ")
                if choice.lower() != 'y':
                    print(" Stopping all tests")
                    break
                    
            except Exception as e:
                print(f" Unexpected error: {e}")
            
            # Pause entre tests
            if current_test < total_tests:
                print(f" Waiting 10s before next test...")
                time.sleep(10)
    
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



def restart_iperf3_server():
    """
    Version qui n'ajoute QUE iperf3 au cgroup
    """
    print(" Restarting iperf3 server...")
    
    # Kill
    try:
        result = subprocess.run(["pkill", "-f", "iperf3"], timeout=5)
        if result.returncode == 0:
            print(" iperf3 process killed")
        else:
            print("ℹ  No existing iperf3 process to kill")
    except Exception as e:
        print(f"⚠️  pkill error: {e}")

    time.sleep(3)
    
    # NE PAS ajouter le processus Python au cgroup !
    # Lancer iperf3 puis l'ajouter explicitement
    
    try:
        process = subprocess.Popen([
            "iperf3", "-s", "-p", "5201"
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        
        print(f"✅ iperf3 server started (PID: {process.pid})")
        
        # Ajouter SEULEMENT iperf3 au cgroup
        time.sleep(0.1)  # Laisser iperf3 démarrer
        try:
            cgroup_file = "/tmp/cgroupv2/foo/cgroup.procs"
            if os.path.exists(cgroup_file):
                with open(cgroup_file, "a") as f:
                    f.write(str(process.pid) + "\n")  # ← SEULEMENT iperf3 !
                print(f" ONLY iperf3 process (PID: {process.pid}) added to cgroup")
            else:
                print("  cgroup file not found")
        except Exception as e:
            print(f"  Failed to add iperf3 to cgroup: {e}")
        
        #time.sleep(3)
        return True
        
    except Exception as e:
        print(f"❌ Failed to restart iperf3: {e}")
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
        # Calculer le timeout approprié
        duration_seconds = int(duration_min) * 60
        timeout_seconds = duration_seconds + 120  # +2min de marge
        
        print(f" Starting event_listener (timeout: {timeout_seconds}s)...")
        
        result = subprocess.run(
            ["python3", "event_listener.py", bench_type, duration_min, algo, env],
            timeout=timeout_seconds,  # ← CORRIGÉ
            capture_output=True,
            text=True
        )
        
        if result.returncode == 0:
            print(f"✅ event_listener completed successfully")
            return True
        else:
            print(f"❌ event_listener failed (code: {result.returncode})")
            print(f"   Error: {result.stderr[:200]}...")
            return False
            
    except subprocess.TimeoutExpired:
        print(f" event_listener TIMEOUT after {timeout_seconds}s")
        return False
    except Exception as e:
        print(f" Unexpected error in event_listener: {e}")
        return False

if __name__ == "__main__":
    run_all_benchmarks()