import csv
import os
import sys
from socket import inet_ntop, AF_INET, AF_INET6
from struct import pack
import get_socket_data

def clean_ipv6_mapped_addr(addr):
    if addr.startswith("::ffff:"):
        return addr[7:]  
    return addr

def filter_samples_by_ip(samples, target_ip):
    """Filter samples by destination IP"""
    filtered_ipv4 = []
    filtered_ipv6 = []
    
    for sample in samples['ipv4']:
        dest_addr = inet_ntop(AF_INET, pack("I", sample.daddr))
        if dest_addr == target_ip:
            filtered_ipv4.append(sample)
    
    for sample in samples['ipv6']:
        dest_addr = inet_ntop(AF_INET6, sample.daddr)
        dest_addr = clean_ipv6_mapped_addr(dest_addr)
        if dest_addr == target_ip:
            filtered_ipv6.append(sample)
    
    return {'ipv4': filtered_ipv4, 'ipv6': filtered_ipv6}

def write_samples_to_csv(samples, label, target_ip, filename=None):
    """Write filtered samples to CSV file"""
    if filename is None:
        filename = f"data_prod_{target_ip.replace(':', '_')}.csv"
    
    with open(filename, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "label", "connection_id",
            "srtt", "rtt", "mdev", "mdev_max", "rttvar", "min_rtt",
            "inflight", "lost", "recv_rtt", "retrans_out",
            "total_lost", "sack_out", "total_retrans",
            "rcv_buf", "snd_buf", "snd_cwnd",
            "sk_pacing_rate", "sk_max_pacing_rate",
            "delivered"
        ])
        
        # Write IPv4 samples
        for event in samples['ipv4']:
            dest_addr = inet_ntop(AF_INET, pack("I", event.daddr))
            connection_id = dest_addr
            
            writer.writerow([
                label, connection_id, 
                event.srtt, event.rtt, event.mdev, event.mdev_max, event.rttvar, event.min_rtt,
                event.inflight, event.lost, event.recv_rtt, event.retrans_out,
                event.total_lost, event.sack_out, event.total_retrans,
                event.rcv_buf, event.snd_buf, event.snd_cwnd,
                event.sk_pacing_rate, event.sk_max_pacing_rate,
                event.delivered
            ])
        
        # Write IPv6 samples
        for event in samples['ipv6']:
            dest_addr = inet_ntop(AF_INET6, event.daddr)
            dest_addr = clean_ipv6_mapped_addr(dest_addr)
            connection_id = dest_addr
            
            writer.writerow([
                label, connection_id,
                event.srtt, event.rtt, event.mdev, event.mdev_max, event.rttvar, event.min_rtt,
                event.inflight, event.lost, event.recv_rtt, event.retrans_out,
                event.total_lost, event.sack_out, event.total_retrans,
                event.rcv_buf, event.snd_buf, event.snd_cwnd,
                event.sk_pacing_rate, event.sk_max_pacing_rate,
                event.delivered
            ])
        
        csvfile.flush()
        os.fsync(csvfile.fileno())
    
    print(f"Data written to {filename}")
    return filename

def collect_and_write(label, target_ip, duration=15.0):
    """Collect data and write filtered results to CSV"""
    print(f"Starting data collection for {duration}s...")
    
    # Collect all data
    result = get_socket_data.start_collection(duration)
    
    # Filter by target IP
    filtered_samples = filter_samples_by_ip(result, target_ip)
    
    print(f"Filtered samples for {target_ip}: IPv4={len(filtered_samples['ipv4'])}, IPv6={len(filtered_samples['ipv6'])}")
    
    # Write to CSV
    filename = write_samples_to_csv(filtered_samples, label, target_ip)
    
    return filename

# If run as standalone script
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python3 write_socket_data.py <label> <target_ip> [duration]")
        sys.exit(1)
    
    LABEL = sys.argv[1]
    TARGET_IP = sys.argv[2]
    DURATION = float(sys.argv[3]) if len(sys.argv) > 3 else 15.0
    
    filename = collect_and_write(LABEL, TARGET_IP, DURATION)
    print(f"Collection completed. Results saved to {filename}")