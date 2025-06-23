Project Overview
	•	Dynamic optimization of TCP Congestion Control Algorithm (CCA)
	•	Based on:
	•	eBPF for kernel-level monitoring and action
	•	Machine Learning to predict network type
	•	Fully real-time, no manual intervention

⸻

Step 1 – Detecting New Connection (event_listener.py)
	•	Persistent Python listener script
	•	eBPF attached to tcp_ack
	•	Port filter: listens only on port 5201 (e.g., iperf3 traffic)
	•	Extracts destination IP
	•	If IP is new:
	•	Triggers analysis via subprocesses

⸻

Step 2 – Collecting Connection Metrics (get_socket_data.py)
	•	Loads a detailed eBPF probe
	•	Also hooked to tcp_ack
	•	TCP metrics collected:
	•	Latency: srtt, rtt, min_rtt, mdev
	•	Loss: lost, retrans_out, sack_out
	•	Congestion: snd_cwnd, inflight
	•	Throughput: sk_pacing_rate, delivered
	•	Sampling: every 100ms for 15s
	•	Saves to: data_prod.csv

⸻

Step 3 – Network Type Prediction (predict_cca.py)
	•	Loads pre-trained ML model (trained_classifier.pkl)
	•	Trained with RandomForest on labeled data
	•	Preprocessing input data (encoding, formatting)
	•	Per-sample predictions
	•	Majority vote → final network type:
fiber, wifi, mobile, datacenter

⸻

Step 4 – Updating eBPF Map with CCA (predict_cca.py)
	•	Mapping network type → CCA:
	•	wifi → cubic
	•	fiber, mobile → bbr
	•	datacenter → dctcp
	•	Accesses pinned eBPF map: /sys/fs/bpf/key_cong_map
	•	Writes:
	•	Key = IP
	•	Value = recommended CCA (e.g., "bbr")

⸻

Step 5 – Applying the CCA (load_sock_ops.c, tcp_changecc_kern.c)
	•	eBPF sock_ops loaded on boot
	•	Attached to a cgroup
	•	Runs on BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB
	•	Looks up IP in key_cong_map
	•	If match found:
	•	Uses bpf_setsockopt() to apply specific CCA
	•	If not: default system CCA is used
