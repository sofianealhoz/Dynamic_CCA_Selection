# Project Overview

- Dynamic optimization of **TCP Congestion Control Algorithm (CCA)**
- Combines:
  - **eBPF** for low-level kernel monitoring & control
  - **Machine Learning** for real-time network type prediction
- Fully automated, **real-time process**

---

## Step 1 – Detecting New Connections (`event_listener.py`)

- Persistent **Python listener service**
- eBPF attached to kernel function: `tcp_ack`
- **Filters** connections on port `5201`
- On new connection:
  - Extracts **destination IP**
  - If IP not yet processed:
    - Triggers analysis with **subprocesses**

---

## Step 2 – Collecting TCP Metrics (`get_socket_data.py`)

- Launches **detailed eBPF probe**
- Attached to `tcp_ack`
- Extracts ~20 advanced TCP metrics:
  - **Latency**: `srtt`, `rtt`, `min_rtt`, `mdev`
  - **Loss**: `lost`, `retrans_out`, `sack_out`
  - **Congestion**: `snd_cwnd`, `inflight`
  - **Throughput**: `sk_pacing_rate`, `delivered`
- **Sampling**:
  - Every 100ms
  - Duration: 15 seconds
- Saves data to: `data_prod.csv`

---

## Step 3 – Network Type Prediction (`predict_cca.py`)

- Loads ML model: `trained_classifier.pkl`
- Model trained with `RandomForest` on labeled dataset
- Processes input data:
  - Cleans, encodes, formats like training set
- Runs inference on samples
- Final prediction = **most frequent** network type:
  - `fiber`, `wifi`, `mobile`, `datacenter`

---

## Step 4 – Updating eBPF Map (`predict_cca.py`)

- Maps network type → optimal CCA:
  - `wifi` → `cubic`
  - `fiber` → `bbr`
  - `mobile` → `bbr`
  - `datacenter` → `dctcp`
- Accesses pinned map: `/sys/fs/bpf/key_cong_map`
- Writes:
  - **Key**: IP address
  - **Value**: CCA name (e.g., `"bbr"`)

---

## Step 5 – Applying the CCA (eBPF Kernel Programs)

### Files: `load_sock_ops.c`, `tcp_changecc_kern.c`

- eBPF program of type `sock_ops`
- **Loaded at boot**, attached to a `cgroup`
- Triggered on: `BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB`
- For each new TCP connection:
  - Looks up IP in `key_cong_map`
  - If found:
    - Applies CCA using `bpf_setsockopt()`
  - Else:
    - Uses **system default CCA**

---
