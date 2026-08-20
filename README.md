# Dynamic CCA Selection

Server-side selection of the **TCP Congestion Control Algorithm (CCA)** based on the type of network a
client is connecting from, decided per connection and applied in real time.

The repository holds three layers:

| Layer | What it does | Stack |
|---|---|---|
| **Real-time pipeline** | Detects a new connection, samples TCP metrics, predicts the network type, applies the matching CCA in the kernel | Python, eBPF, scikit-learn |
| **Benchmark automation** | Runs the benchmark campaigns, aggregates the results and loads them into a database on a schedule | Apache Airflow, MySQL |
| **Web interface** | Browses benchmark runs, filters and sorts them, opens a run detail, submits a new run | Angular, TypeScript |

---

## Real-time pipeline

### Step 1 - Detecting new connections (`event_listener.py`)

- Persistent **Python listener service**
- eBPF attached to kernel function: `tcp_ack`
- **Filters** connections on port `5201`
- On new connection:
  - Extracts **destination IP**
  - If IP not yet processed:
    - Triggers analysis with **subprocesses**

### Step 2 - Collecting TCP metrics (`get_socket_data.py`)

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

### Step 3 - Network type prediction (`predict_cca.py`)

- Loads ML model: `trained_classifier.pkl`
- Model trained with `RandomForest` on labeled dataset
- Processes input data:
  - Cleans, encodes, formats like training set
- Runs inference on samples
- Final prediction = **most frequent** network type:
  - `fiber`, `wifi`, `mobile`, `datacenter`

### Step 4 - Updating the eBPF map (`predict_cca.py`)

- Maps network type to optimal CCA:
  - `wifi` to `cubic`
  - `fiber` to `bbr`
  - `mobile` to `bbr`
  - `datacenter` to `dctcp`
- Accesses pinned map: `/sys/fs/bpf/key_cong_map`
- Writes:
  - **Key**: IP address
  - **Value**: CCA name (e.g., `"bbr"`)

### Step 5 - Applying the CCA (kernel programs)

Files: `load_sock_ops.c`, `tcp_changecc_kern.c`

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

## Benchmark automation (`airflow/`)

Measuring one CCA against one network type takes minutes and has to be repeated across every
combination, so the campaigns are orchestrated instead of launched by hand.

| DAG | Schedule | Role |
|---|---|---|
| `benchmarks_png_pipeline` | daily, 07:00 | Runs the benchmark campaign and produces the comparison charts |
| `mysql_benchmark_import` | daily | Loads the aggregated results into MySQL |
| `bpf_preparation` | manual trigger | Prepares and loads the kernel programs before a run |

Supporting scripts: `run_all_benchmarks.py`, `aggregate_csv.py`, `calculate_averages.py`, `graph.py`.

---

## Web interface (`web-angular/`)

An Angular application to browse the benchmark runs produced by the pipeline. The matching REST API
lives in `web/` (Django): `GET /api/runs/`, `GET /api/runs/<id>/`, `POST /api/runs/launch/`.

Structure, under `src/app/benchmarks/`:

- **`benchmark.service.ts`** - data layer. No component knows where a run comes from: the service
  returns `Observable`s, so the source can change without touching a single view.
- **`runs-table.ts`** - **reusable presentation component**. It takes a `runs` input and emits a
  `select` output; it knows nothing about the service, nor about what a click leads to. That is what
  makes it reusable across pages.
- **`runs-async.ts` / `runs-signals.ts`** - the same list handled two ways, with the `async` pipe and
  with signals, both covering the four states: loading, error, data and empty.
- **`runs-page.ts`** - filtering and sorting held as derived state rather than duplicated fields.
- **`run-detail.ts`** - detail view routed by an `id` URL parameter.
- **`run-form.ts`** - creation form with client-side validation, and handling of the **409 Conflict**
  the server returns when the same algorithm, network and duration triple already exists. Uniqueness is
  a server rule: the client cannot guarantee it, so it has to handle the refusal.

Run it with `npm install` then `npm start` inside `web-angular/`.

---

## Repository layout

| Path | Contents |
|---|---|
| `*.py`, `*.c` at the root | Real-time pipeline: listener, probes, prediction, kernel programs |
| `airflow/` | DAGs orchestrating the benchmark campaigns |
| `web/` | Django back end exposing the benchmark REST API |
| `web-angular/` | Angular front end |
| `frontend/` | Earlier Vue front end, kept for reference |
| `data/benchmarks/` | Raw benchmark measurements, one file per algorithm, network and duration |
| `data/datasets/` | Training datasets for the classifier |
| `data/` | Aggregated results (`benchmark_data_troughput_and_srtt.csv`), pipeline output and SQL schema |
| `scientific_analysis.py`, `shap_summary_plot.png` | Model analysis and feature importance |

## License

MIT, see `LICENSE`.
