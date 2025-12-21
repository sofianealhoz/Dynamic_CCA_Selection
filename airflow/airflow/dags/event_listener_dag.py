from datetime import datetime, timedelta
from pathlib import Path

from airflow import DAG
from airflow.operators.bash import BashOperator
from airflow.operators.python import PythonOperator

REPO = Path("/home/sofiane/Dynamic_CCA_Selection")
BPF_DIR = REPO / "samples/bpf"

default_args = {
    "owner": "airflow",
    "retry_delay": timedelta(minutes=5),
    "depends_on_past": False,
}

with DAG(
    dag_id="bpf_preparation",
    schedule_interval=None,
    start_date=datetime(2025, 1, 1),
    catchup=False,
    default_args=default_args,
) as dag:
    
    compile_bpf = BashOperator(
        task_id="compile_bpf",
        bash_command=(
            f"cd {REPO} && "
            "clang -O2 -g -target bpf -D__TARGET_ARCH_x86 "
            "-c tcp_changecc_kern.c -o samples/bpf/tcp_changecc_kern.o"
        ),
    )

    load_sock_ops =  BashOperator(
        task_id="run_load_sock_ops",
        bash_command=(
            f"cd {REPO} && "
            "python3 load_sock_ops.py /tmp/cgroupv2/foo samples/bpf/tcp_changecc_kern.o"
        ),
    )

    attach_prog = PythonOperator(
        task_id="attach_bpf",
        python_callable=attach_bpf,
    )

    compile_bpf >> load_sock_ops >> attach_prog
