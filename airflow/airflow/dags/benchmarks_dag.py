from __future__ import annotations
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import shutil

from airflow import DAG
from airflow.operators.python import PythonOperator


REPO_ROOT = Path("/home/sofiane/Dynamic_CCA_Selection")
PNG_SOURCE = REPO_ROOT
PNG_TARGET = REPO_ROOT / "artifacts" / "png_exports"

def run_benchmarks():
    subprocess.run(
        ["python3", str(REPO_ROOT / "run_all_benchmarks.py")],
        check=True,
        cwd=REPO_ROOT,
    )

def collect_pngs():
    PNG_TARGET.mkdir(parents=True, exist_ok=True)
    for png in PNG_SOURCE.glob("auto_algorithms_values_comparison_*.png"):
        target = PNG_TARGET / png.name
        shutil.copy2(png, target)

dag = DAG(
    dag_id="benchmarks_png_pipeline",
    schedule_interval=None,
    start_date=datetime(2026, 1, 1),
    catchup=False,
    default_args={
        "owner": "airflow",
        "retry_delay": timedelta(minutes=5),
        "depends_on_past": False,
        "email_on_failure": False,
    },
)

run = PythonOperator(
    task_id="run_benchmarks",
    python_callable=run_benchmarks,
    dag=dag,
)

gather = PythonOperator(
    task_id="collect_pngs",
    python_callable=collect_pngs,
    dag=dag,
)

run >> gather