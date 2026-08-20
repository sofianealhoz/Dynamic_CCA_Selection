from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.providers.mysql.hooks.mysql import MySqlHook
from airflow.providers.mysql.operators.mysql import MySqlOperator

CSV_PATH = Path("/home/sofiane/Dynamic_CCA_Selection/data/benchmark_data_troughput_and_srtt.csv")
CONN_ID = "mysql_benchmarks"

default_args = {
    "owner": "sofiane",
    "depends_on_past": False,
    "retry_delay": timedelta(minutes=5),
    "owner": "sofiane",
    "email": ["sofiane.alhoz@gmail.com"],
    "email_on_failure": True,
    "email_on_retry": False,
}

def load_csv(**context):
    ds = context["ds"]            # date d’exécution Airflow
    df = pd.read_csv(CSV_PATH)
    rows = []

    for _, row in df.iterrows():
        for column in (
            "1min_algo", "3min_algo", "5min_algo",
            "1min_solution", "3min_solution", "5min_solution",
        ):
            if column not in row or pd.isna(row[column]):
                continue
            source = "solution" if "solution" in column else "algo"
            period = column.split("_")[0]
            rows.append(
                (
                    row["algo"],
                    row["env"],
                    row["metric"],
                    period,
                    source,
                    float(row[column]),
                    ds,
                )
            )

    if rows:
        hook = MySqlHook(mysql_conn_id=CONN_ID)
        hook.insert_rows(
            table="benchmark_metrics",
            rows=rows,
            target_fields=["algo", "env", "metric", "period", "source", "value", "data_date"],
        )

def check_threshold(**context):
    hook = MySqlHook(mysql_conn_id=CONN_ID)
    records = hook.get_records("""
        SELECT algo, env, metric, avg_value
        FROM benchmark_aggregates
        WHERE data_date = %s AND avg_value > %s
    """, parameters=(context["ds"], 10000))  # ex seuil 10000
    if records:
        raise ValueError(f"Seuil dépassé : {records}")

with DAG(
    dag_id="mysql_benchmark_import",
    schedule_interval="@daily",
    start_date=datetime(2025, 1, 1),
    catchup=False,
    default_args=default_args,
) as dag:

    extract_and_load = PythonOperator(
        task_id="load_csv_to_mysql",
        python_callable=load_csv,
        provide_context=True,
        retries=2,
        retry_delay=timedelta(minutes=5),
        execution_timeout=timedelta(minutes=10),

    )

    compute_aggregates = MySqlOperator(
        task_id="compute_daily_aggregates",
        mysql_conn_id=CONN_ID,
        sql="""
            INSERT INTO benchmark_aggregates (algo, env, metric, period, avg_value, data_date)
            SELECT algo, env, metric, period, AVG(value), data_date
            FROM benchmark_metrics
            WHERE data_date = '{{ ds }}'
            GROUP BY algo, env, metric, period;
        """,
        retries=1,
        retry_delay=timedelta(minutes=2),
        execution_timeout=timedelta(minutes=5),
    )

    check_threshold_task = PythonOperator(
        task_id="check_threshold",
        python_callable = check_threshold,
        provide_context=True,
    )


    extract_and_load >> compute_aggregates >> check_threshold_task

