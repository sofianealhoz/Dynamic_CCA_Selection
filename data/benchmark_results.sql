CREATE TABLE if not exists benchmark_metrics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    algo VARCHAR(32),
    env VARCHAR(32),
    metric VARCHAR(32),
    period VARCHAR(8),          -- 1min / 3min / 5min / throughput_mbps
    value DOUBLE,
    source VARCHAR(32),         -- algo vs solution
    data_date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE if not exists benchmark_aggregates (
    id INT AUTO_INCREMENT PRIMARY KEY,
    algo VARCHAR(32) NOT NULL,
    env VARCHAR(32) NOT NULL,
    metric VARCHAR(32) NOT NULL,
    period VARCHAR(16) NOT NULL,          -- ex: 1min / 3min / throughput_mbps
    avg_value DOUBLE NOT NULL,
    data_date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    UNIQUE KEY uniq_aggregate (algo, env, metric, period, data_date)
);