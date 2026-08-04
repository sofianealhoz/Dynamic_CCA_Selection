import { BenchmarkRun } from './benchmark.model';

// Valeurs inspirees de benchmark_data_troughput_and_srtt.csv (srtt converti de us en ms).
export const BENCHMARK_RUNS: BenchmarkRun[] = [
  { id: 'r-01', cca: 'bbr', network: 'datacenter', durationMin: 1, throughputMbps: 13980, srttMs: 0.2, startedAt: '2025-06-02T09:10:00Z', status: 'done' },
  { id: 'r-02', cca: 'bbr', network: 'wi-fi', durationMin: 5, throughputMbps: 120, srttMs: 177.9, startedAt: '2025-06-02T10:00:00Z', status: 'done' },
  { id: 'r-03', cca: 'bbr', network: 'mobile', durationMin: 5, throughputMbps: 70, srttMs: 171.9, startedAt: '2025-06-02T11:30:00Z', status: 'done' },
  { id: 'r-04', cca: 'bbr2', network: 'datacenter', durationMin: 5, throughputMbps: 13860, srttMs: 0.18, startedAt: '2025-06-03T09:05:00Z', status: 'done' },
  { id: 'r-05', cca: 'bbr2', network: 'wi-fi', durationMin: 1, throughputMbps: 160, srttMs: 188.2, startedAt: '2025-06-03T09:40:00Z', status: 'done' },
  { id: 'r-06', cca: 'cubic', network: 'datacenter', durationMin: 1, throughputMbps: 18660, srttMs: 0.69, startedAt: '2025-06-04T08:15:00Z', status: 'done' },
  { id: 'r-07', cca: 'cubic', network: 'wi-fi', durationMin: 1, throughputMbps: 190, srttMs: 112.2, startedAt: '2025-06-04T09:20:00Z', status: 'done' },
  { id: 'r-08', cca: 'cubic', network: 'mobile', durationMin: 3, throughputMbps: 30, srttMs: 82.8, startedAt: '2025-06-04T10:45:00Z', status: 'done' },
  { id: 'r-09', cca: 'dctcp', network: 'datacenter', durationMin: 5, throughputMbps: 18410, srttMs: 0.71, startedAt: '2025-06-05T09:00:00Z', status: 'done' },
  { id: 'r-10', cca: 'dctcp', network: 'wi-fi', durationMin: 3, throughputMbps: 150, srttMs: 115.6, startedAt: '2025-06-05T09:50:00Z', status: 'done' },
  { id: 'r-11', cca: 'highspeed', network: 'datacenter', durationMin: 3, throughputMbps: 18390, srttMs: 0.73, startedAt: '2025-06-06T08:30:00Z', status: 'done' },
  { id: 'r-12', cca: 'hybla', network: 'wi-fi', durationMin: 3, throughputMbps: 180, srttMs: 99.7, startedAt: '2025-06-06T11:10:00Z', status: 'done' },
  { id: 'r-13', cca: 'illinois', network: 'wi-fi', durationMin: 5, throughputMbps: 130, srttMs: 154.0, startedAt: '2025-06-07T09:15:00Z', status: 'done' },
  { id: 'r-14', cca: 'vegas', network: 'datacenter', durationMin: 5, throughputMbps: 18240, srttMs: 0.7, startedAt: '2025-06-07T14:00:00Z', status: 'running' },
  { id: 'r-15', cca: 'westwood', network: 'mobile', durationMin: 1, throughputMbps: 20, srttMs: 95.4, startedAt: '2025-06-08T08:05:00Z', status: 'failed' },
];
