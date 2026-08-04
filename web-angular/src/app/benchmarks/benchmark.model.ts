export type NetworkType = 'datacenter' | 'wi-fi' | 'mobile';

export type RunStatus = 'done' | 'running' | 'failed';

export interface BenchmarkRun {
  id: string;
  cca: string;
  network: NetworkType;
  durationMin: number;
  throughputMbps: number;
  srttMs: number;
  startedAt: string;
  status: RunStatus;
}
