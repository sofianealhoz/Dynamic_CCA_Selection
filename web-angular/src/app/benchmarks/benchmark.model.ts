export type NetworkType = 'datacenter' | 'wi-fi' | 'mobile';

export type RunStatus = 'done' | 'running' | 'failed';

/**
 * Erreur metier renvoyee par le serveur, distincte d'une panne reseau.
 * On la modelise pour pouvoir la reconnaitre dans le composant :
 * un 409 se rattache a un champ, un 500 s'affiche en banniere.
 */
export class ConflictError extends Error {
  readonly status = 409;

  constructor(message: string) {
    super(message);
  }
}

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
