import { BenchmarkRun } from './benchmark.model';

/**
 * Les etats possibles d'un affichage asynchrone, rendus explicites.
 * Union discriminee : le champ status dit lequel des trois cas on tient,
 * et TypeScript refuse de lire runs tant qu'on n'a pas teste status === 'ready'.
 * Le 4e etat (vide) n'est pas un etat du chargement : c'est ready avec runs.length === 0.
 */
export type RunsViewState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; runs: BenchmarkRun[] };
