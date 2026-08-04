import { Injectable } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';
import { delay } from 'rxjs/operators';

import { BENCHMARK_RUNS } from './benchmark.data';
import { BenchmarkRun, ConflictError, NetworkType } from './benchmark.model';

export interface NewRun {
  cca: string;
  network: NetworkType;
  durationMin: number;
  throughputMbps: number;
  srttMs: number;
}

/**
 * Couche de donnees. Aucun composant ne connait la source des runs.
 * Ici les donnees sont en dur ; brancher une vraie API reviendrait a
 * remplacer of(...) par http.get<BenchmarkRun[]>('/api/runs'), sans toucher aux vues.
 */
@Injectable({ providedIn: 'root' })
export class BenchmarkService {
  // Leviers de demo, pour rendre visibles les etats de la brique 2.
  failNext = false;
  returnEmpty = false;

  /**
   * Simule POST /api/runs. La regle "pas deux fois le meme couple
   * algorithme + reseau + duree" appartient au SERVEUR : le client ne peut
   * pas la garantir, il ne connait pas l'etat complet des donnees.
   */
  createRun(input: NewRun): Observable<BenchmarkRun> {
    const duplicate = BENCHMARK_RUNS.some(
      (run) =>
        run.cca === input.cca &&
        run.network === input.network &&
        run.durationMin === input.durationMin,
    );

    if (duplicate) {
      return throwError(
        () => new ConflictError(`Un run ${input.cca} / ${input.network} / ${input.durationMin} min existe deja`),
      ).pipe(delay(500));
    }

    const created: BenchmarkRun = {
      ...input,
      id: `r-${(BENCHMARK_RUNS.length + 1).toString().padStart(2, '0')}`,
      startedAt: new Date().toISOString(),
      status: 'done',
    };
    BENCHMARK_RUNS.push(created);

    return of(created).pipe(delay(500));
  }

  getRun(id: string): Observable<BenchmarkRun> {
    const found = BENCHMARK_RUNS.find((run) => run.id === id);
    if (!found) {
      return throwError(() => new Error(`Run ${id} introuvable`)).pipe(delay(400));
    }
    return of(found).pipe(delay(400));
  }

  getRuns(): Observable<BenchmarkRun[]> {
    if (this.failNext) {
      return throwError(() => new Error('Le service de benchmarks est injoignable')).pipe(delay(600));
    }
    return of(this.returnEmpty ? [] : BENCHMARK_RUNS).pipe(delay(600));
  }
}
