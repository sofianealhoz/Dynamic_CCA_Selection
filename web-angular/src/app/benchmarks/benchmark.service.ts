import { Injectable } from '@angular/core';
import { Observable, of, throwError } from 'rxjs';
import { delay } from 'rxjs/operators';

import { BENCHMARK_RUNS } from './benchmark.data';
import { BenchmarkRun } from './benchmark.model';

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
