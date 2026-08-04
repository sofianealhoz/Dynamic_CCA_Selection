import { Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { BenchmarkService } from './benchmark.service';
import { BenchmarkRun } from './benchmark.model';

/**
 * Version 2 : l'etat vit dans le composant, dans des signals.
 * Un signal est une valeur lue avec (), et toute vue qui la lit se remet a jour
 * quand elle change. Equivalent exact de ref() en Vue et de useState en React.
 */
@Component({
  selector: 'runs-signals',
  template: `
    <h2>Version signals</h2>
    <button (click)="load()">Recharger</button>

    @if (loading()) {
      <p>Chargement des runs...</p>
    } @else if (error()) {
      <p class="error">{{ error() }} <button (click)="load()">Reessayer</button></p>
    } @else if (runs().length === 0) {
      <p>Aucun run pour ce filtre.</p>
    } @else {
      <table>
        <thead>
          <tr><th>Algorithme</th><th>Reseau</th><th>Debit (Mbps)</th><th>sRTT (ms)</th></tr>
        </thead>
        <tbody>
          @for (run of runs(); track run.id) {
            <tr>
              <td>{{ run.cca }}</td>
              <td>{{ run.network }}</td>
              <td>{{ run.throughputMbps }}</td>
              <td>{{ run.srttMs }}</td>
            </tr>
          }
        </tbody>
      </table>
    }
  `,
})
export class RunsSignals {
  private readonly benchmarks = inject(BenchmarkService);
  private readonly destroyRef = inject(DestroyRef);

  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly runs = signal<BenchmarkRun[]>([]);

  constructor() {
    this.load();
  }

  load(): void {
    // Remettre les trois signaux a plat, sinon l'erreur precedente reste affichee.
    this.loading.set(true);
    this.error.set(null);

    this.benchmarks
      .getRuns()
      // subscribe manuel : c'est a nous de fermer l'abonnement.
      // takeUntilDestroyed le ferme quand le composant est detruit.
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (runs) => {
          this.runs.set(runs);
          this.loading.set(false);
        },
        error: (err: Error) => {
          this.error.set(err.message);
          this.loading.set(false);
        },
      });
  }
}
