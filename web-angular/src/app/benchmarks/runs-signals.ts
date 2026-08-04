import { Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

import { BenchmarkService } from './benchmark.service';
import { BenchmarkRun } from './benchmark.model';
import { RunsTable } from './runs-table';

/**
 * Version 2 : l'etat vit dans le composant, dans des signals.
 * Un signal est une valeur lue avec (), et toute vue qui la lit se remet a jour
 * quand elle change. Equivalent exact de ref() en Vue et de useState en React.
 */
@Component({
  selector: 'runs-signals',
  imports: [RunsTable],
  template: `
    <h2>Version signals</h2>
    <button (click)="load()">Recharger</button>

    @if (selected(); as run) {
      <p>Selection : {{ run.cca }} sur {{ run.network }}</p>
    }

    @if (loading()) {
      <p>Chargement des runs...</p>
    } @else if (error()) {
      <p class="error">{{ error() }} <button (click)="load()">Reessayer</button></p>
    } @else if (runs().length === 0) {
      <p>Aucun run pour ce filtre.</p>
    } @else {
      <runs-table
        [runs]="runs()"
        [selectedId]="selected()?.id ?? null"
        (select)="selected.set($event)"
      />
    }
  `,
})
export class RunsSignals {
  private readonly benchmarks = inject(BenchmarkService);
  private readonly destroyRef = inject(DestroyRef);

  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly runs = signal<BenchmarkRun[]>([]);
  readonly selected = signal<BenchmarkRun | null>(null);

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
