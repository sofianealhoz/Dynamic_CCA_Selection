import { Component, computed, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { Router } from '@angular/router';

import { BenchmarkService } from './benchmark.service';
import { BenchmarkRun, NetworkType } from './benchmark.model';
import { RunsTable, SortKey } from './runs-table';

/**
 * Version 2 : l'etat vit dans le composant, dans des signals.
 * Un signal est une valeur lue avec (), et toute vue qui la lit se remet a jour
 * quand elle change. Equivalent exact de ref() en Vue et de useState en React.
 *
 * Brique 5 : etat STOCKE (la source + les choix de l'utilisateur)
 * vs etat DERIVE (la liste affichee), jamais stocke, toujours recalcule.
 */
@Component({
  selector: 'runs-signals',
  imports: [RunsTable],
  template: `
    <h2>Version signals</h2>
    <button (click)="load()">Recharger</button>

    <p>
      <input
        placeholder="filtrer par algorithme"
        [value]="ccaFilter()"
        (input)="ccaFilter.set($any($event.target).value)"
      />
      <select [value]="networkFilter()" (change)="networkFilter.set($any($event.target).value)">
        <option value="all">tous les reseaux</option>
        <option value="datacenter">datacenter</option>
        <option value="wi-fi">wi-fi</option>
        <option value="mobile">mobile</option>
      </select>
    </p>

    @if (loading()) {
      <p>Chargement des runs...</p>
    } @else if (error()) {
      <p class="error">{{ error() }} <button (click)="load()">Reessayer</button></p>
    } @else if (runs().length === 0) {
      <p>Aucun run enregistre.</p>
    } @else if (visibleRuns().length === 0) {
      <p>Aucun run ne correspond au filtre. <button (click)="resetFilters()">Reinitialiser</button></p>
    } @else {
      <runs-table
        [runs]="visibleRuns()"
        [sortKey]="sortKey()"
        [sortDir]="sortDir()"
        (select)="openDetail($event)"
        (sortBy)="toggleSort($event)"
      />
    }
  `,
})
export class RunsSignals {
  private readonly benchmarks = inject(BenchmarkService);
  private readonly destroyRef = inject(DestroyRef);
  private readonly router = inject(Router);

  // ---- Etat STOCKE : rien de tout cela ne peut etre recalcule.
  readonly loading = signal(true);
  readonly error = signal<string | null>(null);
  readonly runs = signal<BenchmarkRun[]>([]);
  readonly ccaFilter = signal('');
  readonly networkFilter = signal<NetworkType | 'all'>('all');
  readonly sortKey = signal<SortKey>('cca');
  readonly sortDir = signal<'asc' | 'desc'>('asc');

  // ---- Etat DERIVE : une fonction des signaux ci-dessus.
  // computed relit ses dependances tout seul ; aucune liste a declarer
  // (difference avec useMemo en React), et impossible d'oublier de recalculer.
  readonly visibleRuns = computed(() => {
    const needle = this.ccaFilter().trim().toLowerCase();
    const network = this.networkFilter();
    const key = this.sortKey();
    const direction = this.sortDir() === 'asc' ? 1 : -1;

    return this.runs()
      .filter((run) => run.cca.toLowerCase().includes(needle))
      .filter((run) => network === 'all' || run.network === network)
      // sort() modifie le tableau en place : trier runs() directement corromprait
      // la source. filter() a deja renvoye une copie, donc ici c'est sans risque.
      .sort((a, b) => {
        const left = a[key];
        const right = b[key];
        return (left < right ? -1 : left > right ? 1 : 0) * direction;
      });
  });

  constructor() {
    this.load();
  }

  // Clic sur une colonne : meme colonne = on inverse le sens, autre colonne = on repart croissant.
  toggleSort(key: SortKey): void {
    if (this.sortKey() === key) {
      this.sortDir.update((dir) => (dir === 'asc' ? 'desc' : 'asc'));
    } else {
      this.sortKey.set(key);
      this.sortDir.set('asc');
    }
  }

  resetFilters(): void {
    this.ccaFilter.set('');
    this.networkFilter.set('all');
  }

  openDetail(run: BenchmarkRun): void {
    this.router.navigate(['/runs', run.id]);
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
