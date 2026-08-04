import { Component, inject } from '@angular/core';
import { AsyncPipe } from '@angular/common';
import { ActivatedRoute, RouterLink } from '@angular/router';
import { Observable, of } from 'rxjs';
import { catchError, map, startWith } from 'rxjs/operators';

import { BenchmarkService } from './benchmark.service';
import { BenchmarkRun } from './benchmark.model';

type DetailState =
  | { status: 'loading' }
  | { status: 'error'; message: string }
  | { status: 'ready'; run: BenchmarkRun };

/**
 * Page de detail. Son entree n'est pas une @Input mais l'URL :
 * ce composant est atteignable directement, sans passer par la liste.
 */
@Component({
  selector: 'run-detail',
  imports: [AsyncPipe, RouterLink],
  template: `
    <p><a routerLink="/runs">Retour a la liste</a></p>

    @if (state$ | async; as state) {
      @switch (state.status) {
        @case ('loading') {
          <p>Chargement du run {{ id }}...</p>
        }
        @case ('error') {
          <p class="error">{{ state.message }}</p>
        }
        @case ('ready') {
          <h2>{{ state.run.cca }} sur {{ state.run.network }}</h2>
          <dl>
            <dt>Identifiant</dt><dd>{{ state.run.id }}</dd>
            <dt>Duree</dt><dd>{{ state.run.durationMin }} min</dd>
            <dt>Debit</dt><dd>{{ state.run.throughputMbps }} Mbps</dd>
            <dt>sRTT</dt><dd>{{ state.run.srttMs }} ms</dd>
            <dt>Statut</dt><dd>{{ state.run.status }}</dd>
            <dt>Demarre le</dt><dd>{{ state.run.startedAt }}</dd>
          </dl>
        }
      }
    }
  `,
})
export class RunDetail {
  private readonly benchmarks = inject(BenchmarkService);
  private readonly route = inject(ActivatedRoute);

  // snapshot = photo de l'URL au moment de la construction du composant.
  // Suffisant ici : on ne navigue jamais d'un detail vers un autre detail.
  readonly id = this.route.snapshot.paramMap.get('id') ?? '';

  readonly state$: Observable<DetailState> = this.benchmarks.getRun(this.id).pipe(
    map((run): DetailState => ({ status: 'ready', run })),
    catchError((err: Error) => of<DetailState>({ status: 'error', message: err.message })),
    startWith<DetailState>({ status: 'loading' }),
  );
}
