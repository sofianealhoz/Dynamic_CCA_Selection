import { Component, inject } from '@angular/core';
import { AsyncPipe } from '@angular/common';
import { Router } from '@angular/router';
import { Observable, of } from 'rxjs';
import { catchError, map, startWith } from 'rxjs/operators';

import { BenchmarkService } from './benchmark.service';
import { BenchmarkRun } from './benchmark.model';
import { RunsTable } from './runs-table';
import { RunsViewState } from './view-state';

/**
 * Version 1 : l'etat vit dans le flux. Le composant ne stocke rien,
 * il decrit une transformation : runs -> etat de vue.
 */
@Component({
  selector: 'runs-async',
  imports: [AsyncPipe, RunsTable],
  template: `
    <h2>Version pipe async</h2>
    <button (click)="reload()">Recharger</button>

    @if (state$ | async; as state) {
      @switch (state.status) {
        @case ('loading') {
          <p>Chargement des runs...</p>
        }
        @case ('error') {
          <p class="error">{{ state.message }} <button (click)="reload()">Reessayer</button></p>
        }
        @case ('ready') {
          @if (state.runs.length === 0) {
            <p>Aucun run pour ce filtre.</p>
          } @else {
            <runs-table [runs]="state.runs" (select)="openDetail($event)" />
          }
        }
      }
    }
  `,
})
export class RunsAsync {
  private readonly benchmarks = inject(BenchmarkService);

  private readonly router = inject(Router);

  state$: Observable<RunsViewState> = this.buildState();

  // La table n'a pas change : elle signale toujours "on a clique sur ce run".
  // Seule l'interpretation change : ce n'est plus un champ local, c'est une URL.
  openDetail(run: BenchmarkRun): void {
    this.router.navigate(['/runs', run.id]);
  }

  private buildState(): Observable<RunsViewState> {
    return this.benchmarks.getRuns().pipe(
      // map : la reponse brute devient l'etat "donnees pretes"
      map((runs): RunsViewState => ({ status: 'ready', runs })),
      // catchError : l'echec devient un etat affichable, pas une exception qui tue le flux
      catchError((err: Error) => of<RunsViewState>({ status: 'error', message: err.message })),
      // startWith : le flux emet "chargement" avant meme que la requete parte
      startWith<RunsViewState>({ status: 'loading' }),
    );
  }

  // Reaffecter le champ cree un nouvel Observable : le pipe async se desabonne
  // de l'ancien et souscrit au nouveau, donc la requete repart.
  reload(): void {
    this.state$ = this.buildState();
  }
}
