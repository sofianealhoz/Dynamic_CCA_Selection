import { Component, inject } from '@angular/core';
import { RouterLink } from '@angular/router';

import { BenchmarkService } from './benchmark.service';
import { RunsAsync } from './runs-async';
import { RunsSignals } from './runs-signals';

/**
 * Page liste, montee par le routeur sur /runs.
 * Elle assemble les deux ecritures du meme ecran et les leviers de demo.
 */
@Component({
  selector: 'runs-page',
  imports: [RunsAsync, RunsSignals, RouterLink],
  template: `
    <p><a routerLink="/runs/new">Nouveau run</a></p>

    <fieldset>
      <legend>Simuler la reponse du serveur, puis Recharger</legend>
      <label>
        <input type="checkbox" (change)="benchmarks.failNext = $any($event.target).checked" />
        la requete echoue
      </label>
      <label>
        <input type="checkbox" (change)="benchmarks.returnEmpty = $any($event.target).checked" />
        le serveur repond 0 run
      </label>
    </fieldset>

    <div class="columns">
      <section><runs-async /></section>
      <section><runs-signals /></section>
    </div>
  `,
  styles: `
    .columns { display: flex; gap: 2rem; align-items: flex-start; }
    .columns section { flex: 1; border: 1px solid #ccc; padding: 0.5rem 1rem; }
  `,
})
export class RunsPage {
  readonly benchmarks = inject(BenchmarkService);
}
