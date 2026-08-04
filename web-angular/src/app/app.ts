import { Component, inject } from '@angular/core';
import { AsyncPipe } from '@angular/common';
import { Observable } from 'rxjs';

import { BenchmarkService } from './benchmarks/benchmark.service';
import { BenchmarkRun } from './benchmarks/benchmark.model';

@Component({
  selector: 'app-root',
  imports: [AsyncPipe],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  private readonly benchmarks = inject(BenchmarkService);

  // Un Observable n'execute rien tant que personne ne s'y abonne.
  // Ici c'est le pipe async du template qui declenche l'appel et s'y abonne.
  readonly runs$: Observable<BenchmarkRun[]> = this.benchmarks.getRuns();
}
