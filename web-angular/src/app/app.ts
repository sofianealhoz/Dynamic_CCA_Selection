import { Component, inject } from '@angular/core';

import { BenchmarkService } from './benchmarks/benchmark.service';
import { RunsAsync } from './benchmarks/runs-async';
import { RunsSignals } from './benchmarks/runs-signals';

@Component({
  selector: 'app-root',
  imports: [RunsAsync, RunsSignals],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {
  readonly benchmarks = inject(BenchmarkService);

  // Leviers de demo : ils changent ce que renverra le PROCHAIN appel au service.
  setFail(value: boolean): void {
    this.benchmarks.failNext = value;
  }

  setEmpty(value: boolean): void {
    this.benchmarks.returnEmpty = value;
  }
}
