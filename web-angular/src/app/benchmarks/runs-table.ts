import { Component, input, output } from '@angular/core';

import { BenchmarkRun } from './benchmark.model';

/**
 * Composant de presentation pur : il ne connait ni le service, ni l'origine des runs,
 * ni ce qu'on fait d'un clic. Il recoit des donnees et signale une intention.
 * C'est ce qui le rend reutilisable dans les deux colonnes, et demain ailleurs.
 */
@Component({
  selector: 'runs-table',
  template: `
    <table>
      <thead>
        <tr>
          <th>Algorithme</th>
          <th>Reseau</th>
          <th>Debit (Mbps)</th>
          <th>sRTT (ms)</th>
        </tr>
      </thead>
      <tbody>
        @for (run of runs(); track run.id) {
          <tr
            [class.selected]="run.id === selectedId()"
            (click)="select.emit(run)"
          >
            <td>{{ run.cca }}</td>
            <td>{{ run.network }}</td>
            <td>{{ run.throughputMbps }}</td>
            <td>{{ run.srttMs }}</td>
          </tr>
        }
      </tbody>
    </table>
  `,
  styles: `
    tr { cursor: pointer; }
    tr.selected { background: #eef; font-weight: bold; }
  `,
})
export class RunsTable {
  // Entree obligatoire : le parent DOIT fournir les runs, sinon erreur a la compilation.
  readonly runs = input.required<BenchmarkRun[]>();

  // Entree optionnelle avec valeur par defaut : quelle ligne surligner.
  // L'enfant ne decide pas de la selection, il l'affiche.
  readonly selectedId = input<string | null>(null);

  // Sortie : l'enfant signale une intention, il ne modifie rien chez le parent.
  readonly select = output<BenchmarkRun>();
}
