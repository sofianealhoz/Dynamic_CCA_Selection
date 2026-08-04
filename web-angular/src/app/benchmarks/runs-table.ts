import { Component, input, output } from '@angular/core';

import { BenchmarkRun } from './benchmark.model';

export type SortKey = 'cca' | 'network' | 'throughputMbps' | 'srttMs';

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
          @for (col of columns; track col.key) {
            <th (click)="sortBy.emit(col.key)">
              {{ col.label }}
              @if (sortKey() === col.key) {
                <span>{{ sortDir() === 'asc' ? '^' : 'v' }}</span>
              }
            </th>
          }
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
    th { cursor: pointer; user-select: none; }
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

  // Entrees d'affichage du tri : la table AFFICHE l'ordre courant, elle ne le decide pas
  // et elle ne trie pas elle-meme. Elle recoit deja les lignes dans le bon ordre.
  readonly sortKey = input<SortKey | null>(null);
  readonly sortDir = input<'asc' | 'desc'>('asc');

  // Sorties : l'enfant signale une intention, il ne modifie rien chez le parent.
  readonly select = output<BenchmarkRun>();
  readonly sortBy = output<SortKey>();

  // Constante de presentation, pas un etat : jamais modifiee.
  readonly columns: { key: SortKey; label: string }[] = [
    { key: 'cca', label: 'Algorithme' },
    { key: 'network', label: 'Reseau' },
    { key: 'throughputMbps', label: 'Debit (Mbps)' },
    { key: 'srttMs', label: 'sRTT (ms)' },
  ];
}
