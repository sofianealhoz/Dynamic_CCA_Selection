import { Routes } from '@angular/router';

import { RunsPage } from './benchmarks/runs-page';
import { RunDetail } from './benchmarks/run-detail';
import { RunForm } from './benchmarks/run-form';

/**
 * Table des routes : un motif d'URL -> un composant.
 * L'ordre compte, la 1re route dont le motif correspond gagne.
 */
export const routes: Routes = [
  // pathMatch full : ne rediriger que si l'URL est vide en entier.
  { path: '', redirectTo: 'runs', pathMatch: 'full' },
  { path: 'runs', component: RunsPage },
  // AVANT runs/:id : sinon 'new' serait capture comme un identifiant.
  { path: 'runs/new', component: RunForm },
  // :id est un segment variable, extrait de l'URL et lu via ActivatedRoute.
  { path: 'runs/:id', component: RunDetail },
  // ** = tout le reste, donc toujours en dernier.
  { path: '**', redirectTo: 'runs' },
];
