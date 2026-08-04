import { Component } from '@angular/core';
import { RouterOutlet } from '@angular/router';

/**
 * Coquille de l'application : ce qui ne change jamais (le titre),
 * plus l'emplacement ou le routeur monte le composant de la route courante.
 */
@Component({
  selector: 'app-root',
  imports: [RouterOutlet],
  templateUrl: './app.html',
  styleUrl: './app.css'
})
export class App {}
