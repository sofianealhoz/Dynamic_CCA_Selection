import { Component, DestroyRef, inject, signal } from '@angular/core';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router, RouterLink } from '@angular/router';

import { BenchmarkService } from './benchmark.service';
import { ConflictError, NetworkType } from './benchmark.model';

/**
 * Brique 6 : validation CLIENT (confort, immediate, jamais une garantie)
 * et refus METIER du serveur (409), qui ne peut etre connu qu'a l'envoi.
 */
@Component({
  selector: 'run-form',
  imports: [ReactiveFormsModule, RouterLink],
  template: `
    <p><a routerLink="/runs">Retour a la liste</a></p>
    <h2>Nouveau run</h2>

    <form [formGroup]="form" (ngSubmit)="submit()">
      <p>
        <label>Algorithme <input formControlName="cca" /></label>
        @if (form.controls.cca.touched && form.controls.cca.errors; as errors) {
          @if (errors['required']) { <span class="error">obligatoire</span> }
          @else if (errors['minlength']) { <span class="error">2 caracteres minimum</span> }
          <!-- Erreur venue du serveur, posee a la main sur le controle. -->
          @else if (errors['duplicate']) { <span class="error">{{ serverMessage() }}</span> }
        }
      </p>

      <p>
        <label>
          Reseau
          <select formControlName="network">
            <option value="datacenter">datacenter</option>
            <option value="wi-fi">wi-fi</option>
            <option value="mobile">mobile</option>
          </select>
        </label>
      </p>

      <p>
        <label>Duree (min) <input type="number" formControlName="durationMin" /></label>
        @if (form.controls.durationMin.touched && form.controls.durationMin.invalid) {
          <span class="error">entier entre 1 et 60</span>
        }
      </p>

      <p>
        <label>Debit (Mbps) <input type="number" formControlName="throughputMbps" /></label>
        @if (form.controls.throughputMbps.touched && form.controls.throughputMbps.invalid) {
          <span class="error">nombre positif</span>
        }
      </p>

      <p>
        <label>sRTT (ms) <input type="number" formControlName="srttMs" /></label>
      </p>

      <!-- disabled pendant l'envoi : sinon double clic = deux creations. -->
      <button type="submit" [disabled]="form.invalid || sending()">
        {{ sending() ? 'Envoi...' : 'Creer' }}
      </button>

      <!-- Banniere : uniquement pour ce qui ne se rattache a aucun champ. -->
      @if (serverMessage() && !form.controls.cca.hasError('duplicate')) {
        <p class="error">{{ serverMessage() }}</p>
      }
    </form>
  `,
})
export class RunForm {
  private readonly benchmarks = inject(BenchmarkService);
  private readonly router = inject(Router);
  private readonly fb = inject(FormBuilder);
  private readonly destroyRef = inject(DestroyRef);

  readonly sending = signal(false);
  readonly serverMessage = signal<string | null>(null);

  // Validation client : synchrone, pas chere, purement locale.
  readonly form = this.fb.nonNullable.group({
    cca: ['', [Validators.required, Validators.minLength(2)]],
    // Type explicite : sans lui le controle vaut string, et le service
    // qui attend NetworkType refuse la valeur des la compilation.
    network: this.fb.nonNullable.control<NetworkType>('datacenter', Validators.required),
    durationMin: [1, [Validators.required, Validators.min(1), Validators.max(60)]],
    throughputMbps: [0, [Validators.required, Validators.min(0)]],
    srttMs: [0, [Validators.required, Validators.min(0)]],
  });

  submit(): void {
    if (this.form.invalid) {
      return;
    }

    this.sending.set(true);
    this.serverMessage.set(null);

    this.benchmarks
      .createRun(this.form.getRawValue())
      // Meme regle qu'ailleurs : subscribe manuel = abonnement a fermer.
      .pipe(takeUntilDestroyed(this.destroyRef))
      .subscribe({
        next: (created) => {
          this.sending.set(false);
          this.router.navigate(['/runs', created.id]);
        },
        error: (err: Error) => {
          this.sending.set(false);

          if (err instanceof ConflictError) {
            // Refus metier : on le rattache au champ fautif pour que le bouton
            // se reactive seulement quand l'utilisateur change quelque chose.
            this.form.controls.cca.setErrors({ duplicate: true });
            this.form.controls.cca.markAsTouched();
            this.serverMessage.set(err.message);
          } else {
            // Panne : rien a corriger dans le formulaire, message global.
            this.serverMessage.set(err.message);
          }
        },
      });
  }
}
