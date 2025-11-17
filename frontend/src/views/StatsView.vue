<script setup>
import { onMounted, ref } from "vue";
import { fetchRuns, launchRun } from "@/services/benchmarks";

const runs = ref([]);
const loading = ref(false);
const error = ref("");

async function loadRuns() {
  loading.value = true;
  error.value = "";
  try {
    runs.value = await fetchRuns();
  } catch (err) {
    error.value = err.response?.data?.detail || err.message;
  } finally {
    loading.value = false;
  }
}

async function handleLaunch(profileId) {
  await launchRun({ profile_id: profileId });
  await loadRuns(); // rafraîchir la liste après le POST
}

onMounted(loadRuns);
</script>

<template>
  <section>
    <header class="flex gap-2 items-center">
      <h1>Benchmarks</h1>
      <button @click="loadRuns" :disabled="loading">↻</button>
    </header>

    <p v-if="error" class="error">{{ error }}</p>
    <p v-else-if="!runs.length">Aucun run</p>

    <table v-else>
      <thead>
        <tr>
          <th>Profil</th>
          <th>Utilisateur</th>
          <th>Status</th>
          <th>Créé</th>
          <th>Artefacts</th>
        </tr>
      </thead>
      <tbody>
        <tr v-for="run in runs" :key="run.run_id">
          <td>{{ run.profile }}</td>
          <td>{{ run.launched_by }}</td>
          <td>{{ run.status }}</td>
          <td>{{ run.created_at }}</td>
          <td>
            <a v-for="artifact in run.artifacts" :key="artifact.path" :href="artifact.path" target="_blank">
              {{ artifact.kind }}
            </a>
          </td>
        </tr>
      </tbody>
    </table>

    <button @click="handleLaunch('westwood_fibre')">Lancer Westwood Fibre</button>
  </section>
</template>

<style scoped>
.error { color: red; }
table { width: 100%; border-collapse: collapse; }
td, th { padding: 0.4rem; border-bottom: 1px solid #ccc; }
</style>
