import { createRouter, createWebHashHistory } from 'vue-router'
import HomeView from '../views/HomeView.vue'
import StatsView from '../views/StatsView.vue'

const routes = [
    {path: '/', component: HomeView},
    {path: '/stats', component: StatsView},
]

export default createRouter({
  history: createWebHashHistory(), // hash mode => pas besoin de config côté Django
  routes,
})