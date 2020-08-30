import Vue from 'vue'
import SignIn from './SignIn.vue'
import Identity from './views/Identity.vue'
import Authenticate from './views/Authenticate.vue'
import VueRouter, { RouteConfig } from 'vue-router'

Vue.config.productionTip = false

Vue.use(VueRouter)

const routes: Array<RouteConfig> = [
  {
    path: '/',
    name: 'Identity',
    component: Identity
  },
  {
    path: '/Authenticate',
    name: 'Authenticate',
    component: Authenticate
  }
]

const router = new VueRouter({
  mode: 'history',
  base: '/SignIn/',
  routes
})

new Vue({
    router,
    render: h => h(SignIn),
  }).$mount('#app')