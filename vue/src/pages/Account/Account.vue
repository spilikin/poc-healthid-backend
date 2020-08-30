<template>
  <div id="app">
    <div id="nav">
      <router-link to="/">Home</router-link>
      <router-link to="/about">Nerdy</router-link>
      <a @click="logout" href="/Account/">Logout</a>
    </div>
    <router-view/>
  </div>
</template>

<script lang="ts">
import { Vue, Component } from 'vue-property-decorator'

import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'
import { BootstrapVue, BootstrapVueIcons } from 'bootstrap-vue'

Vue.use(BootstrapVue)
Vue.use(BootstrapVueIcons)

@Component
export default class App extends Vue {
  logout() {
    localStorage.removeItem('access_token')
  }
}
</script>

<style>
#app {
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;
}

#nav {
  color: white;
  padding: 30px;
  background-color: rgb(37, 104, 231);;
}

#nav a {
  color:white;
  background-color: rgb(113, 156, 235);;
  padding: 1em;
  margin: 0.5em;
  border-radius: 0.5em;
}

#nav a.router-link-exact-active {
  font-weight: bold;
  background-color: white;
  color: rgb(37, 104, 231);;
}
</style>
