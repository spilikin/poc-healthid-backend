<template>
  <div id="signin">
    <b-alert :show="error != ''" variant="danger" dismissible>
      {{ error }}
    </b-alert>
    <router-view/>
    <p class="mt-3 mb-3 text-muted">No password. No PIN. No cry.<br>
    <small>API Version {{ apiInfo }}</small>
    </p>
  </div>  
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'
import 'bootstrap/dist/css/bootstrap.css'
import 'bootstrap-vue/dist/bootstrap-vue.css'
import { BootstrapVue, BootstrapVueIcons } from 'bootstrap-vue'
import axios from 'axios';

Vue.use(BootstrapVue)
Vue.use(BootstrapVueIcons)

@Component
export default class SignIn extends Vue {
  apiInfo = "unknown"
  error = ""

  mounted() {
    axios.get("/api/info")
      .then(response => (this.apiInfo = response.data.version))
      .catch(reason => {
        console.error(reason)
        this.error = reason
      })

  }

}
</script>

<style>

html,
body {
  height: 100%;
}

#signin {
  width: 100%;
  text-align: center;
  text-align: center;
  font-family: Avenir, Helvetica, Arial, sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  text-align: center;
  color: #2c3e50;

}

body {
  display: -ms-flexbox;
  display: flex;
  -ms-flex-align: center;
  align-items: center;
  padding-top: 40px;
  padding-bottom: 40px;
  background-color: #f5f5f5;
}

.logo {
  width:100%;
  max-width: 170px;
  border-radius: 15px;
}
</style>
