<template>
  <div id="identity">
    <img class="logo" alt="HealthID" src="@/assets/logo.png">
    <b-form v-on:submit.prevent @submit="onAuthenticate" class="form-signin">
      <h1 class="h3 mb-3 font-weight-normal">Please sign in</h1>
      <b-alert :show="error != ''" variant="danger" dismissible>
      {{ error }}
      </b-alert>
      <div>
        <label for="inputEmail" class="sr-only">Email address</label>
        <input v-model="account" type="email" id="account" class="form-control" placeholder="Enter your HealthID" required autofocus>
        <div class="checkbox mb-3">
          <label>
            <input @change="onRemember" v-model="remember" type="checkbox"> Remember me
          </label>
        </div>
        <button type="submit" class="btn btn-lg btn-primary btn-block">Continue</button>
      </div>
    </b-form>
  </div>  
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'

import QRCode from 'qrcode'
import axios from 'axios';

@Component
export default class Identity extends Vue {
  account = ""
  remember = false
  error = ""

  mounted() {
    this.account = localStorage.getItem("account") || ""
    this.remember = localStorage.getItem("account") != null
  }

  onAuthenticate() {
    console.log('SignIn: '+this.account)
    if (this.remember) {
      localStorage.setItem("account", this.account)
    }
    const baseURL = window.location.protocol + "//" + window.location.host
    let url = ""
    if (window.location.hostname.toLowerCase() == 'acme.spilikin.dev') {
      // running in public environment, use the real appauth server
      url = "https://appauth.acme.spilikin.dev"
    } else {
      url = baseURL
    }
    url += "/api/auth/challenge"
    url += "?acct="+encodeURI(this.account)
    let redirectUri = this.$route.query['redirect_uri']
    if (redirectUri == null) {
      redirectUri = "https://acme.spilikin.dev/Account/"
    }
    url += "&redirect_uri="+redirectUri
    url += "&remote_auth_uri="+encodeURI(baseURL+"/SignIn/Authenticate")
    window.location.href = url
  }

  onRemember(): void {
    if (this.remember) {
      localStorage.setItem("account", this.account)
    } else {
      localStorage.removeItem("account")
    }
  }


}
</script>

<style scoped>


.form-signin {
  width: 100%;
  max-width: 330px;
  padding: 15px;
  margin: auto;
}
.form-signin .checkbox {
  font-weight: 400;
}
.form-signin .form-control {
  position: relative;
  box-sizing: border-box;
  height: auto;
  padding: 10px;
  font-size: 16px;
}
.form-signin .form-control:focus {
  z-index: 2;
}
.form-signin input[type="email"] {
  margin-bottom: -1px;
  margin-bottom: 10px;
}

#cancel {
  display: block;
  padding: 10px;
  text-decoration: underline;
}
</style>
