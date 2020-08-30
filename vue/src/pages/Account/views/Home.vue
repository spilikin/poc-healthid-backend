<template>
  <div class="home">
    <div class="header">
    <h1>{{accountInfo.name}}</h1>
    <div class="avatar-wrapper">
        <img class="avatar" :src="accountInfo.avatarURI"/>
    </div>
    </div>
    <div class="account">
    <h2>Account</h2>
    <p>{{this.$store.state.securityContext.acct}}</p>
    <h2>Devices</h2>
    <p>
    <ul class="list-group">
      <li class="list-group-item" v-for="device in accountInfo.devices" :key="device.alias">
        {{ device.alias }}<br/>
        <small>Apple iPhone</small>
      </li>
      <li class="list-group-item">
        Web Browser<br/>
        <small class="green-text">Active</small>
      </li>
    </ul>
    </p>
    <h2>Applications</h2>
    <ul class="list-group">
      <li class="list-group-item">
        HealthID Account Management<br/>
        <small><strong>Active</strong></small>
      </li>
      <li class="list-group-item">
        Health Record<br/>
        <small>Not configured</small>
      </li>
      <li class="list-group-item">
        Prescription<br/>
        <small>Not configured</small>
      </li>
      <li class="list-group-item">
        Messaging<br/>
        <small class="bq-title">Not configured</small>
      </li>
    </ul>

    <p>
    </p>

    </div>
  </div>
</template>

<script lang="ts">
import { Vue, Component, Prop } from 'vue-property-decorator'
import VueJsonPretty from 'vue-json-pretty'
import axios from 'axios'

@Component({
  components: { VueJsonPretty }
})
export default class Home extends Vue {
  acct?: string;
  accountInfo: object = {}

  created() {
    this.acct = this.$store.state.securityContext.acct
    axios.get(`/api/acct/${this.$store.state.securityContext.acct}`, 
      this.$store.state.securityContext.axiosConfig)
      .then(response => {
        console.debug(response)
        this.accountInfo = response.data
      })
      .catch(error => {
        console.error(error)
    });

  }

}
</script>

<style scoped>
h1 {
  color: white;
  background-color: rgb(37, 104, 231);
}
.header {
  background-color: rgb(37, 104, 231);
}
.vjs-tree, .is-root {
  text-align: left;
  margin: auto;
  width: 50%;
}
.avatar {
  border-radius: 50%;
  width: 20em;
  height: 20em;
  object-fit: cover;
  box-shadow: 0 10px 20px rgba(0,0,0,0.19), 0 6px 6px rgba(0,0,0,0.23);
  margin: 0.5em;
}

.avatar-wrapper {
      background: linear-gradient(180deg,rgb(37, 104, 231) 50%,white 50%);

}

.account {
  text-align: left;
  margin: auto;
  max-width: 90%;
}
</style>