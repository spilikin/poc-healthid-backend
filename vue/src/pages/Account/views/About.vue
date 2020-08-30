<template>
  <div class="about">
    <h1>{{this.$store.state.securityContext.acct}}</h1>
    <h2>Token content</h2>
    <vue-json-pretty
      :path="'res'"
      :data="jwt">
    </vue-json-pretty>
    <h2>Account information</h2>
    <vue-json-pretty
      :path="'res'"
      :data="account">
    </vue-json-pretty>
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
  accountInfo: object = {}
  jwt?: object

  get account(): object {
    return this.accountInfo
  }

  created() {
    this.jwt = this.$store.state.securityContext.jwt
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
.vjs-tree, .is-root {
  text-align: left;
  margin: auto;
    width: 50%;
}

</style>