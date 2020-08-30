<template>
  <div class="authenticate">
      <canvas id="code"></canvas>
      <h1 class="h3 mb-3 font-weight-normal">Scan QR-Code using your Smartphone</h1>
      <small>NONCE: {{ nonce }}</small>

      <div class="d-flex justify-content-center mb-3">
          <b-spinner variant="primary" label="Spinning"></b-spinner>
      </div> 
      <a href="https://apps.apple.com/de/app/testflight/id899247664?mt=8" style="display:inline-block;overflow:hidden;background:url(https://linkmaker.itunes.apple.com/en-us/badge-lrg.svg?releaseDate=2014-09-09&kind=iossoftware&bubble=ios_apps) no-repeat;width:135px;height:40px;"></a>
      <div>
        <a id="cancel" :href="redirectUri">Cancel</a>
      </div>
    </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'

import QRCode from 'qrcode'

@Component
export default class Identity extends Vue {
  redirectUri = "https://acme.spilikin.dev/Account/"
  nonce = ""

  mounted() {
    this.nonce = ""+this.$route.query['nonce']

      if (this.$route.query['redirect_uri'] != null) {
        this.redirectUri = ""+this.$route.query['redirect_uri']
      }
      const canvas = document.getElementById('code')
      let url = 'https://appauth.acme.spilikin.dev/api/auth/remote'
      url += "?acct="+this.$route.query['acct']
      url += "&nonce="+this.$route.query['nonce']
      url += "&redirect_uri="+this.$route.query['redirect_uri']

      const source = new EventSource("/api/auth/remote?nonce="+this.$route.query['nonce']);
      source.onmessage = function(event) {
        source.close()
        const data = JSON.parse(event.data)
        let url = data['redirect_uri']
        url += "?acct="+data['acct']
        url += "&code="+data['code']
        url += "&redirect_uri="+data['redirect_uri']
        window.location.href=url
      };
      source.onerror = function() {
        console.log("Error occured");
      };

      this.$nextTick(function () {
        QRCode.toCanvas(canvas, url , function (error: Error) {
          if (error) console.error(error)
        })
    });

  }

}
</script>

<style scoped>

</style>
