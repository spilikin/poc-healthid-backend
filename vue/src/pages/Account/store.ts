import Vue from 'vue'
import Vuex, { StoreOptions } from 'vuex';

Vue.use(Vuex)

export interface SecurityContext {
  token: string;
  jwt: object;
  acct: string;
  axiosConfig: object;
}

export interface RootState {
  securityContext?: SecurityContext;
  accountInfo?: object;
}

const store: StoreOptions<RootState> = {
  state: {
  },
  mutations: {
    accountInfo (state: RootState, accountInfo: object) {
      state.accountInfo = accountInfo
    }
  }
};

export default new Vuex.Store<RootState>(store);
