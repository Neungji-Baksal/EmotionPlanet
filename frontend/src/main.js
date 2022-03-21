import Vue from 'vue'
import App from './App.vue'
import router from './router'
import store from './store'

Vue.config.productionTip = false
Vue.prototype.$bus = new Vue()
new Vue({
  router,
  store,
  render: h => h(App)
}).$mount('#app')

import GAuth from 'vue-google-oauth2'

const gauthOption = {
  clientId: '172274534251-7a2a6sthcuviratis75u7gu7utbkdp8d.apps.googleusercontent.com',
  scope: 'profile email',
  prompt: 'select_account'
}
Vue.use(GAuth, gauthOption)

window.Kakao.init('11f4db68bab4c22515d9a90f8abc6d2e');