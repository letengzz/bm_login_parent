

import { createApp } from 'vue'
import App from './App.vue'
import router from '@/router'

const app = createApp(App);
//使用路由
app.use(router)
//挂载#app元素下
app.mount('#app')
