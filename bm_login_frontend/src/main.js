import { createApp } from 'vue'
import App from './App.vue'
import router from '@/router'
import axios from "axios";

//配置登录地址
axios.defaults.baseURL = 'http://localhost:8080'

const app = createApp(App);
//使用路由
app.use(router)
//挂载#app元素下
app.mount('#app')
