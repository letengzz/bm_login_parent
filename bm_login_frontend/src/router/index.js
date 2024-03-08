//引入createRouter
import {createRouter, createWebHistory} from "vue-router";

// 创建路由
const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes:[
        {
            //路径
            path: '/',
            //名称
            name: 'welcome',
            //组件名
            component: () => import('@/views/WelcomeView.vue'),
            // 子路由
            children: [
                {
                    path: '',
                    name: 'welcome-login',
                    component: ()=> import('@/views/welcome/LoginPage.vue')
                }
            ]
        }
    ]
})

//对外暴露
export default router