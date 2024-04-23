//引入createRouter
import {createRouter, createWebHistory} from "vue-router";
import {unauthorized} from "@/net/index.js";

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

            meta: { keepAlive: true }, // true：需要被缓存
            // 子路由
            children: [
                {
                    path: '',
                    name: 'welcome-login',
                    component: ()=> import('@/views/welcome/LoginPage.vue')
                },
                {
                    path: 'register',
                    name: 'welcome-register',
                    component: ()=> import('@/views/welcome/RegisterPage.vue')
                }
            ]
        },
        {
            path: '/index',
            name: 'index',
            component: () =>import('@/views/IndexView.vue')
        }
    ]
})

//配置路由守卫
router.beforeEach((to,from,next) =>{
    const isUnauthorized = unauthorized()
    if (to.name.startsWith('welcome-') && !isUnauthorized){
        next('/index')
    }else if (to.fullPath.startsWith('/index') && isUnauthorized){
        next('/')
    }else {
        next()
    }
})
//对外暴露
export default router