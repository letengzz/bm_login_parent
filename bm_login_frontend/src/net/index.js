//引入axios
import axios from 'axios'
import {ElMessage} from "element-plus";

//默认的错误处理失败
const defaultFailure = (message,code,url)=>{
    //控制台输出
    console.warn(`请求地址：${url}，状态码：${code},错误信息：${message}`)
    //element ui 弹窗警告
    ElMessage.warning(message)
}
const defaultError = (err)=>{
    //控制台输出
    console.error(err)
    //element ui 弹窗警告
    ElMessage.warning('发生来一些错误，请联系管理员')
}
//内部使用 post
function internalPost(url,data,header,success,failure,error = defaultError){
    axios.post(url,data,{headers:header}).then(({data})=>{
        if (data.code === 200){
            success(data.data)
        }else {
            failure(data.message,data.code,url)
        }
    }).catch(err => error(err))
}

//get
function internalGet(url,header,success,failure,error = defaultError){
    axios.get(url,{headers:header}).then(({data})=>{
        if (data.code === 200){
            success(data.data)
        }else {
            failure(data.message,data.code,url)
        }
    }).catch(err => error(err))
}

//login
function login(username,password,remember,success,failure = defaultFailure){
    internalPost('/api/auth/login',{
        username: username,
        password: password
    },{
        //Spring Security 只能是表单登录
        'Content-Type': 'application/x-www-form-urlencoded'
    },(data) =>{
        storeAccessToken(data.token,remember,data.expire)
        ElMessage.success(`登录成功，欢迎 ${data.username} 欢迎来到该系统`)
        success(data)
    },failure)
}

//名称统一
const authItemName = 'access_token'
//保存accessToken
function storeAccessToken(token,remember,expire){
    //封装成对象
    const authObj = { token:token,expire:expire}
    //根据remember 存储 是否到localStorage
    const str = JSON.stringify(authObj)
    if (remember)
        localStorage.setItem(authItemName,str)
    else
        sessionStorage.setItem(authItemName,str)
}

//取出accessToken
function takeAccessToken(){
    const str = localStorage.getItem(authItemName) || sessionStorage.getItem(authItemName)
    if (!str) return null;
    const authObj = JSON.parse(str)
    //如果时间小于当前时间 在 storage 中删除
    if (authObj.expire <= new Date()){
        deleteAccessToken()
        ElMessage.warning('登录状态已过期，请重新登录')
        return null;
    }
    return authObj.token
}

//删除token
function deleteAccessToken(){
    localStorage.removeItem(authItemName)
    sessionStorage.removeItem(authItemName)
}

//暴露
export {login}