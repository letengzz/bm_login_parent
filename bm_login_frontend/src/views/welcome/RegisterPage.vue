<script setup>
import {computed, ref,reactive} from "vue";
import {EditPen, Lock, Message, User} from "@element-plus/icons-vue";
import router from "@/router/index.js";
import {ElMessage} from "element-plus";
import {get, post} from "@/net/index.js";

const form = reactive({
  username: '',
  password: '',
  password_repeat: '',
  email: '',
  code: ''
})
const validateUsername = (rule, value, callback) => {
  if (value === '') {
    callback(new Error('请输入用户名'))
  } else if (!/^[a-zA-Z0-9\u4e00-\u9fa5]+$/.test(value)) {
    callback(new Error('用户名不能包含特殊字符，只能使用中/英文'))
  } else {
    callback()
  }
}
const validatePassword = (rule, value, callback) => {
  if (value === '') {
    callback(new Error('请再次输入密码'))
  } else if (value !== form.password) {
    callback(new Error('两次输入的密码不一致'))
  }else {
    callback()
  }
}
// 判断规则
const rule = {
  // 校验
  username: [
    {validator: validateUsername, trigger: ['blur', 'change']},
    {min: 1, max: 10, message: '用户名长度在2-9位之间', trigger: ['blur']}
  ],
  password: [
    {required: true, message: '密码不能为空', trigger: ['blur']},
    {min: 6, max: 20, message: '密码长度在6-20位之间', trigger: ['blur', 'change']}
  ],
  password_repeat: [
    {required: true, message: '请再次输入密码', trigger: ['blur', 'change']},
    {validator: validatePassword,trigger: ['blur', 'change']}
  ],
  email:[
      {required: true, message: '请输入邮箱地址', trigger: ['blur']},
      {type: 'email', message: '请输入正确的邮箱地址', trigger: ['blur', 'change']}
  ],
  code:[
      {required: true, message: '请输入验证码', trigger: ['blur']},
      {min: 6, max: 6, message: '验证码长度为6位', trigger: ['blur', 'change']}
  ]
}
function askCode(){
  if(isEmailValid){
    coldTime.value = 60
    get(`/api/auth/ask-code?email=${form.email}&type=register`,()=>{
      ElMessage.success(`验证码已发送: ${form.email}, 请查收`)
      setInterval(() => coldTime.value--,1000)
    },(message)=>{
      ElMessage.warning(message)
      coldTime.value = 0
    })
  }else {
    ElMessage.warning('请输入正确的邮箱地址')
  }

}

//冷却时间
const coldTime = ref(0)
const isEmailValid = computed(() => /^[\w.-]+@[\w.-]+\.\w+$/.test(form.email))
const formRef = ref()
function register(){
  formRef.value.validate((valid) => {
    if (valid){
      post('api/auth/register',{...form},()=>{
        ElMessage.success('注册成功，欢迎加入')
        router.push('/')
      })
    }else {
      ElMessage.warning('请填写正确的信息')
    }
  })
}
</script>

<template>
  <div style="text-align: center;margin: 0 20px">
    <div style="margin-top: 100px">
      <div style="font-size: 25px;font-weight: bold">注册新用户</div>
      <div style="font-size: 14px;color: gray">欢迎注册我们的学习网站，请在下方填写相关信息</div>
    </div>
    <div style="margin-top: 50px">
      <el-form :model="form" :rules="rule" ref="formRef">
        <el-form-item prop="username">
          <el-input v-model="form.username" maxlength="10" type="text" placeholder="用户名">
            <template #prefix>
              <el-icon>
                <User/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="password">
          <el-input v-model="form.password" maxlength="20" type="password" placeholder="密码">
            <template #prefix>
              <el-icon>
                <Lock/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="password_repeat">
          <el-input v-model="form.password_repeat" maxlength="20" type="password" placeholder="重复密码">
            <template #prefix>
              <el-icon>
                <Lock/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="email">
          <el-input v-model="form.email"  type="email" placeholder="电子邮箱">
            <template #prefix>
              <el-icon>
                <Message/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="code">
          <el-row :gutter="10" style="width: 100%;">
            <el-col :span="17">
              <el-input v-model="form.code" maxlength="6" type="text" placeholder="请输入验证码">
                <template #prefix>
                  <el-icon>
                    <EditPen/>
                  </el-icon>
                </template>
              </el-input>
            </el-col>
            <el-col :span="5">
              <el-button @click="askCode" :disabled="!isEmailValid || coldTime" type="success">
                {{coldTime ? `请稍等 ${coldTime}s` : '发送验证码'}}
              </el-button>
            </el-col>
          </el-row>
        </el-form-item>
      </el-form>
      <div style="margin-top: 80px">
        <el-button style="width: 270px" type="warning" @click="register" plain>注册</el-button>
      </div>
      <div style="margin-top: 20px">
        <span style="font-size: 14px;line-height: 15px;color: gray">已有账号？</span>
        <el-link style="translate: 0 -1px" @click="router.push('/')">立即登录</el-link>
      </div>
    </div>
  </div>
</template>

<style scoped>

</style>