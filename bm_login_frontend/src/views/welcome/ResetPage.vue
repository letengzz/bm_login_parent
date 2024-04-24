<script setup>
import {computed, reactive, ref} from 'vue'
import {EditPen, Lock, Message} from "@element-plus/icons-vue";
import {get, post} from "@/net/index.js";
import {ElMessage} from "element-plus";
import router from "@/router/index.js";

const active = ref(0)

const form=reactive({
  email:"",
  code:"",
  password:"",
  password_repeat:""
})
function askCode(){
  if(isEmailValid){
    coldTime.value = 60
    get(`/api/auth/ask-code?email=${form.email}&type=reset`,()=>{
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
const validatePassword = (rule, value, callback) => {
  if (value === '') {
    callback(new Error('请再次输入密码'))
  } else if (value !== form.password) {
    callback(new Error('两次输入的密码不一致'))
  }else {
    callback()
  }
}
const rules = {
  email: [
    {required: true, message: '请输入电子邮件地址', trigger: 'blur'},
    {type: 'email', message: '请输入正确的电子邮件地址', trigger: ['blur', 'change']}
  ],
  code: [
    {required: true, message: '请输入验证码', trigger: 'blur'},
    {min: 6, max: 6, message: '验证码长度为6位', trigger: 'blur'}
  ],
  password: [
    {required: true, message: '请输入密码', trigger: 'blur'},
    {min: 6, max: 20, message: '密码长度为6-20位', trigger: 'blur'}
  ],
  password_repeat: [
    {required: true, message: '请再次输入密码', trigger: ['blur', 'change']},
    {validator: validatePassword,trigger: ['blur', 'change']}
  ]
}
const formRef = ref()
function confirmReset(){
  formRef.value.validate((valid) => {
    if (valid) {
      post('/api/auth/reset-confirm',{
        email:form.email,
        code:form.code
      },()=>active.value++,
          (message)=>{
        ElMessage.warning(message)
      })
    } else {
      return false;
    }
  })
}

function doRest(){
  formRef.value.validate((valid) => {
    if (valid) {
      post('/api/auth/reset-password',{...form},
          ()=>{
            ElMessage.success('密码重置成功，请重新登录')
            router.push('/')
          },
          (message)=>{
            ElMessage.warning(message)
          })
    } else {
      return false;
    }
  })
}
</script>

<template>
  <div style="text-align: center">
    <div style="margin-top: 30px">
      <el-steps :active="active" finish-status="success" align-center>
        <el-step title="验证电子邮件"></el-step>
        <el-step title="重新设定密码"></el-step>
      </el-steps>
    </div>
    <div>
      <div style="margin: 0 20px" v-if="active === 0">
        <div style="margin-top: 80px">
          <div style="font-size: 25px;font-weight: bold">重置密码</div>
          <div style="font-size: 14px;color: gray">请输入需要重置密码的电子邮件地址</div>
        </div>
        <div style="margin-top: 50px">
          <el-form :model="form" :rules="rules" ref="formRef">
            <el-form-item prop="email">
              <el-input placeholder="请输入电子邮件地址" v-model="form.email" type="email">
                <template #prefix>
                  <el-icon><Message/></el-icon>
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
                  <el-button @click="askCode" :disabled="!isEmailValid || coldTime > 0" type="success">
                    {{coldTime ? `请稍等 ${coldTime}s` : '发送验证码'}}
                  </el-button>
                </el-col>
              </el-row>
            </el-form-item>
          </el-form>
        </div>
        <div style="margin-top: 80px">
          <el-button style="width: 270px" type="warning" @click="confirmReset" plain>开始重置密码</el-button>
        </div>
      </div>
      <div style="margin: 0 20px" v-if="active === 1">
        <div style="margin-top: 80px">
          <div style="font-size: 25px;font-weight: bold">重置密码</div>
          <div style="font-size: 14px;color: gray">请填写您的新密码，请务必牢记，以便下次登录</div>
        </div>
        <div style="margin-top: 50px">
          <el-form :model="form" :rules="rules" ref="formRef">
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
          </el-form>
        </div>
        <div style="margin-top: 80px">
          <el-button style="width: 270px" type="danger" @click="doRest" plain>立即重置密码</el-button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>

</style>