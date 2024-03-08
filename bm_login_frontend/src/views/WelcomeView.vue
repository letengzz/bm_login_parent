<template>
  <!--  宽100vw 高100vh 超过部分隐藏 采用flex布局-->
  <div style="width: 100vw;height: 100vh;overflow: hidden;display: flex">
    <!--  左部区域  -->
    <div style="flex: 1;background-color: black">
      <!--      fit 不拉伸-->
      <el-image style="width: 100%;height: 100%" fit="cover"
                src="https://img1.baidu.com/it/u=4097856652,4033702227&fm=253&app=120&f=JPEG?w=1422&h=800"/>
    </div>
    <!--    使用绝对布局来做文字效果-->
    <div class="welcome-title">
      <div style="font-size: 30px;font-weight: bold">欢迎来到此项目</div>
      <div style="margin-top: 10px">希望你喜欢</div>
    </div>
    <!--   右部区域 -->
    <div class="right-card">
        <router-view/>
    </div>
  </div>
</template>
<script setup>

</script>


<style scoped>
.right-card {
  width: 400px;
  z-index: 1;
  background-color: white;
}

.welcome-title {
  position: absolute;
  bottom: 30px;
  left: 30px;
  color: white;
  text-shadow: 0 0 10px black;
}
</style>