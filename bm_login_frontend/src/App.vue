<script setup>

import {useDark, useToggle} from "@vueuse/core";

useDark({
  selector: 'html',
  attribute: 'class',
  valueDark: 'dark',
  valueLight: 'light'
});

useDark({
  onChanged(dark){useToggle(dark)}
})
</script>

<template>
  <div>
<!--    展示路由界面-->
    <router-view/>
  </div>
</template>

<style scoped>
</style>

