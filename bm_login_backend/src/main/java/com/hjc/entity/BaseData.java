package com.hjc.entity;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.function.Consumer;

//自己实现属性拷贝
public interface BaseData {
    //使用lambda
    default <V> V asViewObject(Class<V> clazz, Consumer<V> consumer){
        V v = this.asViewObject(clazz);
        consumer.accept(v);
        return v;
    }
    default <V> V asViewObject(Class<V> clazz){

        try {
            //获取全部属性
            Field[] declaredFields = clazz.getDeclaredFields();
            //获取无参构造
            Constructor<V> constructor = clazz.getConstructor();
            //将对象构建出来
            V v = constructor.newInstance();

            for (Field declaredField : declaredFields) {
                convert(declaredField,v);
            }
            return v;
        } catch (Exception  e) {
            throw new RuntimeException(e);
        }
    }

    //转换
    private void convert(Field field,Object vo){
        try {
            Field source = this.getClass().getDeclaredField(field.getName());
            //允许访问
            source.setAccessible(true);
            field.setAccessible(true);
            //将当前对象取出来的属性 赋值给vo对象的属性
            field.set(vo,source.get(this));
        } catch (NoSuchFieldException | IllegalAccessException ignored) {}
    }
}
