package com.hjc.config;

import com.hjc.entity.RestBean;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;

@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                .authorizeHttpRequests(conf -> conf
                        .requestMatchers("/api/auth/**").permitAll() //放行登陆请求
                        .anyRequest().authenticated() //所有请求都需要权限
                )
                .formLogin(conf -> conf
                        .loginProcessingUrl("/api/auth/login") //登陆的url
                        .successHandler(this::onAuthenticationSuccess) //登陆成功handle
                        .failureHandler(this::onAuthenticationFailure)
                ) //表单登陆
                .logout(
                        conf -> conf
                                .logoutUrl("/api/auth/logout") //退出登陆的url
                                .logoutSuccessHandler(this::onLogoutSuccess)
                )
                .csrf(AbstractHttpConfigurer::disable) //关闭csrf
                .sessionManagement(conf ->
                        conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 将会话管理设置为无状态 (交由JWT)
                .build();
    }

    //登陆成功处理器
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        response.getWriter().write("Success");
    }

    //登陆失败处理器
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.getWriter().write("Failure");
    }

    //退出登陆处理器
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.getWriter().write("Logout");
    }
}
