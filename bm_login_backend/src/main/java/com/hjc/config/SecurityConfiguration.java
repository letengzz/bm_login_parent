package com.hjc.config;

import com.hjc.entity.Account;
import com.hjc.entity.RestBean;
import com.hjc.entity.vo.response.AuthorizeVo;
import com.hjc.filter.JwtAuthorizeFilter;
import com.hjc.service.AccountService;
import com.hjc.utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import java.io.IOException;
import java.io.PrintWriter;

@Configuration
public class SecurityConfiguration {

    @Resource
    private JwtAuthorizeFilter jwtAuthorizeFilter;

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
                .exceptionHandling(
                        conf -> conf.authenticationEntryPoint(this::onUnauthorized) //处理未登录
                                .accessDeniedHandler(this::onAccessDeny) //处理未授权
                )
                .csrf(AbstractHttpConfigurer::disable) //关闭csrf
                .sessionManagement(conf ->
                        conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 将会话管理设置为无状态 (交由JWT)
                .addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class) //添加自定义的filter
                .build();
    }

    @Resource
    private JwtUtils jwtUtils;

    @Resource
    private AccountService accountService;
    //登陆成功处理器
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        //设置响应格式
        response.setContentType("application/json;charset=utf-8");
        //用户身份信息
        User user = (User) authentication.getPrincipal();
        Account account = accountService.findAccountByNameOrEmail(user.getUsername());
        //创建token
        String token = jwtUtils.createJwt(user, account.getId(), account.getUsername());
        //封装成Vo
        AuthorizeVo authorizeVo = new AuthorizeVo();
        authorizeVo.setUsername(account.getUsername());
        authorizeVo.setRole(account.getRole());
        authorizeVo.setToken(token);
        authorizeVo.setExpire(jwtUtils.expireTime());
        response.getWriter().write(RestBean.success(authorizeVo).asJsonString());
    }

    //登陆失败处理器
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        //设置响应格式
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.unauthorized(exception.getMessage()).asJsonString());
    }

    //退出登陆处理器

    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        //设置响应格式
        response.setContentType("application/json;charset=utf-8");
        PrintWriter writer = response.getWriter();
        // 请求头中获取token
        String authorization = request.getHeader("Authorization");
        if (jwtUtils.invalidateJwt(authorization)){
            writer.write(RestBean.success().asJsonString());
        }else {
            writer.write(RestBean.failure(400,"退出登录失败").asJsonString());
        }
    }

    //未登录
    public void onUnauthorized(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        //设置响应格式
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.unauthorized(authException.getMessage()).asJsonString());
    }

    //处理未授权
    public void onAccessDeny(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        //设置响应格式
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.forbidden(accessDeniedException.getMessage()).asJsonString());

    }
}
