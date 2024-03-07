package com.hjc.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.hjc.utils.JwtUtils;
import jakarta.annotation.Resource;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthorizeFilter extends OncePerRequestFilter {

    @Resource
    private JwtUtils jwtUtils;
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        //自定义验证逻辑

        //读取请求头中的信息
        String authorization = request.getHeader("Authorization");

        DecodedJWT decodedJWT = jwtUtils.resolveJwt(authorization);
        if (decodedJWT != null){
            UserDetails user = jwtUtils.toUser(decodedJWT);
            //创建UsernamePassword
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(user,null,user.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            //往Spring Security 丢用户信息
            SecurityContextHolder.getContext().setAuthentication(authentication);
            request.setAttribute("id",jwtUtils.toId(decodedJWT));
        }
        filterChain.doFilter(request,response);
    }
}
