package com.hjc.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Calendar;
import java.util.Date;

@Component
public class JwtUtils {
    //加密密钥
    @Value("${spring.security.jwt.key}")
    private String key;
    //过期时间
    @Value("${spring.security.jwt.expire}")
    private int expire;
    //创建Jwt令牌
    public String createJwt(UserDetails details,int id,String username){
        //设置加密方式
        Algorithm algorithm = Algorithm.HMAC256(key);
        //过期时间
        Date expire = this.expireTime();
        return JWT.create() // 创建Jwt
                //添加自定义索赔值
                .withClaim("id",id)
                .withClaim("name",username)
                .withClaim("authorities",details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                //设置过期时间
                .withExpiresAt(expire)
                .withIssuedAt(new Date())//颁发时间
                .sign(algorithm);
    }

    //设置过期时间
    public Date expireTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR,expire * 24);
        return calendar.getTime();
    }

}
