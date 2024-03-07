package com.hjc.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.print.DocFlavor;
import java.util.Calendar;
import java.util.Date;
import java.util.Map;

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

    //解析Jwt令牌
    public DecodedJWT resolveJwt(String headerToken){
        String token = this.convertToken(headerToken);
        if (token == null) return null;
        //使用同样的算法来解析
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        try {
            DecodedJWT verify = jwtVerifier.verify(token);
            //获取过期的日期
            Date expiresAt = verify.getExpiresAt();
            //判断当前日期是不是在令牌日期之前
            return new Date().after(expiresAt) ? null :verify;
        } catch (JWTVerificationException e) {
            return null;
        }
    }

    //判断token
    private String convertToken(String token){
        if (token == null || !token.startsWith("Bearer ")){
            return null;
        }
        return token.substring(7);
    }

    //解析出用户
    public UserDetails toUser(DecodedJWT decodedJWT){
        Map<String, Claim> claims = decodedJWT.getClaims();
        return User.withUsername(claims.get("name").asString())
                .password("******")
                .authorities(claims.get("authorities").asArray(String.class))
                .build();
    }

    //解析Id
    public Integer toId(DecodedJWT decodedJWT){
        Map<String, Claim> claims = decodedJWT.getClaims();
        return claims.get("id").asInt();
    }
}
