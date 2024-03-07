package com.hjc.entity.vo.response;

import lombok.Data;

import java.util.Date;

@Data
public class AuthorizeVo {
    //用户名
    private String username;
    //角色
    private String role;
    //token
    private String token;
    //过期时间
    private Date expire;
}
