package com.hjc.service.impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hjc.entity.Account;
import com.hjc.mapper.AccountMapper;
import com.hjc.service.AccountService;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {

    //查询用户信息
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Account account = this.findAccountByNameOrEmail(username);
        if (account == null)
            throw new UsernameNotFoundException("用户名或密码错误");
        return User
                .withUsername(account.getUsername())
                .password(account.getPassword())
                .roles(account.getRole())
                .build();
    }

    //根据用户名或邮箱查询用户
    @Override
    public Account findAccountByNameOrEmail(String text){
        return this.query().eq("username",text).or().eq("email",text).one();
    }

}
