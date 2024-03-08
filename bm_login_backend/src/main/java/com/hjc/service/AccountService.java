package com.hjc.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.hjc.entity.Account;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AccountService extends IService<Account>, UserDetailsService {
    Account findAccountByNameOrEmail(String text);
}
