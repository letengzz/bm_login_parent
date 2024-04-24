package com.hjc.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.hjc.entity.Account;
import com.hjc.entity.vo.request.ConfirmResetVO;
import com.hjc.entity.vo.request.EmailRegisterVO;
import com.hjc.entity.vo.request.EmailRestVO;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface AccountService extends IService<Account>, UserDetailsService {
    Account findAccountByNameOrEmail(String text);

    String registerEmailVerifyCode(String type,String email,String ip);

    String registerEmailAccount(EmailRegisterVO vo);

    String resetConfirm(ConfirmResetVO vo);

    String resetEmailAccountPassword(EmailRestVO vo);
}
