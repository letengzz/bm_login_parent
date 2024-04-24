package com.hjc.controller;

import com.hjc.entity.RestBean;
import com.hjc.entity.vo.request.ConfirmResetVO;
import com.hjc.entity.vo.request.EmailRegisterVO;
import com.hjc.entity.vo.request.EmailRestVO;
import com.hjc.service.AccountService;
import jakarta.annotation.Resource;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.function.Function;
import java.util.function.Supplier;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthorizeController {

    @Resource
    private AccountService accountService;
    @GetMapping("/ask-code")
    public RestBean<Void> askVerifyCode(@RequestParam @Email String email,
                                        @RequestParam @Pattern( regexp = "(register|reset)") String type,
                                        HttpServletRequest request){
//        String message = accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr());
//        return message == null ? RestBean.success() : RestBean.failure(400, message);
        return messageHandle(()->
                accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr()));
    }

    @PostMapping("/register")
    public RestBean<Void> register(@Valid @RequestBody EmailRegisterVO vo){
       return messageHandle(()->accountService.registerEmailAccount(vo));
    }

    //封装
    private RestBean<Void> messageHandle(Supplier<String> action){
        String message = action.get();
        return message == null ? RestBean.success() : RestBean.failure(400, message);
    }

    private <T> RestBean<Void> messageHandle(T vo, Function<T,String> function){
           return messageHandle(() -> function.apply(vo));
    }
    @PostMapping("/reset-confirm")
    public RestBean<Void> resetConfirm(@Valid @RequestBody ConfirmResetVO vo){
//        return this.messageHandle(()->accountService.resetConfirm(vo));
        return messageHandle(vo,accountService::resetConfirm);
    }
    @PostMapping("/reset-password")
    public RestBean<Void> resetConfirm(@Valid @RequestBody EmailRestVO vo){
//        return this.messageHandle(()->accountService.resetConfirm(vo));
        return messageHandle(vo,accountService::resetEmailAccountPassword);
    }
}
