package com.hjc.service.impl;

import com.baomidou.mybatisplus.core.toolkit.Wrappers;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.hjc.entity.Account;
import com.hjc.entity.vo.request.EmailRegisterVO;
import com.hjc.mapper.AccountMapper;
import com.hjc.myConst.Const;
import com.hjc.service.AccountService;
import com.hjc.utils.FlowUtils;
import jakarta.annotation.Resource;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.Random;
import java.util.concurrent.TimeUnit;

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
    public Account findAccountByNameOrEmail(String text) {
        return this.query().eq("username", text).or().eq("email", text).one();
    }


    @Resource
    private AmqpTemplate amqpTemplate;

    @Resource
    private StringRedisTemplate stringRedisTemplate;

    @Override
    public String registerEmailVerifyCode(String type, String email, String ip) {
        //加锁防止重复多次调用
        synchronized (ip.intern()) {
            if (!this.verifyLimit(ip)) {
                return "请求频繁，请稍后再试";
            }
            //生成随机验证码
            Random random = new Random();
            int code = random.nextInt(899999) + 100000;
            Map<String, Object> data = Map.of("type", type, "email", email, "code", code);
            amqpTemplate.convertAndSend("mail", data);

            stringRedisTemplate.opsForValue()
                    .set(Const.VERIFY_EMAIL_DATA + email, String.valueOf(code), 3, TimeUnit.MINUTES);

            return null;
        }
    }

    //加密
    @Resource
    private PasswordEncoder encoder;

    @Override
    public String registerEmailAccount(EmailRegisterVO vo) {
        String email = vo.getEmail();
        String username = vo.getUsername();
        String code = stringRedisTemplate.opsForValue().get(Const.VERIFY_EMAIL_DATA + email);

        //判断验证码
        if (code == null){
            return "验证码过期，请重新获取";
        }
        if (!code.equals(vo.getCode())){
            return "验证码错误";
        }
        //判断邮箱是否被注册
        if (this.existsAccountByEmail(email)){
            return "邮箱已被注册";
        }
        //判断用户名是否被注册
        if (this.existsAccountByEmail(email)){
            return "用户名已被注册";
        }

        String password =  encoder.encode(vo.getPassword());
        Account account = new Account(null,vo.getUsername(),password, vo.getEmail(), "user",new Date());
        if (this.save(account)){
            //删除code
            stringRedisTemplate.delete(Const.VERIFY_EMAIL_DATA + email);
            return null;
        }else {
            return "内部错误，请联系管理员";
        }
    }

    //通过邮件判断账户是否存在
    private boolean existsAccountByEmail(String email) {
        return this.baseMapper.exists(Wrappers.<Account>query().eq("email", email));
    }

    //通过用户名判断账户是否存在
    private boolean existsAccountByUsername(String username) {
        return this.baseMapper.exists(Wrappers.<Account>query().eq("username", username));
    }
    @Resource
    private FlowUtils flowUtils;

    //根据ip判断是否在限制时间内
    private boolean verifyLimit(String ip) {
        String key = Const.VERIFY_EMAIL_LIMIT + ip;
        return flowUtils.limitOnceCheck(key, 60);
    }

}
