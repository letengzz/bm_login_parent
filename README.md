# bm_login_parent
**项目架构**：

- 后端开发：SpringBoot3 + MySQL + Redis + RabbitMQ + Jwt（基于Token的权限校验） 
- 前端开发：Vue3 + Vite + ElementPlus （深色模式适配）

**原项目地址**：https://github.com/itbaima-study/SpringBoot-Vue-Template-Jwt

## 后端开发

### 创建项目

使用Spring Inittializr 来创建项目：

![image-20240307135317307](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/imgimage-20240307135317307.png)

选择依赖：

![image-20240307135556445](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/imgimage-20240307135556445.png)

将不需要的文件删除，并将applicaiton.properties 改为 application.yml：

![image-20240307141501142](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/imgimage-20240307141501142.png)

### Spring Security 配置

配置Spring Security：

> com.hjc.config.SecurityConfiguration

```java
@Configuration
public class SecurityConfiguration {

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
                .csrf(AbstractHttpConfigurer::disable) //关闭csrf
                .sessionManagement(conf ->
                        conf.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // 将会话管理设置为无状态 (交由JWT)
                .build();
    }

    //登陆成功处理器
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
        response.getWriter().write("Success");
    }

    //登陆失败处理器
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
        response.getWriter().write("Failure");
    }

    //退出登陆处理器
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        response.getWriter().write("Logout");
    }
}
```

### 配置统一返回

导入依赖：

```xml
<dependency>
    <groupId>com.alibaba.fastjson2</groupId>
    <artifactId>fastjson2</artifactId>
    <version>2.0.47</version>
</dependency>
```

创建记录类：

> com.hjc.entity.RestBean

```java
public record RestBean<T>(int code, T data, String message) {
    //请求成功
    public static <T> RestBean<T> success(T data){
        return new RestBean<>(200,data,"请求成功");
    }

    //请求成功 无data
    public static <T> RestBean<T> success(){
        return RestBean.success(null);
    }

    //请求失败
    public  static <T> RestBean<T> failure(int code,String message){
        return new RestBean<>(code,null,message);
    }

    //转化为JSON字符串
    public String asJsonString(){
        //JSONWriter.Feature.WriteNulls 防止null值错误
        return JSON.toJSONString(this, JSONWriter.Feature.WriteNulls);
    }

}
```

修改Spring Security 登陆成功/失败的响应：

```java
//登陆成功处理器
public void onAuthenticationSuccess(HttpServletRequest request,
                                    HttpServletResponse response,
                                    Authentication authentication) throws IOException, ServletException {
    //设置响应格式
    response.setContentType("application/json;charset=utf-8");
    response.getWriter().write(RestBean.success().asJsonString());
}

//登陆失败处理器
public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    //设置响应格式
    response.setContentType("application/json;charset=utf-8");
    response.getWriter().write(RestBean.failure(401,exception.getMessage()).asJsonString());
}
```

### 配置Jwt

导入依赖：

```java
<dependency>
	<groupId>com.auth0</groupId>
	<artifactId>java-jwt</artifactId>
	<version>4.4.0</version>
</dependency>
```

#### 令牌颁发

创建Jwt工具类：

> com.hjc.utils.JwtUtils

```java
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
    private Date expireTime() {
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.HOUR,expire * 24);
        return calendar.getTime();
    }

}
```

创建前端交互类(Vo)：

> com.hjc.entity.vo.response.AuthorizeVo

```java
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
```

修改Spring Security 登陆成功/失败的响应：

```java
@Resource
private JwtUtils jwtUtils;
//登陆成功处理器
public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
	//设置响应格式
  response.setContentType("application/json;charset=utf-8");
  //用户身份信息
  User user = (User) authentication.getPrincipal();
  //创建token
  String token = jwtUtils.createJwt(user, 1, "小明");
  //封装成Vo
  AuthorizeVo authorizeVo = new AuthorizeVo();
  authorizeVo.setUsername("小明");
  authorizeVo.setRole("");
  authorizeVo.setToken(token);
  authorizeVo.setExpire(jwtUtils.expireTime());
  response.getWriter().write(RestBean.success(authorizeVo).asJsonString());
}
```

#### 请求头校验

Jwt工具类中添加：

```java
@Component
public class JwtUtils {
    //加密密钥
    @Value("${spring.security.jwt.key}")
    private String key;
     
  	//....

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
```

使用Spring Security 过滤器来实现请求头校验：

```java
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
```

添加测试controller：

```java
@RestController
@RequestMapping("/api/test")
public class TestController {
    @GetMapping("/hello")
    public String test(){
        return "Hello World";
    }
}
```

将过滤器添加到Spring Security：

```java
@Configuration
public class SecurityConfiguration {
		@Resource
    private JwtAuthorizeFilter jwtAuthorizeFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // ...
                .addFilterBefore(jwtAuthorizeFilter, UsernamePasswordAuthenticationFilter.class) //添加自定义的filter
                .build();
    }
}
```

统一返回类中添加401错误处理通用方法：

```java
public record RestBean<T>(int code, T data, String message) {
    //....

    //401错误处理
    public static <T> RestBean<T> unauthorized(String message) {
        return failure(401, message);
    }
		//....
}
```

未登录处理：

```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
               	// ...
                .exceptionHandling(
                        conf -> conf.authenticationEntryPoint(this::onUnauthorized) //处理未登录
                )
            	  // ...
                .build();
    }
  
    //未登录
    public void onUnauthorized(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        //设置响应格式
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.unauthorized(authException.getMessage()).asJsonString());
    }
}
```

优化代码：

```java
//登陆失败处理器
public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
    //设置响应格式
    response.setContentType("application/json;charset=utf-8");
    response.getWriter().write(RestBean.unauthorized(exception.getMessage()).asJsonString());
}

```

统一返回类中添加403错误处理通用方法：

```java
public record RestBean<T>(int code, T data, String message) {
    //....

    //403错误处理
    public static <T> RestBean<T> forbidden(String message) {
        return failure(401, message);
    }
		//....
}
```

未授权处理：

```java
@Configuration
public class SecurityConfiguration {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        return http
                // ...
                .exceptionHandling(
                        conf -> conf.authenticationEntryPoint(this::onUnauthorized) //处理未登录
                                .accessDeniedHandler(this::onAccessDeny) //处理未授权
                )
          	    // ...
                .build();
    }

    //处理未授权
    public void onAccessDeny(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        //设置响应格式
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.forbidden(accessDeniedException.getMessage()).asJsonString());

    }
}
```

#### 退出登录

退出登录需要把令牌失效才可以，否则令牌仍然有效，存在安全隐患。

使用Redis实现黑名单失效：

导入依赖：

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

Jwt工具类中在创建令牌时携带一个ID并在退出时将令牌存入到redis时：

```java

```



### 数据库用户校验





### 密码重置

### 限流操作

### 跨域配置



### 验证码



### 注册



## 前端开发

### 创建项目

创建Vue项目：

![image-20240307135734061](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/imgimage-20240307135734061.png)

使用npm install 安装依赖

![image-20240307135906430](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/imgimage-20240307135906430.png)





### 

### 注册



### 密码重置页面



### 深色模式适配



