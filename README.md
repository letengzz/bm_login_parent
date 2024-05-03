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

Jwt工具类中在创建令牌时携带一个ID方便退出时存储令牌：

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
                .withJWTId(UUID.randomUUID().toString()) //创建ID 方便其退出登录拉黑
                //添加自定义索赔值
                .withClaim("id",id)
                .withClaim("name",username)
                .withClaim("authorities",details.getAuthorities().stream().map(GrantedAuthority::getAuthority).toList())
                //设置过期时间
                .withExpiresAt(expire)
                .withIssuedAt(new Date())//颁发时间
                .sign(algorithm);
    }
}
```

构建常量存储经常使用的属性：

> com.hjc.myConst.Const

```java
public class Const {
    public static final String JWT_BLACK_LIST = "jwt:blacklist:";
}
```

在退出时将令牌存入到redis：

```java
@Component
public class JwtUtils {
    //加密密钥
    @Value("${spring.security.jwt.key}")
    private String key;
 
  	// ... 
  
    @Resource
    private StringRedisTemplate template;


    //设置令牌无效
    public boolean invalidateJwt(String headerToken){
        String token = this.convertToken(headerToken);
        if (token == null) return false;
        //使用同样的算法来解析
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        try {
            DecodedJWT jwt = jwtVerifier.verify(token);
            String id = jwt.getId();
            return this.deleteToken(id,jwt.getExpiresAt());
        } catch (JWTVerificationException e) {
            return false;
        }
    }

    //删除令牌
    private boolean deleteToken(String uuid,Date time){
        //如果无效直接返回
        if (this.isInvalidToken(uuid)){
            return false;
        }
        //判断当前时间与过期时间
        Date now = new Date();
        long expire = Math.max(time.getTime() - now.getTime(), 0);
        template.opsForValue().set(Const.JWT_BLACK_LIST+uuid,"",expire, TimeUnit.MILLISECONDS);
        return true;
    }

    //判断令牌是否有效
    private boolean isInvalidToken(String uuid){
        return Boolean.TRUE.equals(template.hasKey(Const.JWT_BLACK_LIST + uuid));
    }
}
```

解析令牌判断是否有效：

```java
@Component
public class JwtUtils {
    //加密密钥
    @Value("${spring.security.jwt.key}")
    private String key;
 
    // ...

    //解析Jwt令牌
    public DecodedJWT resolveJwt(String headerToken){
        String token = this.convertToken(headerToken);
        if (token == null) return null;
        //使用同样的算法来解析
        Algorithm algorithm = Algorithm.HMAC256(key);
        JWTVerifier jwtVerifier = JWT.require(algorithm).build();
        try {
            DecodedJWT verify = jwtVerifier.verify(token);
            //判断是否有效
            if (this.isInvalidToken(verify.getId())){
                return  null;
            }
            //获取过期的日期
            Date expiresAt = verify.getExpiresAt();
            //判断当前日期是不是在令牌日期之前
            return new Date().after(expiresAt) ? null :verify;
        } catch (JWTVerificationException e) {
            return null;
        }
    }
		
  	// ... 

    //判断令牌是否有效
    private boolean isInvalidToken(String uuid){
        return Boolean.TRUE.equals(template.hasKey(Const.JWT_BLACK_LIST + uuid));
    }
}
```

修改退出登录处理器：

```java
//退出登陆处理器

public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    //设置响应格式
    response.setContentType("application/json;charset=utf-8");
    PrintWriter writer = response.getWriter();
    // 请求头中获取token
    String authorization = request.getHeader("Authorization");
    if (jwtUtils.invalidateJwt(authorization)){
        writer.write(RestBean.success().asJsonString());
    }else {
        writer.write(RestBean.failure(400,"退出登录失败").asJsonString());
    }
}
```

### 数据库用户校验

创建数据库表及数据：

```sql
CREATE TABLE `db_account` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT 'Id\n',
  `username` varchar(255) DEFAULT NULL COMMENT '用户名\n',
  `password` varchar(255) DEFAULT NULL COMMENT '密码',
  `email` varchar(255) DEFAULT NULL COMMENT '邮箱',
  `role` varchar(255) DEFAULT NULL COMMENT '角色\n',
  `register_time` datetime DEFAULT NULL COMMENT '注册时间',
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;

INSERT INTO `bm_login`.`db_account` (`username`, `password`, `email`, `role`, `register_time`) VALUES ('test', '$2a$10$piiDnjkCWNRoK49sb5GVw.yMCI5l3BGj03at1vfByMdmH6g88rAR6', '12345@aa.com', 'user', '2024-03-08 13:31:21');
```

导入MyBtais-plus依赖：

```xml
<dependency>
    <groupId>com.baomidou</groupId>
    <artifactId>mybatis-plus-spring-boot3-starter</artifactId>
    <version>3.5.5</version>
</dependency>
```

配置数据库：

> /src/main/resources/application.yml

```yaml
spring:
  datasource:
    driver-class-name: com.mysql.cj.jdbc.Driver
    username: root
    password: 123123
    url: jdbc:mysql://localhost:3306/bm_login
```

创建Account：

> com.hjc.entity.Account

```java
@Data
@TableName("db_account")
@AllArgsConstructor
@NoArgsConstructor
public class Account {
    @TableId(type = IdType.AUTO)
    private Integer id;
    private String username;
    private String password;
    private String email;
    private String role;
    private Date registerTime;
}
```

创建Mapper：

> com.hjc.mapper.AccountMapper

```java
public interface AccountMapper extends BaseMapper<Account> {
}
```

启动类：

```java
@SpringBootApplication
@MapperScan("com.hjc.mapper")
public class BmLoginBackendApplication {

	public static void main(String[] args) {
		SpringApplication.run(BmLoginBackendApplication.class, args);
	}

}
```

Service接口及实现类：

> com.hjc.service.AccountService

```java
public interface AccountService extends IService<Account>, UserDetailsService {
    Account findAccountByNameOrEmail(String text);
}
```

> com.hjc.service.impl.AccountServiceImpl

```java
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
```

配置密码加密器：

> com.hjc.config.WebConfiguration

```java
@Configuration
public class WebConfiguration {
    //配置密码加密器
    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder(){
        return new BCryptPasswordEncoder();
    }
}
```

修改登陆成功处理器：

```java
@Resource
private AccountService accountService;
//登陆成功处理器
public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {
	//设置响应格式
  response.setContentType("application/json;charset=utf-8");
  //用户身份信息
  User user = (User) authentication.getPrincipal();
  Account account = accountService.findAccountByNameOrEmail(user.getUsername());
  //创建token
  String token = jwtUtils.createJwt(user, account.getId(), account.getUsername());
  //封装成Vo
  AuthorizeVo authorizeVo = new AuthorizeVo();
  authorizeVo.setUsername(account.getUsername());
  authorizeVo.setRole(account.getRole());
  authorizeVo.setToken(token);
  authorizeVo.setExpire(jwtUtils.expireTime());
  response.getWriter().write(RestBean.success(authorizeVo).asJsonString());
}
```

### 对象转换

使用反射来实现对象转换：

```java
//自己实现属性拷贝
public interface BaseData {
    //使用lambda
    default <V> V asViewObject(Class<V> clazz, Consumer<V> consumer){
        V v = this.asViewObject(clazz);
        consumer.accept(v);
        return v;
    }
    default <V> V asViewObject(Class<V> clazz){

        try {
            //获取全部属性
            Field[] declaredFields = clazz.getDeclaredFields();
            //获取无参构造
            Constructor<V> constructor = clazz.getConstructor();
            //将对象构建出来
            V v = constructor.newInstance();

            for (Field declaredField : declaredFields) {
                convert(declaredField,v);
            }
            return v;
        } catch (Exception  e) {
            throw new RuntimeException(e);
        }
    }

    //转换
    private void convert(Field field,Object vo){
        try {
            Field source = this.getClass().getDeclaredField(field.getName());
            //允许访问
            source.setAccessible(true);
            field.setAccessible(true);
            //将当前对象取出来的属性 赋值给vo对象的属性
            field.set(vo,source.get(this));
 				} catch (NoSuchFieldException | IllegalAccessException ignored) {}
    }
}
```

实现该接口：

```java
@Data
@TableName("db_account")
@AllArgsConstructor
@NoArgsConstructor
public class Account implements BaseData{
    @TableId(type = IdType.AUTO)
    private Integer id;
    private String username;
    private String password;
    private String email;
    private String role;
    private Date registerTime;
}
```

直接调用：

```java
//封装成Vo
AuthorizeVo authorizeVo = account
							.asViewObject(AuthorizeVo.class, v -> {
                    v.setToken(token);
                    v.setExpire(jwtUtils.expireTime());
							});
```

### 跨域配置

由于需要做限流操作，所以要自己实现跨域问题：

```java
/**
 * 跨域配置过滤器，仅处理跨域，添加跨域响应头
 */
@Component
@Order(Const.ORDER_CORS) //优先级需要比过滤器链高
public class AjaxCorsFilter extends HttpFilter {
    @Value("${spring.web.cors.origin}")
    String origin;

    @Value("${spring.web.cors.credentials}")
    boolean credentials;

    @Value("${spring.web.cors.methods}")
    String methods;

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        this.addCorsHeader(request, response);
        chain.doFilter(request, response);
    }

    /**
     * 添加所有跨域相关响应头
     * @param request 请求
     * @param response 响应
     */
    private void addCorsHeader(HttpServletRequest request, HttpServletResponse response) {
        response.addHeader("Access-Control-Allow-Origin", this.resolveOrigin(request));
        response.addHeader("Access-Control-Allow-Methods", this.resolveMethod());
        response.addHeader("Access-Control-Allow-Headers", "Authorization, Content-Type");
        if(credentials) {
            response.addHeader("Access-Control-Allow-Credentials", "true");
        }
    }

    /**
     * 解析配置文件中的请求方法
     * @return 解析得到的请求头值
     */
    private String resolveMethod(){
        return methods.equals("*") ? "GET, HEAD, POST, PUT, DELETE, OPTIONS, TRACE, PATCH" : methods;
    }

    /**
     * 解析配置文件中的请求原始站点
     * @param request 请求
     * @return 解析得到的请求头值
     */
    private String resolveOrigin(HttpServletRequest request){
        return origin.equals("*") ? request.getHeader("Origin") : origin;
    }
}
```

> applicaiton.yaml

```yaml
spring:
  web:
    cors:
      origin: '*'
      credentials: false
      methods: '*'
```

> com.hjc.myConst.Const

```java
public class Const {
    public static final String JWT_BLACK_LIST = "jwt:blacklist:";

    public static final int ORDER_CORS = -102;
}
```

### 验证码

通过消息队列消费消费邮件发送的消息，用户申请验证码邮件，把验证码邮件丢到消息队列中，再有监听器消费消息队列中的邮件发送请求 

导入依赖：

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-mail</artifactId>
</dependency>
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-amqp</artifactId>
</dependency>
```

配置mail：

```yaml
spring:
  mail:
    host: smtp.163.com
    username: m19164221189@163.com
    password: RAKTCQGORXBPIVPR
```

配置RabbitMQ：

```yaml
spring:
 rabbitmq:
    virtual-host: /
    username: admin
    password: admin
```

```java
@Configuration
public class RabbitConfiguration {
    @Bean("emailQueue")
    public Queue eamilQueue(){
        return QueueBuilder.durable("mail").build();
    }
    @Bean
    public MessageConverter jsonMessageConverter() {
        return new Jackson2JsonMessageConverter();
    }
}
```

添加常量：

```java
public class Const {

    public static final String VERIFY_EMAIL_LIMIT = "verify:email:limit";

    public static final String VERIFY_EMAIL_DATA = "verify:email:data";
}
```

service添加：

```java
public interface AccountService extends IService<Account>, UserDetailsService {
    String registerEmailVerifyCode(String type,String email,String ip);
}
```

```java
@Service
public class AccountServiceImpl extends ServiceImpl<AccountMapper, Account> implements AccountService {
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

    @Resource
    private FlowUtils flowUtils;

    //根据ip判断是否在限制时间内
    private boolean verifyLimit(String ip) {
        String key = Const.VERIFY_EMAIL_LIMIT + ip;
        return flowUtils.limitOnceCheck(key, 60);
    }

}
```

使用Redis做一个限流：

```java
/**
 * 限流
 */
@Component
public class FlowUtils {

    @Resource
    StringRedisTemplate redisTemplate;

    public boolean limitOnceCheck(String key, int blockTime){
        if (Boolean.TRUE.equals(redisTemplate.hasKey(key))){
            return false;
        }else {
            redisTemplate.opsForValue().set(key,"",blockTime, TimeUnit.SECONDS);
            return true;
        }
    }
}
```

创建监听器：

```java
//通过监听器消费邮件队列
@Component
@RabbitListener(queues = "mail")
public class MailQueueListener {
    @Resource
    private JavaMailSender sender;

    @Value("${spring.mail.username}")
    String username;

    @RabbitHandler
    public void sendMailMessage(Map<String,Object> data){
        String email = (String) data.get("email");
        Integer code = (Integer) data.get("code");
        String type = (String) data.get("type");
        SimpleMailMessage message = switch (type){
            case "register" ->  createMessage("欢迎注册我们的网站","您的邮件注册验证码为："+code+"有效时间3分钟，为了保障您的安全，请勿向他人泄露验证码信息",email);
            case "reset" ->  createMessage("重置密码","您的密码重置验证码为："+code+"有效时间3分钟，为了保障您的安全，请勿向他人泄露验证码信息",email);
            default -> null;
        };
        if (message == null) return;
        sender.send(message);
    }

    //发送邮件
    private SimpleMailMessage createMessage(String title,String content,String email){
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject(title);
        message.setText(content);
        message.setTo(email);
        message.setFrom(username);
        return message;
    }
}
```

创建Controller：

```java
@RestController
@RequestMapping("/api/auth")
public class AuthorizeController {

    @Resource
    private AccountService accountService;
    @GetMapping("/ask-code")
    public RestBean<Void> askVerifyCode(@RequestParam String email,
                                        @RequestParam String type,
                                        HttpServletRequest request){
        String message = accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr());
        return message == null ? RestBean.success() : RestBean.failure(400, message);
    }
}
```

### 注册

对接口参数进行校验。

添加依赖：

```xml
<dependency>
	<groupId>org.springframework.boot</groupId>
	<artifactId>spring-boot-starter-validation</artifactId>
</dependency>
```

参数添加邮件验证及方式限制：

```java
@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthorizeController {

    @Resource
    private AccountService accountService;
    @GetMapping("/ask-code")
    public RestBean<Void> askVerifyCode(@RequestParam @Email String email,
                                        @RequestParam @Pattern( regexp = "(regoster|reset)") String type,
                                        HttpServletRequest request){
        String message = accountService.registerEmailVerifyCode(type, email, request.getRemoteAddr());
        return message == null ? RestBean.success() : RestBean.failure(400, message);
    }
}
```

通过exception进行错误处理：

```java
@Slf4j
@RestControllerAdvice
public class ValidationController {
    @ExceptionHandler(ValidationException.class)
    public RestBean<Void> validateException(ValidationException exception) {
        log.warn("Resolve:[{}：{}]",exception.getClass().getName(), exception.getMessage());
        return RestBean.failure(400, "参数验证有误");
    }
}
```

放行错误路径：

```java
return http
	.authorizeHttpRequests(conf -> conf
                         .requestMatchers("/api/auth/**","error").permitAll() //放行登陆请求
                         .anyRequest().authenticated() //所有请求都需要权限
)
```

请求实体类：

```java
@Data
public class EmailRegisterVO {
    @Email
    @Length(min=4)
    private String email;
    @Length(max = 6,min = 6)
    private String code;
    @Pattern(regexp = "^[a-zA-Z0-9\\u4e00-\\u9fa5]+$")
    @Length(min=1,max = 10)
    private String username;
    @Length(min = 6,max=20)
    private String password;
}
```

编写注册邮件账户：

```java
public interface AccountService extends IService<Account>, UserDetailsService {
  
	...
  
  String registerEmailAccount(EmailRegisterVO vo);
}
```

```java
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
```

数据库添加索引：

```sql
CREATE TABLE `db_account` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT 'Id\n',
  `username` varchar(255) DEFAULT NULL COMMENT '用户名\n',
  `password` varchar(255) DEFAULT NULL COMMENT '密码',
  `email` varchar(255) DEFAULT NULL COMMENT '邮箱',
  `role` varchar(255) DEFAULT NULL COMMENT '角色\n',
  `register_time` datetime DEFAULT NULL COMMENT '注册时间',
  PRIMARY KEY (`id`),
	UNIQUE KEY `unique_name` ( `username` ) USING BTREE,
UNIQUE KEY `unique_email` ( `email` ) USING BTREE
) ENGINE=InnoDB AUTO_INCREMENT=3 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
```

controller：

```java
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
}
```

### 密码重置

重置密码方案：

1. **方案一**：用户先带着验证码请求对应接口，然后后端存储对应用户已经通过的标记，用户填写新的密码之后，然后请求重置密码的借口，接口验证是否已经通过，然后才重置密码
2. **方案二**：用户带着验证码请求对应接口，然后后端仅对验证码是否正确进行验证，用户填写新的密码之后，请求重置密码接口，不仅需要带上密码还要之前的验证码一起，然后再次验证验证码如果正确，就重置密码

添加请求：

```java
@Data
@AllArgsConstructor
public class ConfirmResetVO {
    @Email
    private String email;
    @Length(min = 6,max = 6)
    private String code;

}
```

```java
@Data
public class EmailRestVO {
    @Email
    String email;
    @Length(min = 6,max = 6)
    String code;
    @Length(min = 5,max = 20)
    String password;
}
```

service：

```java
public interface AccountService extends IService<Account>, UserDetailsService {
  	。。。

    String resetConfirm(ConfirmResetVO vo);

    String resetEmailAccountPassword(EmailRestVO vo);
}
```

```java
    @Override
    public String resetConfirm(ConfirmResetVO vo) {
        String email = vo.getEmail();
        String code = stringRedisTemplate.opsForValue().get(Const.VERIFY_EMAIL_DATA + email);
        if(code == null) return "请先获取验证码";
        if (!code.equals(vo.getCode())) return "验证码错误，请重新输入";

        return null;
    }

    //重置密码
    @Override
    public String resetEmailAccountPassword(EmailRestVO vo) {
        String email = vo.getEmail();
        String verify = this.resetConfirm(new ConfirmResetVO(email, vo.getCode()));
        if (verify != null) return verify;
        String password = encoder.encode(vo.getPassword());
        boolean update = this.update().eq("email", email).set("password", password).update();
        if (update){
            stringRedisTemplate.delete(Const.VERIFY_EMAIL_DATA + email);
        }
        return null;
    }
```

controller：

```java
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
```

### 限流操作

```java
public static final int ORDER_CORS = -101;
public static final int ORDER_LIMIT = -102;

public static final String FLOW_LIMIT_COUNTER = "flow:counter:";
public static final String FLOW_LIMIT_BLOCK = "flow:block:";
```

```java
@Component
@Order(Const.ORDER_LIMIT)
public class FlowLimitFilter extends HttpFilter {

    @Resource
    private StringRedisTemplate stringRedisTemplate;

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String address = request.getRemoteAddr();
        if(this.tryCount(address)){
            chain.doFilter(request, response);
        }else {
            this.writeBlockMessage(response);
        }
    }

    private void writeBlockMessage(HttpServletResponse response) throws IOException {
        response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        response.setContentType("application/json;charset=utf-8");
        response.getWriter().write(RestBean.forbidden("访问过于频繁，请稍后再试").asJsonString());
    }
    private boolean tryCount(String ip){
        synchronized (ip.intern()){
            if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(Const.FLOW_LIMIT_BLOCK + ip))){
                return false;
            }
            return this.limitPeriodCheck(ip);
        }

    }

    private boolean limitPeriodCheck(String ip){
        if (Boolean.TRUE.equals(stringRedisTemplate.hasKey(Const.FLOW_LIMIT_COUNTER + ip))){
            Long increment = Optional.ofNullable(stringRedisTemplate.opsForValue().increment(Const.FLOW_LIMIT_COUNTER + ip)).orElse(0L);
            if (increment > 10){
                stringRedisTemplate.opsForValue().set(Const.FLOW_LIMIT_BLOCK + ip,"",30,TimeUnit.SECONDS);
                return false;
            }
        }else {
            stringRedisTemplate.opsForValue().set(Const.FLOW_LIMIT_COUNTER + ip,"1",3, TimeUnit.SECONDS);
        }
        return true;
    }
}
```

## 前端开发

### 创建项目

创建Vue项目：

![image-20240307135734061](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/imgimage-20240307135734061.png)

使用npm install 安装依赖

![image-20240307135906430](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/imgimage-20240307135906430.png)

### 基本页面配置

删除默认界面：

![image-20240308175448310](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031708471.png)

![image-20240308175613771](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031708051.png)

![image-20240308175703305](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031708987.png)

![image-20240308180031170](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031708982.png)

创建views目录来存放页面：

![image-20240308180141447](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031708215.png)

导入element-ui：

```bash
npm install element-plus --save
```

使用按需导入的方式来引入：

```bash
npm install -D unplugin-vue-components unplugin-auto-import
```

在vite.config.js：

```js
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
import AutoImport from 'unplugin-auto-import/vite'
import Components from 'unplugin-vue-components/vite'
import { ElementPlusResolver } from 'unplugin-vue-components/resolvers'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    vue(),
    AutoImport({
      resolvers: [ElementPlusResolver()],
    }),
    Components({
      resolvers: [ElementPlusResolver()],
    }),
  ],
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url))
    }
  }
})
```

创建基础页面：

```vue
<template>
  <!--  宽100vw 高100vh 超过部分隐藏 采用flex布局-->
  <div style="width: 100vw;height: 100vh;overflow: hidden;display: flex">
    <!--  左部区域  -->
    <div style="flex: 1;background-color: black">
      <!--      fit 不拉伸-->
      <el-image style="width: 100%;height: 100%" fit="cover"
                src="https://img1.baidu.com/it/u=4097856652,4033702227&fm=253&app=120&f=JPEG?w=1422&h=800"/>
    </div>
    <!--    使用绝对布局来做文字效果-->
    <div class="welcome-title">
      <div style="font-size: 30px;font-weight: bold">欢迎来到此项目</div>
      <div style="margin-top: 10px">希望你喜欢</div>
    </div>
    <!--   右部区域 -->
    <div class="right-card">
        <router-view/>
    </div>
  </div>
</template>
<script setup>

</script>


<style scoped>
.right-card {
  width: 400px;
  z-index: 1;
  background-color: white;
}

.welcome-title {
  position: absolute;
  bottom: 30px;
  left: 30px;
  color: white;
  text-shadow: 0 0 10px black;
}
</style>
```

创建views/welcome目录用于存放跳转的路由界面：

![image-20240308181747303](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031709670.png)

创建登录：

![image-20240308201645933](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031709069.png)

在前端路径下安装路由vue-router：

```bash
npm install vue-router
```

创建router目录来存放路由：

![image-20240308180509102](https://cdn.jsdelivr.net/gh/letengzz/tc2@main/img202405031709123.png)

创建路由信息：

```js
//引入createRouter
import {createRouter, createWebHistory} from "vue-router";

// 创建路由
const router = createRouter({
    history: createWebHistory(import.meta.env.BASE_URL),
    routes:[
        {
            //路径
            path: '/',
            //名称
            name: 'welcome',
            //组件名
            component: () => import('@/views/WelcomeView.vue'),
            // 子路由
            children: [
                {
                    path: '',
                    name: 'welcome-login',
                    component: ()=> import('@/views/welcome/LoginPage.vue')
                }
            ]
        }
    ]
})

//对外暴露
export default router
```

### 登录页面

```java
<script setup>
import {Lock, User} from "@element-plus/icons-vue";
import {reactive} from "vue";

const form = reactive({
  username: '',
  password: '',
  remember: false
})
</script>

<template>
  <!--  字体居中 左右隔开20px -->
  <div style="text-align: center;margin: 0 20px">
    <div style="margin-top: 150px">
      <div style="font-size: 25px;font-weight: bold">登录</div>
      <div style="font-size: 14px;color: gray">在进入系统之前，请先输入用户名和密码进行登录</div>
    </div>
<!--    输入框-->
    <div style="margin-top: 50px">
<!--      使用element ui 的表单实现-->
      <el-form :model="form">
        <el-form-item>
          <el-input v-model="form.username" maxlength="10" type="text" placeholder="用户名/邮箱">
            <!--插槽-->
            <template #prefix>
              <el-icon><User/></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item>
          <el-input v-model="form.password" maxlength="20" placeholder="密码">
            <!--插槽-->
            <template #prefix>
              <el-icon><Lock/></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-row>
          <el-col :span="12" style="text-align: left">
            <el-form-item>
              <el-checkbox v-model="form.remember" label="记住我"/>
            </el-form-item>
          </el-col>
          <el-col :span="12" style="text-align: right">
            <el-link>忘记密码？</el-link>
          </el-col>
        </el-row>
      </el-form>
      <div style="margin-top: 40px">
        <el-button style="width: 270px" type="success" plain>立即登录</el-button>
      </div>
      <el-divider>
        <span style="font-size: 13px;color: gray">没有账号</span>
      </el-divider>
      <div>
        <el-button style="width: 270px" type="warning" plain>立即注册</el-button>
      </div>
    </div>
  </div>
</template>

<style scoped>

</style>
```

### Axios 请求封装

安装axios：

```bash
npm install axios
```

> src/net/index.js

```js
//引入axios
import axios from 'axios'
import {ElMessage} from "element-plus";

//默认的错误处理失败
const defaultFailure = (message,code,url)=>{
    //控制台输出
    console.warn(`请求地址：${url}，状态码：${code},错误信息：${message}`)
    //element ui 弹窗警告
    ElMessage.warning(message)
}
const defaultError = (err)=>{
    //控制台输出
    console.error(err)
    //element ui 弹窗警告
    ElMessage.warning('发生来一些错误，请联系管理员')
}
//内部使用 post
function internalPost(url,data,header,success,failure,error = defaultError){
    axios.post(url,data,{headers:header}).then(({data})=>{
        if (data.code === 200){
            success(data.data)
        }else {
            failure(data.message,data.code,url)
        }
    }).catch(err => error(err))
}

//get
function internalGet(url,header,success,failure,error = defaultError){
    axios.get(url,{headers:header}).then(({data})=>{
        if (data.code === 200){
            success(data.data)
        }else {
            failure(data.message,data.code,url)
        }
    }).catch(err => error(err))
}

//login
function login(username,password,remember,success,failure = defaultFailure){
    internalPost('/api/auth/login',{
        username: username,
        password: password
    },{
        //Spring Security 只能是表单登录
        'Content-Type': 'application/x-www-form-urlencoded'
    },(data) =>{
        storeAccessToken(data.token,remember,data.expire)
        ElMessage.success(`登录成功，欢迎 ${data.username} 欢迎来到该系统`)
        success(data)
    },failure)
}

//名称统一
const authItemName = 'access_token'
//保存accessToken
function storeAccessToken(token,remember,expire){
    //封装成对象
    const authObj = { token:token,expire:expire}
    //根据remember 存储 是否到localStorage
    const str = JSON.stringify(authObj)
    if (remember)
        localStorage.setItem(authItemName,str)
    else
        sessionStorage.setItem(authItemName,str)
}

//取出accessToken
function takeAccessToken(){
    const str = localStorage.getItem(authItemName) || sessionStorage.getItem(authItemName)
    if (!str) return null;
    const authObj = JSON.parse(str)
    //如果时间小于当前时间 在 storage 中删除
    if (authObj.expire <= new Date()){
        deleteAccessToken()
        ElMessage.warning('登录状态已过期，请重新登录')
        return null;
    }
    return authObj.token
}

//删除token
function deleteAccessToken(){
    localStorage.removeItem(authItemName)
    sessionStorage.removeItem(authItemName)
}

//暴露
export {login}
```

登录：

```vue
<script setup>
import {Lock, User} from "@element-plus/icons-vue";
import {reactive,ref} from "vue";
import {login} from "@/net";

const form = reactive({
  username: '',
  password: '',
  remember: false
})

//判断是否输入 element ui 规则判断
const rule = {
  username: [
    {required:true,message:'请输入用户名'}
  ],
  password: [
    {required:true,message:'请输入密码'}
  ]
}

const formRef = ref()
function userLogin(){
  formRef.value.validate((valid)=>{
    if (valid){
      login(form.username,form.password,form.remember,() =>{})
    }
  })
}
</script>

<template>
  <!--  字体居中 左右隔开20px -->
  <div style="text-align: center;margin: 0 20px">
    <div style="margin-top: 150px">
      <div style="font-size: 25px;font-weight: bold">登录</div>
      <div style="font-size: 14px;color: gray">在进入系统之前，请先输入用户名和密码进行登录</div>
    </div>
<!--    输入框-->
    <div style="margin-top: 50px">
<!--      使用element ui 的表单实现-->
      <el-form :model="form" :rules="rule" ref="formRef">
        <el-form-item prop="username">
          <el-input v-model="form.username" maxlength="10" type="text" placeholder="用户名/邮箱">
            <!--插槽-->
            <template #prefix>
              <el-icon><User/></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="password">
          <el-input v-model="form.password" type="password" maxlength="20" placeholder="密码">
            <!--插槽-->
            <template #prefix>
              <el-icon><Lock/></el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-row>
          <el-col :span="12" style="text-align: left">
            <el-form-item prop="remember">
              <el-checkbox v-model="form.remember" label="记住我"/>
            </el-form-item>
          </el-col>
          <el-col :span="12" style="text-align: right">
            <el-link>忘记密码？</el-link>
          </el-col>
        </el-row>
      </el-form>
      <div style="margin-top: 40px">
        <el-button @click="userLogin()" style="width: 270px" type="success" plain>立即登录</el-button>
      </div>
      <el-divider>
        <span style="font-size: 13px;color: gray">没有账号</span>
      </el-divider>
      <div>
        <el-button style="width: 270px" type="warning" plain>立即注册</el-button>
      </div>
    </div>
  </div>
</template>

<style scoped>

</style>
```

导入Element-ui样式：

> index.html

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <link rel="icon" href="/favicon.ico">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
<!--      导入element ui 样式-->
      <link rel="stylesheet" href="https://unpkg.com/element-ui/lib/theme-chalk/index.css">
    <title>Vite App</title>
      <style>
          body{
              margin: 0;
          }
      </style>
  </head>
  <body>
    <div id="app"></div>
    <script type="module" src="./src/main.js"></script>
  </body>
</html>
```

配置Axios 默认地址：

> src/main.js

```javascript
//配置登录地址
axios.defaults.baseURL = 'http://localhost:8080'
```

### 退出登录

> src/net/index.js

```java
//删除token
function deleteAccessToken(){
    localStorage.removeItem(authItemName)
    sessionStorage.removeItem(authItemName)
}
//退出登录
function logout(success,failure){
    get('/api/auth/logout',() =>{
        deleteAccessToken()
        ElMessage.success('退出登录成功，欢迎您再次使用')
        success()
    },failure)
}
//获取请求头
function accessHeader(){
    const token = takeAccessToken();
    return token ? {
        'Authorization': `Bearer ${takeAccessToken()}`
    } : {}
}

//携带请求头的get方法
function get(url,success,failure = defaultFailure){
    internalGet(url,accessHeader(),success,failure)
}
//携带请求头的post方法
function post(url,data,success,failure = defaultFailure){
    internalPost(url,data,accessHeader(),success,failure)
}

//是否登录
function unauthorized(){
    return !takeAccessToken()
}
//暴露
export {login,logout,get,post,unauthorized}
```

> src/router/index.js

```js
{
    path: '/index',
    name: 'index',
    component: () =>import('@/views/IndexView.vue')
}
```

> src/views/WelcomeView.vue

```js
function userLogin(){
  formRef.value.validate((valid)=>{
    if (valid){
      login(form.username,form.password,form.remember,() =>{router.push('/index')})
    }
  })
}
```

> src/views/IndexView.vue

```vue
<!--主界面-->
<script setup>
import {logout} from "@/net/index.js";
import router from "@/router/index.js";

function userLogout(){
  logout(()=>router.push('/'))
}
</script>

<template>
<div>
  <el-button @click="userLogout">退出登录</el-button>
</div>
</template>

<style scoped>

</style>
```

### 路由守卫

> src/router/index.js

```js
import {unauthorized} from "@/net/index.js";
//配置路由守卫
router.beforeEach((to,from,next) =>{
    const isUnauthorized = unauthorized()
    if (to.name.startsWith('welcome-') && !isUnauthorized){
        next('/index')
    }else if (to.fullPath.startsWith('/index') && isUnauthorized){
        next('/')
    }else {
        next()
    }
})
```

### 注册

添加注册页面：

> src/views/welcome/RegisterPage.vue

```vue
<script setup>
import {computed, ref,reactive} from "vue";
import {EditPen, Lock, Message, User} from "@element-plus/icons-vue";
import router from "@/router/index.js";
import {ElMessage} from "element-plus";
import {get, post} from "@/net/index.js";

const form = reactive({
  username: '',
  password: '',
  password_repeat: '',
  email: '',
  code: ''
})
const validateUsername = (rule, value, callback) => {
  if (value === '') {
    callback(new Error('请输入用户名'))
  } else if (!/^[a-zA-Z0-9\u4e00-\u9fa5]+$/.test(value)) {
    callback(new Error('用户名不能包含特殊字符，只能使用中/英文'))
  } else {
    callback()
  }
}
const validatePassword = (rule, value, callback) => {
  if (value === '') {
    callback(new Error('请再次输入密码'))
  } else if (value !== form.password) {
    callback(new Error('两次输入的密码不一致'))
  }else {
    callback()
  }
}
// 判断规则
const rule = {
  // 校验
  username: [
    {validator: validateUsername, trigger: ['blur', 'change']},
    {min: 1, max: 10, message: '用户名长度在2-9位之间', trigger: ['blur']}
  ],
  password: [
    {required: true, message: '密码不能为空', trigger: ['blur']},
    {min: 6, max: 20, message: '密码长度在6-20位之间', trigger: ['blur', 'change']}
  ],
  password_repeat: [
    {required: true, message: '请再次输入密码', trigger: ['blur', 'change']},
    {validator: validatePassword,trigger: ['blur', 'change']}
  ],
  email:[
      {required: true, message: '请输入邮箱地址', trigger: ['blur']},
      {type: 'email', message: '请输入正确的邮箱地址', trigger: ['blur', 'change']}
  ],
  code:[
      {required: true, message: '请输入验证码', trigger: ['blur']},
      {min: 6, max: 6, message: '验证码长度为6位', trigger: ['blur', 'change']}
  ]
}
function askCode(){
  if(isEmailValid){
    coldTime.value = 60
    get(`/api/auth/ask-code?email=${form.email}&type=register`,()=>{
      ElMessage.success(`验证码已发送: ${form.email}, 请查收`)
      setInterval(() => coldTime.value--,1000)
    },(message)=>{
      ElMessage.warning(message)
      coldTime.value = 0
    })
  }else {
    ElMessage.warning('请输入正确的邮箱地址')
  }

}

//冷却时间
const coldTime = ref(0)
const isEmailValid = computed(() => /^[\w.-]+@[\w.-]+\.\w+$/.test(form.email))
const formRef = ref()
function register(){
  formRef.value.validate((valid) => {
    if (valid){
      post('api/auth/register',{...form},()=>{
        ElMessage.success('注册成功，欢迎加入')
        router.push('/')
      })
    }else {
      ElMessage.warning('请填写正确的信息')
    }
  })
}
</script>

<template>
  <div style="text-align: center;margin: 0 20px">
    <div style="margin-top: 100px">
      <div style="font-size: 25px;font-weight: bold">注册新用户</div>
      <div style="font-size: 14px;color: gray">欢迎注册我们的学习网站，请在下方填写相关信息</div>
    </div>
    <div style="margin-top: 50px">
      <el-form :model="form" :rules="rule" ref="formRef">
        <el-form-item prop="username">
          <el-input v-model="form.username" maxlength="10" type="text" placeholder="用户名">
            <template #prefix>
              <el-icon>
                <User/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="password">
          <el-input v-model="form.password" maxlength="20" type="password" placeholder="密码">
            <template #prefix>
              <el-icon>
                <Lock/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="password_repeat">
          <el-input v-model="form.password_repeat" maxlength="20" type="password" placeholder="重复密码">
            <template #prefix>
              <el-icon>
                <Lock/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="email">
          <el-input v-model="form.email"  type="email" placeholder="电子邮箱">
            <template #prefix>
              <el-icon>
                <Message/>
              </el-icon>
            </template>
          </el-input>
        </el-form-item>
        <el-form-item prop="code">
          <el-row :gutter="10" style="width: 100%;">
            <el-col :span="17">
              <el-input v-model="form.code" maxlength="6" type="text" placeholder="请输入验证码">
                <template #prefix>
                  <el-icon>
                    <EditPen/>
                  </el-icon>
                </template>
              </el-input>
            </el-col>
            <el-col :span="5">
              <el-button @click="askCode" :disabled="!isEmailValid || coldTime" type="success">
                {{coldTime ? `请稍等 ${coldTime}s` : '发送验证码'}}
              </el-button>
            </el-col>
          </el-row>
        </el-form-item>
      </el-form>
      <div style="margin-top: 80px">
        <el-button style="width: 270px" type="warning" @click="register" plain>注册</el-button>
      </div>
      <div style="margin-top: 20px">
        <span style="font-size: 14px;line-height: 15px;color: gray">已有账号？</span>
        <el-link style="translate: 0 -1px" @click="router.push('/')">立即登录</el-link>
      </div>
    </div>
  </div>
</template>

<style scoped>

</style>
```

添加路由：

```js
    routes:[
        {
            //路径
            path: '/',
            //名称
            name: 'welcome',
            //组件名
            component: () => import('@/views/WelcomeView.vue'),

            meta: { keepAlive: true }, // true：需要被缓存
            // 子路由
            children: [
                {
                    path: '',
                    name: 'welcome-login',
                    component: ()=> import('@/views/welcome/LoginPage.vue')
                },
                {
                    path: 'register',
                    name: 'welcome-register',
                    component: ()=> import('@/views/welcome/RegisterPage.vue')
                }
            ]
        },
```

登录界面跳转注册：

```vue
      <div>
        <el-button  @click="router.push('/register')" style="width: 270px" type="warning" plain>立即注册</el-button>
      </div>
```

添加渐入渐出：

> WelcomeView.vue

```vue
    <div class="right-card">
      <router-view  v-slot="{Component}">
        <transition name="el-fade-in-linear" mode="out-in">
          <component :is="Component"/>
        </transition>
      </router-view>
    </div>
```



### 密码重置页面

添加重置页面：

```vue
<script setup>
import {computed, reactive, ref} from 'vue'
import {EditPen, Lock, Message} from "@element-plus/icons-vue";
import {get, post} from "@/net/index.js";
import {ElMessage} from "element-plus";
import router from "@/router/index.js";

const active = ref(0)

const form=reactive({
  email:"",
  code:"",
  password:"",
  password_repeat:""
})
function askCode(){
  if(isEmailValid){
    coldTime.value = 60
    get(`/api/auth/ask-code?email=${form.email}&type=reset`,()=>{
      ElMessage.success(`验证码已发送: ${form.email}, 请查收`)
      setInterval(() => coldTime.value--,1000)
    },(message)=>{
      ElMessage.warning(message)
      coldTime.value = 0
    })
  }else {
    ElMessage.warning('请输入正确的邮箱地址')
  }

}

//冷却时间
const coldTime = ref(0)
const isEmailValid = computed(() => /^[\w.-]+@[\w.-]+\.\w+$/.test(form.email))
const validatePassword = (rule, value, callback) => {
  if (value === '') {
    callback(new Error('请再次输入密码'))
  } else if (value !== form.password) {
    callback(new Error('两次输入的密码不一致'))
  }else {
    callback()
  }
}
const rules = {
  email: [
    {required: true, message: '请输入电子邮件地址', trigger: 'blur'},
    {type: 'email', message: '请输入正确的电子邮件地址', trigger: ['blur', 'change']}
  ],
  code: [
    {required: true, message: '请输入验证码', trigger: 'blur'},
    {min: 6, max: 6, message: '验证码长度为6位', trigger: 'blur'}
  ],
  password: [
    {required: true, message: '请输入密码', trigger: 'blur'},
    {min: 6, max: 20, message: '密码长度为6-20位', trigger: 'blur'}
  ],
  password_repeat: [
    {required: true, message: '请再次输入密码', trigger: ['blur', 'change']},
    {validator: validatePassword,trigger: ['blur', 'change']}
  ]
}
const formRef = ref()
function confirmReset(){
  formRef.value.validate((valid) => {
    if (valid) {
      post('/api/auth/reset-confirm',{
        email:form.email,
        code:form.code
      },()=>active.value++,
          (message)=>{
        ElMessage.warning(message)
      })
    } else {
      return false;
    }
  })
}

function doRest(){
  formRef.value.validate((valid) => {
    if (valid) {
      post('/api/auth/reset-password',{...form},
          ()=>{
            ElMessage.success('密码重置成功，请重新登录')
            router.push('/')
          },
          (message)=>{
            ElMessage.warning(message)
          })
    } else {
      return false;
    }
  })
}
</script>

<template>
  <div style="text-align: center">
    <div style="margin-top: 30px">
      <el-steps :active="active" finish-status="success" align-center>
        <el-step title="验证电子邮件"></el-step>
        <el-step title="重新设定密码"></el-step>
      </el-steps>
    </div>
    <div>
      <div style="margin: 0 20px" v-if="active === 0">
        <div style="margin-top: 80px">
          <div style="font-size: 25px;font-weight: bold">重置密码</div>
          <div style="font-size: 14px;color: gray">请输入需要重置密码的电子邮件地址</div>
        </div>
        <div style="margin-top: 50px">
          <el-form :model="form" :rules="rules" ref="formRef">
            <el-form-item prop="email">
              <el-input placeholder="请输入电子邮件地址" v-model="form.email" type="email">
                <template #prefix>
                  <el-icon><Message/></el-icon>
                </template>
              </el-input>
            </el-form-item>
            <el-form-item prop="code">
              <el-row :gutter="10" style="width: 100%;">
                <el-col :span="17">
                  <el-input v-model="form.code" maxlength="6" type="text" placeholder="请输入验证码">
                    <template #prefix>
                      <el-icon>
                        <EditPen/>
                      </el-icon>
                    </template>
                  </el-input>
                </el-col>
                <el-col :span="5">
                  <el-button @click="askCode" :disabled="!isEmailValid || coldTime > 0" type="success">
                    {{coldTime ? `请稍等 ${coldTime}s` : '发送验证码'}}
                  </el-button>
                </el-col>
              </el-row>
            </el-form-item>
          </el-form>
        </div>
        <div style="margin-top: 80px">
          <el-button style="width: 270px" type="warning" @click="confirmReset" plain>开始重置密码</el-button>
        </div>
      </div>
      <div style="margin: 0 20px" v-if="active === 1">
        <div style="margin-top: 80px">
          <div style="font-size: 25px;font-weight: bold">重置密码</div>
          <div style="font-size: 14px;color: gray">请填写您的新密码，请务必牢记，以便下次登录</div>
        </div>
        <div style="margin-top: 50px">
          <el-form :model="form" :rules="rules" ref="formRef">
            <el-form-item prop="password">
              <el-input v-model="form.password" maxlength="20" type="password" placeholder="密码">
                <template #prefix>
                  <el-icon>
                    <Lock/>
                  </el-icon>
                </template>
              </el-input>
            </el-form-item>
            <el-form-item prop="password_repeat">
              <el-input v-model="form.password_repeat" maxlength="20" type="password" placeholder="重复密码">
                <template #prefix>
                  <el-icon>
                    <Lock/>
                  </el-icon>
                </template>
              </el-input>
            </el-form-item>
          </el-form>
        </div>
        <div style="margin-top: 80px">
          <el-button style="width: 270px" type="danger" @click="doRest" plain>立即重置密码</el-button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>

</style>
```

添加路由：

```javascript
{
	path: 'reset',
  name: 'welcome-reset',
  component: ()=> import('@/views/welcome/ResetPage.vue')
}
```

登录页面：

```vue
<el-link @click="router.push('/reset')">忘记密码？</el-link>
```

### 深色模式适配

安装vueuse：

```node
npm install @vueuse/core
```

配置：

> App.vue

```vue
<script setup>

import {useDark, useToggle} from "@vueuse/core";

useDark({
  selector: 'html',
  attribute: 'class',
  valueDark: 'dark',
  valueLight: 'light'
});

useDark({
  onChanged(dark){useToggle(dark)}
})
</script>
```

访问页面背景色：

```css
.right-card {
  width: 400px;
  z-index: 1;
  background-color: var(--el-bg-color);
}
```

