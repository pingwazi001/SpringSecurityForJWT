# SpringBoot+SpringSecurity+JWT实现无状态登录认证
## 1、导包
```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.3.3.RELEASE</version>
    </parent>
    <groupId>com.pingwazi</groupId>
    <artifactId>SpringSecurityForJWT</artifactId>
    <version>1.0-SNAPSHOT</version>
    <dependencies>
        <!-- 引入web模块 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!-- spring security需要的包 -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <!-- jjwt需要的包 -->
        <dependency>
            <groupId>io.jsonwebtoken</groupId>
            <artifactId>jjwt</artifactId>
            <version>0.9.1</version>
        </dependency>
        <!-- hutool工具 -->
        <dependency>
            <groupId>cn.hutool</groupId>
            <artifactId>hutool-all</artifactId>
            <version>5.3.10</version>
        </dependency>
    </dependencies>
</project>
```
## 2、表写JwtUtils工具包
主要用于生成jwt token串和获取token串中的载荷值。现在只有两个最核心的方法，当然你可以吧这个工具包扩展得更加强大。
```java
/**
 * @author pingwazi
 * @description jwt 的工具包
 */
public class JwtUtils {
    private static final String jwtClaimKey="tokenObj-key";
    private static final String jwtSecretKey="jwtSecret-Key";

    /**
     * 生成jwt的token串
     * @param value
     * @return
     */
    public static String createJwtToken(String value)
    {
        HashMap<String,Object> claims=new HashMap<>();
        claims.put(jwtClaimKey,value);
        Calendar calendar=Calendar.getInstance();
        calendar.add(Calendar.HOUR_OF_DAY,24);//当前时间添加24是小时,即token在24小时后过期
        return Jwts.builder()
                .setClaims(claims)//设置载荷部分
                .setExpiration(calendar.getTime())//设置过期时间
                .signWith(SignatureAlgorithm.HS512, jwtSecretKey)//设置加密算法
                .compact();
    }

    /**
     * 从jwttoken串中获取载荷值
     * @param tokenStr
     * @return
     */
    public static String getJwtTokenClaimValue(String tokenStr)
    {
        String result=null;
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecretKey)
                    .parseClaimsJws(tokenStr)
                    .getBody();

            if(claims.getExpiration().compareTo(Calendar.getInstance().getTime())>0)
            {
                //token未过期
                result=claims.get(jwtClaimKey,String.class);
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result;
    }
}
```
## 3、创建UserEntity
```java
/**
 * @author pingwazi
 * @description 用户信息实体
 */
public class UserEntity {
    private  String userName;
    private String password;
    private List<String> authorities;

    //======下面的getter、setter、toString代码都可以不手动编写，只是使用编辑工具的自动生成即可======
 
```
## 4、编写UserService接口及其实现类
```java
/**
 * @author pingwazi
 * @description 用户的业务方法
 */
public interface UserService {
     UserEntity getByUserName(String userName);
     String login(String userName,String password);
}
//====下面是实现类====
/**
 * @author pingwazi
 * @description 用户信息实现类
 */
@Service
public class UserServiceImpl  implements UserService {
    /**
     * 通过用户名获取用户信息
     * @param userName
     * @return
     */
    @Override
    public UserEntity getByUserName(String userName) {
        //这里应该要访问存储介质获取到用户信息的，但是这些步骤都是十分常规的操作，因此这里跳过，直接模拟了访问数据
        List<String> authorities=new ArrayList<>();
        authorities.add("ALL");
        UserEntity user=new UserEntity("pingwazi","123",authorities);
        return user;
    }

    /**
     * 用户登录，如果账号密码比对成功，就生成一个token串返回给前端
     * @param userName
     * @param password
     * @return
     */
    @Override
    public String login(String userName, String password) {
        //这里应该要访问存储介质获取到用户信息的，但是这些步骤都是十分常规的操作，因此这里跳过，直接模拟了访问数据
        if("pingwazi".equals(userName) && "123".equals(password))
        {
           return JwtUtils.createJwtToken(userName);
        }
        return "";
    }
}
```
## 5、编写两个自定义的错误处理器
这两个类中的方法都是由spring security触发某种错误时才会调用的，比如说没有进行认证或者访问了没有权限的接口。
```java 
/**
 * @author pingwazi
 * @description 访问没有授权时的处理器
 */
@Component
public class RestfulAccessDeniedHandler implements AccessDeniedHandler {
    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException e) throws IOException, ServletException {
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json");
        response.setStatus(200);
        response.getWriter().println("您当前访问未授权");//这里返回一个字符串，可以吧一个对象序列化之后再返回。
        response.getWriter().flush();
    }
}



/**
 * @author pingwazi
 * @description 认证信息失效（未认证或者认证信息过期）处理器
 */
@Component
public class RestfulAuthenticationEntryPoint implements AuthenticationEntryPoint {
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.setCharacterEncoding("utf-8");
        response.setContentType("application/json");
        response.setStatus(200);
        response.getWriter().println("您当前的认证信息无效");//这里的返回信息是一个字符串，也就是说可以是吧一个对象序列化再放回
        response.getWriter().flush();
    }
}
```
## 6、自定义JWT认证的核心Filter
虽然这里的实现是给予JWT进行实现的，但如果你明白了其原理，实际上你可以将其改造为任何方式的方式
```java
/**
 * @author pingwazi
 * @description
 */
@Component
public class JWTAuthenticationTokenFilter extends OncePerRequestFilter {
    @Autowired
    private UserService userService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        //当前上下文中不存在认证信息
        //尝试获取token （token不一定存放在header中，比如也可以当做请求参数进行传递）
        //尝试从token中解析对象 （token中可以存放任何信息）
        //尝试从根据存放在token的信息去找对应的用户信息
        //用户找到用户信息信息 就在当前的认证上下文中进行设置,确保后续的filter能够检测到认证通过
        if (SecurityContextHolder.getContext().getAuthentication() == null) {
            String tokenStr = request.getHeader("token");
            if (StrUtil.isNotBlank(tokenStr)) {
                String tokenObj = JwtUtils.getJwtTokenClaimValue(tokenStr);
                if (StrUtil.isNotBlank(tokenObj)) {
                    UserEntity user = userService.getByUserName(tokenObj);
                    if (user != null) {
                        List<SimpleGrantedAuthority> authorities = new ArrayList<>();
                        if (user.getAuthorities() != null && user.getAuthorities().size() > 0) {
                            authorities = user.getAuthorities().stream().map(a -> new SimpleGrantedAuthority(a)).collect(Collectors.toList());
                        }
                        //设置当前上下文的认证信息
                        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(tokenObj, "", authorities);
                        authentication.setDetails(user);
                        SecurityContextHolder.getContext().setAuthentication(authentication);
                    }
                }

            }
        }
        //调用下一个过滤器
        chain.doFilter(request, response);
    }
}
```
## 7、编写SpringSecurity的配置类
配置类中使用了我们自定义的filter和两个错误处理器，其中配置那些接口允许访问，那些接口不能放回也是十分方便的。
```java
/**
 * @author pingwazi
 * @description
 */
@Configuration
public class SecurityConfigurer extends WebSecurityConfigurerAdapter {
    @Autowired
    private RestfulAccessDeniedHandler restfulAccessDeniedHandler;
    @Autowired
    private RestfulAuthenticationEntryPoint restfulAuthenticationEntryPoint;
    @Autowired
    private JWTAuthenticationTokenFilter jwtAuthenticationTokenFilter;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()//不使用防跨站攻击
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)//不使用session
                .and()
                .authorizeRequests()
                .antMatchers(HttpMethod.GET, "/",
                        "/*.html",
                        "/favicon.ico",
                        "/**/*.html",
                        "/**/*.css",
                        "/**/*.js",
                        "/swagger-resources/**",
                        "/v2/api-docs/**").permitAll()//允许静态资源无授权访问
                .and()
                .authorizeRequests().antMatchers("/admin/login", "/admin/register").permitAll()//允许登录接口、注册接口访问
                .and()
                .authorizeRequests().antMatchers(HttpMethod.OPTIONS).permitAll()//配置跨域的option请求，跨域请求之前都会进行一次option请求
                .and()
                .authorizeRequests().anyRequest().authenticated();//其他没有配置的请求都需要身份认证
        http.headers().cacheControl();//http的cache控制，如下这句代码会禁用cache
        http.addFilterBefore(jwtAuthenticationTokenFilter, UsernamePasswordAuthenticationFilter.class);//添加JWT身份认证的filter
        //添加自定义未授权的处理器
        http.exceptionHandling().accessDeniedHandler(restfulAccessDeniedHandler);
        //添加自定义未登录的处理器
        http.exceptionHandling().authenticationEntryPoint(restfulAuthenticationEntryPoint);
    }
}
```
