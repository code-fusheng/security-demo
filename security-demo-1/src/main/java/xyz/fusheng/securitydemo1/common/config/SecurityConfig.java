package xyz.fusheng.securitydemo1.common.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.authentication.*;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.io.PrintWriter;

/**
 * @FileName: SecurityConfig
 * @Author: code-fusheng
 * @Date: 2020/11/3 13:27
 * @version: 1.0
 * Description: SecurityConfig 安全框架配置类
 * 1、继承 WebSecurityConfigurerAdapter 网络安全配置适配器
 * 2、
 * 3、
 * 4、
 *
 * Spring Security : 认证流程简析
 * 1、AuthenticationProvider(身份验证提供者) -> 验证逻辑 #authenticate() 验证用户身份; #supports() 判断当前 AuthenticationProvider 是否支持对应的 Authentication
 * 2、【Authentication】 -> 当前登录用户信息 PS:可以在任何地方注入 (翻译：身份验证)
 * public interface Authentication extends Principal, Serializable {
 * 	  Collection<? extends GrantedAuthority> getAuthorities();  // 获取用户的权限
 *    Object getCredentials();      // 获取用户凭证，一般就是密码
 *    Object getDetails();          // 获取用户携带的详细信息，可能是当前请求之类的
 *    Object getPrincipal();        // 获取当前用户，可能是一个用户名，可能是一个用户对象
 *    boolean isAuthenticated();    // 判断当前用户是否认证成功
 *    void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException;
 * }
 * PS: Authentication 作为一个接口，定义了用户，或者说 Principal(当事人) 的一些基本行为，有很多实现类
 * 直接实现类 AbstractAuthenticationToken
 * 间接实现类 UsernamePasswordAuthenticationToken
 * 间接实现类 RememberMeAuthenticationToken
 * 。。。
 * 每一个 Authentication 都有适合它的 AuthenticationProvider 去处理校验
 * 比如:
 * UsernamePasswordAuthenticationToken --> DaoAuthenticationProvider
 *
 * 3、DaoAuthenticationProvider : 处理用户名/密码 登录
 * 父类 --> AbstractUserDetailsAuthenticationProvider
 * #Authentication authenticate(Authentication authentication) : 认证的方法
 * ① authentication.getName() 从 Authentication 提取登录用户名
 * ② user = retrieveUser(username, (UsernamePasswordAuthenticationToken) authentication) 获取当前用户对象 -> #
 * ③ preAuthenticationChecks.check(user) 检查账户是否被禁用、是否被锁定、是否过期
 * ④ additionalAuthenticationChecks(user, (UsernamePasswordAuthenticationToken) authentication) 密码对比
 * PS: 上述方法其实是抽象方法，具体实现在 AbstractUserDetailsAuthenticationProvider 的子类 DaoAuthenticationProvider，因为作为一个通用的父类，只处理一些通用的行为
 * 有时候登录不需要密码就没必要进行密码核对
 * ⑤ postAuthenticationChecks.check(user) 检查密码是否过期
 * ⑥ forcePrincipalAsString 默认 false 负责 Authentication -> principal 属性设置字符串
 * ⑦ createSuccessAuthentication(principalToReturn, authentication, user) 构建新的 UsernamePasswordAuthenticationToken

 * #boolean supports(Class<?> authentication) : 判断当前的 Authentication 是否是 UsernamePasswordAuthenticationToken
 *
 * 既然 AbstractUserDetailsAuthenticationProvider 实现了那么多东西 那么 DaoAuthenticationProvider 只需关注 additionalAuthenticationChecks() 密码对比
 * ！！！matches() 方法
 *
 * AuthenticationProvider 都是通过 ProviderManager(Provider 管理者)#authenticate(Authentication authentication) 调用
 * 循环遍历调用
 * for (AuthenticationProvider provider : getProviders()) {
 * 			if (!provider.supports(toTest)) {
 * 				continue;
 *          }
 *          ...
 *          ...
 *          result = provider.authenticate(authentication);
 *          ...
 *     }
 * 该方法会遍历所有的 AuthenticationProvider，并调用 authenticate() 方法进行认证
 *
 */

@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {


    @Bean
    PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("fusheng").password("123456").roles("admin").build());
        manager.createUser(User.withUsername("zhanghao").password("123").roles("user").build());
        return manager;
    }

    @Bean
    RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl hierarchy = new RoleHierarchyImpl();
        hierarchy.setHierarchy("ROLE_admin > ROLE_user");
        return hierarchy;
    }

    // @Override
    // protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
    //     // inMemoryAuthentication 开启在内存中定义用户
    //     authenticationManagerBuilder.inMemoryAuthentication()
    //             .withUser("fusheng").password("123456").roles("admin")
    //             .and()
    //             .withUser("zhanghao").password("123456").roles("user")
    //             ;
    // }

    @Override
    public void configure(WebSecurity web) throws Exception {
        // web.ignoring() 用来配置忽略掉 URL 地址，对于静态文件也可以这样操作
        web.ignoring().antMatchers("/js/**", "/css/**", "/images/**");
    }

    /**
     *
     * @param http
     * @throws Exception
     * 1、FormLoginConfigurer --> form 表单的相关配置 该类继承 AbstractAuthenticationFilterConfigurer 类，
     * 当 FormLoginConfigurer 初始化时， AbstractAuthenticationFilterConfigurer 也会初始化
     * 在 AbstractAuthenticationFilterConfigurer 的构造方法中可以看到 this.setLoginPage("/login");
     * 在 FormLoginConfigurer -> 构造方法中调用了父类的 init() 方法，其中 updateAuthenticationDefaults 指明了在没有设置 loginProcessingUrl 时默认 == loginPage
     *
     * 2、UsernamePasswordAuthenticationFilter 用户名密码身份验证过滤器
     * 在过滤器中通过 obtainUsername() obtainPassword() 方法从 Request 中获取用户名与密码
     *
     * 3、TokenBasedRememberMeServices -> onLoginSuccess -> tokenLifetime token存活时间（默认两周）
     * 设置记住我之后，会在客户端浏览器设置 Cookie: JSESSIONID=914527C5DC9B23EB20A5902F89912538; remember-me=ZnVzaGVuZzoxNjA1Njk4MjY5OTY5Ojg3Mzc3NzEyMTdlN2M4MDQ0YmZjZWY3ZjQyOGVmNDNk
     * PS: 服务端重启之后会失效，使用自定义的 key 解决这个问题
     * 源码分析参考流程:
     * AbstractAuthenticationProcessingFilter(抽象身份验证处理器)#doFilter ->
     * AbstractAuthenticationProcessingFilter#successfulAuthentication(身份验证成功) ->
     * AbstractRememberMeServices(记住我抽象业务类)#loginSuccess
     * 记住我认证参考流程:
     * Spring Security 系列功能都是一个过滤器链实现，RememberMe --> RememberMeAuthenticationFilter(记住我身份验证过滤器)#doFilter
     * 首先从 SecurityContextHolder 中获取当前登录用户实例，如果没有就调用 rememberMeServices.autoLogin()
     * RememberMeServices#autoLogin() --> AbstractRememberMeServices#autoLogin()
     * 通过 this.extractRememberMeCookie(request) 获取 cookie 信息，然后对其进行【解码】
     * processAutoLoginCookie(cookieTokens, request, response) 校验 : 核心流程
     * 首先获取用户名和过期时间，再根据用户名查询用户密码，然后通过 MD5 散列函数计算出散列值，再将拿到的散列值和浏览器传递过来的散列值进行对比，就能确认这个令牌是否有效。
     *
     *
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // <intercept-url> 拦截地址
        http.authorizeRequests()
                // 只有通过自动登录的才能访问
                .antMatchers("/rememberMe").rememberMe()
                .antMatchers("/admin/**").hasRole("admin")
                .antMatchers("/user/**").hasRole("user")
                // fullyAuthenticated 不包含自动登录
                .antMatchers("/autoTest1").fullyAuthenticated()
                // authenticated 包含自动登录
                .antMatchers("/autoTest2").authenticated()
                // anyRequest 不能放在 antMatchers 之前
                // anyRequest 一定配置在最后
                // 剩余的接口请求都需要登录认证
                .anyRequest().authenticated()
                .and()
                .formLogin()
                // 登录页面地址
                // .loginPage("/login.html")
                // 登录接口地址
                .loginProcessingUrl("/doLogin")
                // 用户名
                .usernameParameter("name")
                // 密码
                .passwordParameter("pwd")
                // 登录成功回调 defaultSuccessUrl | successForwardUrl
                // .defaultSuccessUrl("/index")
                .successForwardUrl("/index")
                // 登录失败回调 failureForwardUrl | failureUrl
                // .failureForwardUrl()
                // .failureUrl()
                // 登录成功处理 authentication 保存登录成功的用户信息
                .successHandler((req, resp, authentication) -> {
                    // 当事人
                    Object principal = authentication.getPrincipal();
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write(new ObjectMapper().writeValueAsString(principal));
                    out.flush();
                    out.close();
                })
                // 登录失败处理 exception 异常类型信息
                .failureHandler((req, resp, e) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    if (e instanceof LockedException) {
                        out.write("账户被锁定");
                    } else if ( e instanceof CredentialsExpiredException) {
                        out.write("密码过期");
                    } else if ( e instanceof AccountExpiredException) {
                        out.write("账号过期");
                    } else if ( e instanceof DisabledException) {
                        out.write("账户被禁用");
                    } else if ( e instanceof BadCredentialsException) {
                        out.write("用户名或密码错误");
                    } else if ( e instanceof UsernameNotFoundException) {
                        out.write("用户名查找失败");
                    }
                    out.write(e.getMessage());
                    out.flush();
                    out.close();
                })


                // 注销登录 默认是 /logout
                .and()
                // 记住我，自动登录
                .rememberMe()
                .key("fusheng")
                .and()
                .logout()
                .logoutUrl("/logout")
                .logoutSuccessHandler((req, resp, authentication) -> {
                    resp.setContentType("application/json;charset=utf-8");
                    PrintWriter out = resp.getWriter();
                    out.write("注销成功");
                    out.flush();
                    out.close();
                })
                // 清除 cookies
                .deleteCookies()
                // 清除认证信息
                .clearAuthentication(true)
                // 使Http会话失效
                .invalidateHttpSession(true)
                .permitAll()
                .and()
                .csrf().disable()
                .exceptionHandling()

                // 尚未登录逻辑处理，重定向还是forward跳转
                // .authenticationEntryPoint((req, resp, authException) -> {
                //     resp.setContentType("application/json;charset=utf-8");
                //     PrintWriter out = resp.getWriter();
                //     out.write("尚未登录，请先登录");
                //     out.flush();
                //     out.close();
                // })

                ;
    }
}
