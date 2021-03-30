package com.example.temp.security.config;

import com.example.temp.security.SecurityAuthenticationEntryPoint;
import com.example.temp.security.SecurityAuthenticationProvider;
import com.example.temp.security.handler.SecurityAccessDeniedHandler;
import com.example.temp.security.handler.SecurityAuthenticationFailureHandler;
import com.example.temp.security.handler.SecurityLogoutSuccessHandler;
import com.example.temp.security.handler.UserLoginSuccessHandler;
import com.example.temp.security.manager.UrlAccessDecisionManager;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.session.HttpSessionEventPublisher;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;

/**
 * @Description: 适配器
 * @PackageName: com.example.temp.security.config
 * @Author: 陈世超
 * @Create: 2021-03-23 10:39
 * @Version: 1.0
 */
@Configuration
@EnableWebSecurity
@Slf4j
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    private SecurityAuthenticationProvider securityAuthenticationProvider;
    @Autowired
    private UserLoginSuccessHandler userLoginSuccessHandler;
    @Autowired
    private SecurityAuthenticationFailureHandler securityAuthenticationFailureHandler;
    @Autowired
    private SecurityLogoutSuccessHandler securityLogoutSuccessHandler;
    @Autowired
    private SecurityAccessDeniedHandler securityAccessDeniedHandler;
    @Autowired
    private SecurityAuthenticationEntryPoint securityAuthenticationEntryPoint;
    @Autowired
    private UrlAccessDecisionManager urlAccessDecisionManager;

    /**
     * 访问静态资源
     */
    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers(
                "/css/**",
                "/js/**",
                "/images/**",
                "/fonts/**",
                "/favicon.ico",
                "/static/**",
                "/resources/**",
                "/error");
        // 也可以配置api为开头的接口，这表示WebSecurity可以过滤前后端的资源，只是更好的是比较适合前端过滤
//        web.ignoring().antMatchers("/login", "/error", "/api/open/**", "/api/user/login", "/api/user/logout" ,
//                "/session/invalid");
    }

    /**
     * 配置的是认证信息，向security提供真实的用户身份
     * 创建AuthenticationManager(用户身份的管理者, 是认证的入口)，
     */
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(securityAuthenticationProvider);
    }

    /**
     * 配置Security的认证策略,每个模块配置使用and()结尾
     * WebSecurity与HttpSecurity的区别：
     * 顾名思义，WebSecurity主要是配置跟web资源相关的，比如css、js、images等等，但是这个还不是本质的区别，关键的区别如下：
     * ingore是完全绕过了spring security的所有filter，相当于不走spring security
     * permitall没有绕过spring security，其中包含了登录的以及匿名的。
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                // 配置路径拦截，表明路径访问所对应的权限，角色，认证信息。
                .authorizeRequests()
                .anyRequest()
                .authenticated()
                .withObjectPostProcessor(urlObjectPostProcessor())
                .and()

                // 对应表单认证相关的配置
                .formLogin()
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .usernameParameter("username")
                .passwordParameter("password")
                .permitAll()
                .failureHandler(securityAuthenticationFailureHandler)
                .successHandler(userLoginSuccessHandler)
                .and()

                // 没有登录，没有权限
                .exceptionHandling()
                .authenticationEntryPoint(securityAuthenticationEntryPoint)
                .accessDeniedHandler(securityAccessDeniedHandler)
                .and()

                // 对应了注销相关的配置
                .logout()
                .deleteCookies("JSESSIONID")
                .logoutUrl("/logout")
                .logoutSuccessHandler(securityLogoutSuccessHandler)
                .permitAll()
                .and()

                // 关闭csrf，防止csrf攻击
                .csrf()
                .disable();

        http
                .sessionManagement()
                // 无效session跳转
                .invalidSessionUrl("/login")
                // 同账号最大允许登录数
                .maximumSessions(1)
                // session过期跳转
                .expiredUrl("/login")
                .sessionRegistry(sessionRegistry());
    }

    public ObjectPostProcessor urlObjectPostProcessor() {
        return new ObjectPostProcessor<FilterSecurityInterceptor>() {
            @Override
            public <O extends FilterSecurityInterceptor> O postProcess(O o) {
//                o.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource);
                o.setAccessDecisionManager(urlAccessDecisionManager);
                return o;
            }
        };
    }

    @Bean
    public SessionRegistry sessionRegistry() {
        return new SessionRegistryImpl();
    }

    /**
     * 解决session失效后 sessionRegistry中session没有同步失效的问题
     */
    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    /**
     * 设置加密方式
     */
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Override
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

//    public static void main(String[] args) {
//        LocalDateTime tradeDateTime = LocalDateTime.parse("2021/11/06 21:30:02", DateTimeFormatter.ofPattern("yyyy/MM/dd HH:mm:ss"));
//        ZoneId AmericaEastZone = ZoneId.of(ZoneId.SHORT_IDS.get("EST"));
//        tradeDateTime.atZone(ZoneOffset.UTC);
//        LocalDateTime zonedDateTime = tradeDateTime.atZone(ZoneId.systemDefault()).withZoneSameInstant(AmericaEastZone).withZoneSameInstant(AmericaEastZone).toLocalDateTime();
////        LocalDateTime localDateTime = tradeDateTime.atZone(ZoneId.systemDefault()).withZoneSameInstant(ZoneId.of("US/Eastern")).toLocalDateTime();
//        System.out.println(zonedDateTime.toString());
//        ZoneId zoneId = ZoneId.systemDefault();
//        System.out.println(tradeDateTime.atZone(ZoneId.systemDefault()).withZoneSameInstant(ZoneId.of("US/Eastern")).toLocalDateTime().toString());
//    }
}
