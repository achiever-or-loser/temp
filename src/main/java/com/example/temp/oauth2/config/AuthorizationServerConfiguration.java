package com.example.temp.oauth2.config;

import com.example.temp.security.SecurityUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

/**
 * @Description: 配置ClientDetailsServiceConfigurer、AuthorizationServerEndpointsConfigurer、AuthorizationServerSecurityConfigurer
 * @PackageName: com.example.temp.oauth2.config
 * @Author: 陈世超
 * @Create: 2021-03-23 16:11
 * @Version: 1.0
 */
@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private SecurityUserService securityUserService;
    @Autowired
    private ClientDetailsService clientDetailsService;
    @Autowired
    private AuthorizationCodeServices authorizationCodeServices;
    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String RESOURCE_ONE = "oauth2";
    private static final String RESOURCE_TWO = "RESOURCE_TWO";

    /**
     * 配置从哪里获取ClientDetails信息。
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        // 1. 数据库的方式
//        clients.withClientDetails(clientDetails());
        // 2. 在内存中配置，这种方式不够灵活，学习倒是没有问题
        // //配置两个客户端,一个用于password认证一个用于client认证
        clients.inMemory().withClient("client_1")
                .resourceIds(RESOURCE_ONE)
                .authorizedGrantTypes("client_credentials", "refresh_token")
                .scopes("select")
                .authorities("client")
                .secret("123456")
                .and().withClient("client_2")
                .resourceIds(RESOURCE_TWO)
                .authorizedGrantTypes("password", "refresh_token")
                .scopes("select")
                .authorities("client")
                .secret("123456")
                .redirectUris("http://www.baidu.com")
        ;

    }


    /**
     * 声明授权和token的端点以及token的服务的一些配置信息，
     * 比如采用什么存储方式、token的有效期等
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) {

        endpoints
//                .tokenStore(tokenStore())
                // 配置授权管理认证对象
                .authenticationManager(authenticationManager)
                // 配置加载用户信息的服务
                .userDetailsService(securityUserService)
                // 授权码服务,添加就可以保存到数据库了
                .authorizationCodeServices(authorizationCodeServices)
                .setClientDetailsService(clientDetailsService);
    }


    /**
     * 声明安全约束，哪些允许访问，哪些不允许访问
     */

    /**
     * 配置：安全检查流程,用来配置令牌端点（Token Endpoint）的安全与权限访问
     * 默认过滤器：BasicAuthenticationFilter
     * 1、oauth_client_details表中clientSecret字段加密【ClientDetails属性secret】
     * 2、CheckEndpoint类的接口 oauth/check_token 无需经过过滤器过滤，默认值：denyAll()
     * 对以下的几个端点进行权限配置：
     * /oauth/authorize：授权端点
     * /oauth/token：令牌端点
     * /oauth/confirm_access：用户确认授权提交端点
     * /oauth/error：授权服务错误信息端点
     * /oauth/check_token：用于资源服务访问的令牌解析端点
     * /oauth/token_key：提供公有密匙的端点，如果使用JWT令牌的话
     **/
    @Override
    public void configure(AuthorizationServerSecurityConfigurer oauthServer) {
        oauthServer.allowFormAuthenticationForClients()//允许客户表单认证
                .passwordEncoder(passwordEncoder)//设置oauth_client_details中的密码编码器
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");

        //允许表单认证
        oauthServer.allowFormAuthenticationForClients();
        oauthServer.passwordEncoder(passwordEncoder);
        // 对于CheckEndpoint控制器[框架自带的校验]的/oauth/check端点允许所有客户端发送器请求而不会被Spring-security拦截
        oauthServer.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
        oauthServer.realm("oauth2");
    }
}
