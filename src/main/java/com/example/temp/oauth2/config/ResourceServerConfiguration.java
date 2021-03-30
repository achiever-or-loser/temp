package com.example.temp.oauth2.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.error.OAuth2AccessDeniedHandler;

/**
 * @Description:
 * @PackageName: com.example.temp.oauth2.config
 * @Author: 陈世超
 * @Create: 2021-03-23 15:38
 * @Version: 1.0
 */
@Configuration
@EnableResourceServer
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

    private static final String RESOURCE_ID = "oauth2";

    /**
     * 资源安全配置
     * ResourceServerSecurityConfigurer主要配置以下几方面：
     * tokenServices：ResourceServerTokenServices 类的实例，用来实现令牌访问服务，如果资源服务和授权服务不在一块，就需要通过RemoteTokenServices来访问令牌
     * tokenStore：TokenStore类的实例，定义令牌的访问方式
     * resourceId：这个资源服务的ID
     * 其他的拓展属性例如 tokenExtractor 令牌提取器用来提取请求中的令牌。
     */
    @Override
    public void configure(ResourceServerSecurityConfigurer resources) {
        // 如果stateless为 false关闭状态，则 accessToken 使用时的 session id 会被记录，后续请求不携带 accessToken 也可以正常响应
        // 如果stateless为 true 打开状态，则 每次请求都必须携带 accessToken 请求才行，否则将无法访问
        //resourceId 用于分配给可授予的clientId
        // stateless  标记以指示在这些资源上仅允许基于令牌的身份验证
        // tokenStore token的存储方式
        resources.resourceId(RESOURCE_ID).stateless(true);

        //authenticationEntryPoint  认证异常流程处理返回
        // tokenExtractor token获取方式,默认BearerTokenExtractor
        // 从header获取token为空则从request.getParameter("access_token")
//        resources.resourceId(RESOURCE_ID).stateless(true).tokenStore(tokenStore)
//                .authenticationEntryPoint(authenticationEntryPoint).tokenExtractor(unicomTokenExtractor);

        /**
         * 其他属性：
         * accessDeniedHandler          权失败且主叫方已要求特定的内容类型响应
         * resourceTokenServices        加载 OAuth2Authentication 和 OAuth2AccessToken 的接口
         *
         * eventPublisher                     事件发布-订阅  根据异常的clazz触发不同event
         */
    }

    /**
     * http安全配置
     * 为oauth2单独创建角色，这些角色只具有访问受限资源的权限，可解决token失效的问题
     * <p>
     * HttpSecurity配置这个与Spring Security类似：
     * 请求匹配器，用来设置需要进行保护的资源路径，默认的情况下是保护资源服务的全部路径。
     */
    @Override
    public void configure(HttpSecurity http) throws Exception {
//        AuthenticationManager oauthAuthenticationManager = oauthAuthenticationManager(http);
//        //OAuth2核心过滤器
//        resourcesServerFilter = new OAuth2AuthenticationProcessingFilter();
//        resourcesServerFilter.setAuthenticationEntryPoint(authenticationEntryPoint);
//        //OAuth2AuthenticationManager，只有被OAuth2AuthenticationProcessingFilter拦截到的oauth2相关请求才被特殊的身份认证器处理。
//        resourcesServerFilter.setAuthenticationManager(oauthAuthenticationManager);
//        if (eventPublisher != null) {
//            //同上
//            resourcesServerFilter.setAuthenticationEventPublisher(eventPublisher);
//        }
//        if (tokenExtractor != null) {
//            //同上
//            resourcesServerFilter.setTokenExtractor(tokenExtractor);
//        }
//        resourcesServerFilter = postProcess(resourcesServerFilter);
//        resourcesServerFilter.setStateless(stateless);

        http
                // 获取登录用户的 session
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .and()
                // 资源服务器拦截的路径 注意此路径不要和主过滤器冲突
                .requestMatchers()
                .antMatchers("/user/oauth/**");
        //
        http
                .authorizeRequests()
                // 配置资源服务器已拦截的路径才有效
                .antMatchers("/user/oauth/**").authenticated();
        // .access(" #oauth2.hasScope('select') or hasAnyRole('ROLE_超级管理员', 'ROLE_设备管理员')");
        //

        //accessDeniedHandler  异常 :  令牌不能访问该资源 （403）异常等
        //authenticationEntryPoint  异常 : 不传令牌，令牌错误（失效）等
        http
                .exceptionHandling()
                .accessDeniedHandler(new OAuth2AccessDeniedHandler())
                .and()
                .authorizeRequests()
                .anyRequest()
                .authenticated();
    }

}
