package com.example.temp.oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;

import javax.sql.DataSource;

/**
 * @Description:
 * @PackageName: com.example.temp.oauth2.config
 * @Author: 陈世超
 * @Create: 2021-03-23 16:27
 * @Version: 1.0
 */
//@Configuration
public class OauthConfig {
//    @Autowired
    DataSource dataSource;

    /**
     * 加入对授权码模式的支持
     */
//    @Bean
    public AuthorizationCodeServices authorizationCodeServices(DataSource dataSource) {
        return new JdbcAuthorizationCodeServices(dataSource);
    }
}
