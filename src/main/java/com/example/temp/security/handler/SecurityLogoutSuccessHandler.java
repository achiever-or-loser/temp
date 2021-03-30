package com.example.temp.security.handler;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * @Description:
 * @PackageName: com.example.temp.security.handler
 * @Author: 陈世超
 * @Create: 2021-03-23 10:01
 * @Version: 1.0
 */
@Component
@Slf4j
public class SecurityLogoutSuccessHandler implements LogoutSuccessHandler {
    @Override
    public void onLogoutSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        // 清除登录的session
        httpServletRequest.getSession().invalidate();
        log.info("退出成功");
    }
}
