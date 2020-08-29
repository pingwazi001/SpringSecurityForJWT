package com.pingwazi.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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