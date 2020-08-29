package com.pingwazi.filter;

import cn.hutool.core.util.StrUtil;
import com.pingwazi.entity.UserEntity;
import com.pingwazi.service.UserService;
import com.pingwazi.utils.JwtUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

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