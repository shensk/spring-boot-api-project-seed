package com.company.project.security.handler;

import com.company.project.core.ResultGenerator;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 自定401返回值
 * 自定义了身份验证失败的返回值
 * @author hackyo
 * Created on 2017/12/9 20:10.
 */
@Component
public class EntryPointUnauthorizedHandler implements AuthenticationEntryPoint {

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException e) throws IOException {
        response.setHeader("Access-Control-Allow-Origin", "*");
        response.setStatus(401);
        response.setHeader("Content-Type","application/json;charset=UTF-8");
        response.getWriter().println(ResultGenerator.genFailResult("token invalid"));
    }

}