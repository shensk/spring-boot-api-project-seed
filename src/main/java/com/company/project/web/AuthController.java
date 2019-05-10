package com.company.project.web;

import com.company.project.core.Result;
import com.company.project.core.ResultGenerator;
import com.company.project.model.User;
import com.company.project.service.IUserService;
import com.company.project.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Autowired
    private IUserService iUserService;

    @Resource
    private UserService userService;

    /**
     * 用户登录
     *
     * @param username 用户名
     * @param password 密码
     * @return 操作结果
     * @throws AuthenticationException 错误信息
     */
    @PostMapping(value = "/login", params = {"username", "password"})
    public Result getToken(String username, String password) throws AuthenticationException {
        try {
            User user = userService.findBy("username",username);
            Map<String,Object> map = new HashMap<String,Object>();
            user.setPassword("*");
            user.setRegisterDate(new Date(user.getRegisterDate().getTime() / 1000));
            map.put("user",user);
            map.put("token",iUserService.login(username, password));
            return ResultGenerator.genSuccessResult(map);
        }catch (Exception e){
            return ResultGenerator.genFailResult("账号或密码错误");
        }
    }

    /**
     * 用户注册
     *
     * @param user          用户信息
     * @return 操作结果
     * @throws AuthenticationException 错误信息
     */
    @PostMapping(value = "/register")
    public String register(User user) throws AuthenticationException {
        return iUserService.register(user);
    }

    /**
     * 刷新密钥
     *
     * @param authorization 原密钥
     * @return 新密钥
     * @throws AuthenticationException 错误信息
     */
    @GetMapping(value = "/refreshToken")
    public String refreshToken(@RequestHeader String authorization) throws AuthenticationException {
        return iUserService.refreshToken(authorization);
    }
}
