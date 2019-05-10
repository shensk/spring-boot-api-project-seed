package com.company.project.security.auth;

import com.company.project.dao.UserMapper;
import com.company.project.model.User;
import com.company.project.security.model.JwtUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * 用户验证方法
 *
 * @author hackyo
 * Created on 2017/12/8 9:18.
 */
@Service
public class JwtUserDetailsServiceImpl implements UserDetailsService {

    @Resource
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User selectUser = new User();
        selectUser.setUsername(username);
        User re = userMapper.selectOne(selectUser);
        if (re == null) {
            throw new UsernameNotFoundException(String.format("No user found with username '%s'.", username));
        } else {
            List<String> roles = new ArrayList<String>();
            roles.add("ROLE_USER");
            return new JwtUser(re.getUsername(), re.getPassword(), roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList()));
        }
    }

}