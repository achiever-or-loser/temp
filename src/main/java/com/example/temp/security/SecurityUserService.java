package com.example.temp.security;

import com.example.temp.security.domain.SecurityUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * @Description:
 * @PackageName: com.example.temp.security
 * @Author: 陈世超
 * @Create: 2021-03-23 10:22
 * @Version: 1.0
 */
@Service
public class SecurityUserService implements UserDetailsService {
    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
//        UserDTO userDTO = userService.getRolesByUsername(username);
        // 默认用户ID为1的为管理员
//        if (null != userDTO){
//            if(1L == userDTO.getId()) {
//                this.getAdminPermission(userDTO);
//            }
//            SecurityUser securityUser = new SecurityUser(LoginUserDTO.user2LoginUserDTO(userDTO));
//            return securityUser;
//        } else {
//            throw new UsernameNotFoundException(username + " 用户不存在!");
//        }
        return new SecurityUser();
    }
}
