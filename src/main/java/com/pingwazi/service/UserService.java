package com.pingwazi.service;

import com.pingwazi.entity.UserEntity;

/**
 * @author pingwazi
 * @description 用户的业务方法
 */
public interface UserService {
     UserEntity getByUserName(String userName);
     String login(String userName,String password);
}
