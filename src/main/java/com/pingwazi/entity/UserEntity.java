package com.pingwazi.entity;

import java.util.List;

/**
 * @author pingwazi
 * @description 用户信息实体
 */
public class UserEntity {
    private  String userName;
    private String password;
    private List<String> authorities;

    //======下面的代码都可以不手动编写，只是使用编辑工具的自动生成即可======
    public UserEntity() {
    }

    public UserEntity(String userName, String password) {
        this.userName = userName;
        this.password = password;
    }

    public UserEntity(String userName, String password, List<String> authorities) {
        this.userName = userName;
        this.password = password;
        this.authorities = authorities;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public List<String> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(List<String> authorities) {
        this.authorities = authorities;
    }

    @Override
    public String toString() {
        return "UserEntity{" +
                "userName='" + userName + '\'' +
                ", password='" + password + '\'' +
                ", authorities=" + authorities +
                '}';
    }
}
