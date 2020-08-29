package com.pingwazi.controller;

import com.pingwazi.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author pingwazi
 * @description
 */
@RestController()
@RequestMapping("/admin")
public class AdminController {
    @Autowired
    private UserService userService;
    @GetMapping("/login")
    public String login(@RequestParam String userName,@RequestParam String password) {
        return userService.login(userName,password);
    }
}
