package com.pingwazi.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author pingwazi
 * @description
 */
@RestController
@RequestMapping("/home")
public class HomeController {
    @GetMapping("/index")
    public String index()
    {
        return "welcome to SpringSecurityForJWT";
    }
}
