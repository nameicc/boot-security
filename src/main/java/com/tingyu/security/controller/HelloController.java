package com.tingyu.security.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class HelloController {

    @GetMapping("/hello")
    @ResponseBody
    public String hello(){
        return "hello";
    }

    @GetMapping("/index")
    public String index(){
        return "redirect:index.html";
    }

    @GetMapping("/admin/hello")
    @ResponseBody
    public String adminHello(){
        return "admin";
    }

    @GetMapping("/user/hello")
    @ResponseBody
    public String userHello(){
        return "user";
    }

}
