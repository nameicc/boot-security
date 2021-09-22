package com.tingyu.security.controller;

import com.tingyu.security.service.HelloService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.annotation.Resource;
import javax.servlet.http.HttpSession;

@Controller
public class HelloController {

    @Value("${server.port}")
    private Integer port;

    @Resource
    private HelloService helloService;

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

    @GetMapping("/detail")
    @ResponseBody
    public String detail() {
        helloService.hello();
        return "detail";
    }

    @GetMapping("/setSession")
    @ResponseBody
    public String setSession(HttpSession session) {
        session.setAttribute("player", "kobe");
        return port + "";
    }

    @GetMapping("/getSession")
    @ResponseBody
    public String getSession(HttpSession session) {
        String name = (String)session.getAttribute("player");
        return name + " : " + port;
    }

}
