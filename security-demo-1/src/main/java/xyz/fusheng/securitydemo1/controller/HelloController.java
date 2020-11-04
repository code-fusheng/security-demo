package xyz.fusheng.securitydemo1.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @FileName: HelloController
 * @Author: code-fusheng
 * @Date: 2020/11/3 11:13
 * @version: 1.0
 * Description:
 */

@RestController
public class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "Hello";
    }

    @GetMapping("/admin/hello")
    public String admin() {
        return "admin";
    }

    @GetMapping("/user/hello")
    public String user() {
        return "user";
    }

    @GetMapping("/rememberMe")
    public String rememberMe() {
        return "rememberMe";
    }

    @GetMapping("/autoTest1")
    public String autoTest1() {
        return "autoTest1";
    }

    @GetMapping("/autoTest2")
    public String autoTest2() {
        return "autoTest2";
    }

}
