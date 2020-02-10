package com.project.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controls {
    @GetMapping("/successResponse")
    private String asd() {
        return "success";
    }
    @GetMapping("/adminHome")
    private String asdq() {
        return "success";
    }
}
