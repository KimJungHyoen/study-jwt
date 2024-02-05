package com.study.jwt.app.login.controller;

import com.study.jwt.app.login.dto.LoginReqDto;
import com.study.jwt.app.login.dto.LoginRespDto;
import com.study.jwt.app.login.service.LoginService;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/login")
public class LoginController {

    private final LoginService loginService;

    @PostMapping
    public LoginRespDto login(@Validated @RequestBody LoginReqDto loginReqDto) {

        return loginService.login(loginReqDto);
    }
}
