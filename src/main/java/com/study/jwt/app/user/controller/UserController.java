package com.study.jwt.app.user.controller;

import com.study.jwt.app.user.dto.UserDto;
import com.study.jwt.app.user.entity.User;
import com.study.jwt.app.user.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/user")
public class UserController {

    private final UserService userService;

    @PostMapping("/signup")
    public User signup(@Validated @RequestBody UserDto userDto) {
        return userService.signup(userDto);
    }
}
