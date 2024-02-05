package com.study.jwt.app.login.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class LoginReqDto {
    @NotBlank
    private String userId;
    @NotBlank
    private String password;
}
