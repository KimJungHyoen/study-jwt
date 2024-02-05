package com.study.jwt.app.login.dto;

import com.study.jwt.core.jwt.TokenDto;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
public class LoginRespDto {
    private String userId;
    private TokenDto tokenInfo;
}
