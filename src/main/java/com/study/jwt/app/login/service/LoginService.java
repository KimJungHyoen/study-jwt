package com.study.jwt.app.login.service;

import com.study.jwt.app.login.dto.LoginReqDto;
import com.study.jwt.app.login.dto.LoginRespDto;
import com.study.jwt.core.jwt.TokenDto;
import com.study.jwt.core.jwt.TokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class LoginService {

    private final AuthenticationManager authenticationManager;

    private final TokenProvider tokenProvider;

    public LoginRespDto login(LoginReqDto loginReqDto) {
        UsernamePasswordAuthenticationToken authenticationToken =
                UsernamePasswordAuthenticationToken.unauthenticated(loginReqDto.getUserId(), loginReqDto.getPassword());

        final Authentication authentication = authenticationManager.authenticate(authenticationToken);

        TokenDto tokenDto = createTokenDto(authentication);

        return new LoginRespDto(loginReqDto.getUserId(), tokenDto);
    }

    private TokenDto createTokenDto(Authentication authentication) {

        String accessToken = tokenProvider.createAccessToken(authentication);
        String refreshToken = tokenProvider.createRefreshToken(authentication);

        return new TokenDto(accessToken, refreshToken);
    }
}

