package com.study.jwt.app.user.entity;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Stream;

@Getter
@AllArgsConstructor
public class MyUserDetails implements UserDetails {
    private User user;

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Stream.of(user.getAuthority().name())
                .map(SimpleGrantedAuthority::new)
                .toList();
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUserId();
    }

    // 아래의 옵션들로 Spring Security가 발생시킨다.
    // false일 경우 인증을 허용하지 않고 사용자는 권한을 얻지못해 엑세스를 못함
    @Override
    public boolean isAccountNonExpired() {
        // 토큰 만료 확인하는 코드 필요
        return true;
    }

    // 계정이 잠겨있는지 확인 / 사용자 직접 or 비밀번호 틀리면
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    // 비밀번호 유효기간 -> 변경 요청
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    // 계정 활성화 / 시큐리티는 사용자가 인증하도록 허용한다.
    // false 일 경우
    @Override
    public boolean isEnabled() {
        return user.isActivated();
    }
}
