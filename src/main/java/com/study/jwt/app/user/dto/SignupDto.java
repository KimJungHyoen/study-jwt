package com.study.jwt.app.user.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.study.jwt.app.authority.constants.Authority;
import com.study.jwt.app.user.entity.User;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SignupDto {
    @NotBlank
    private String userId;
    @NotBlank
    @JsonProperty(access = JsonProperty.Access.WRITE_ONLY)
    private String password;
    private String nickname;
    private String username;

    public User toEntity() {
        return User.builder()
                .userId(userId)
                .username(username)
                .password(password)
                .nickname(nickname)
                .activated(true)
                .authority(Authority.ROLE_USER)
                .build();
    }

}
