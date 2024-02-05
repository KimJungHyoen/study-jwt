package com.study.jwt.app.user.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.study.jwt.app.authority.constants.Authority;
import jakarta.persistence.*;
import lombok.*;

@Entity(name = "users")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private long id;
    @Column(name = "user_id", length = 20)
    private String userId;
    @Column(length = 50)
    private String username;
    @Column(length = 100)
    @JsonIgnore
    private String password;
    private String nickname;
    private boolean activated;
    @Enumerated(EnumType.STRING)
    private Authority authority;
}
