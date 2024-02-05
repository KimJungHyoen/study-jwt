package com.study.jwt.app.user.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity(name = "users")
@Getter
@Setter
@NoArgsConstructor
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE)
    private long id;
    @Column(name = "user_id", length = 20)
    private String userId;
    @Column(length = 50)
    private String username;
    @Column(length = 100)
    private String password;
    private String nickname;
    private boolean activated;
}
