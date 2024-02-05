package com.study.jwt.app.user.service;

import com.study.jwt.app.authority.constants.Authority;
import com.study.jwt.app.user.dto.UserDto;
import com.study.jwt.app.user.entity.User;
import com.study.jwt.app.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public User signup(UserDto userDto) {

        if (userRepository.findOneByUserId(userDto.getUserId()).isPresent()) {
            throw new RuntimeException();
        }

        String encPwd = passwordEncoder.encode(userDto.getPassword());

        User user = User.builder()
                .userId(userDto.getUserId())
                .password(encPwd)
                .nickname(userDto.getNickname())
                .authority(Authority.ROLE_USER)
                .activated(true)
                .build();

        return userRepository.save(user);
    }

}
