package com.study.jwt.app.user.service;

import com.study.jwt.app.user.dto.SignupDto;
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

    public User signup(SignupDto signupDto) {

        if (userRepository.findOneByUserId(signupDto.getUserId()).isPresent()) {
            throw new RuntimeException();
        }

        String encPwd = passwordEncoder.encode(signupDto.getPassword());
        signupDto.setPassword(encPwd);

        return userRepository.save(signupDto.toEntity());
    }

}
