package com.study.jwt.app.user.service;

import com.study.jwt.app.user.entity.MyUserDetails;
import com.study.jwt.app.user.entity.User;
import com.study.jwt.app.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class MyUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user = userRepository.findOneByUserId(username);
        if (user.isPresent()) {
            return new MyUserDetails(user.get());
        } else {
            throw new UsernameNotFoundException(username);
        }
    }
}
