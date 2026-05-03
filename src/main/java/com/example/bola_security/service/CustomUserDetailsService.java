package com.example.bola_security.service;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.*;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserAccountCacheService userAccountCacheService;

    public CustomUserDetailsService(UserAccountCacheService userAccountCacheService) {
        this.userAccountCacheService = userAccountCacheService;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        CachedUserAccount user = userAccountCacheService.load(username);

        return new org.springframework.security.core.userdetails.User(
                user.username(),
                user.password(),
                true,
                true,
                true,
                !user.accountLocked(),
                List.of(new SimpleGrantedAuthority("ROLE_" + user.role().name()))
        );
    }
}
