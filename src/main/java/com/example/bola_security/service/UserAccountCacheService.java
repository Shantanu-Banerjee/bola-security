package com.example.bola_security.service;

import com.example.bola_security.repository.UserRepository;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UserAccountCacheService {

    private final UserRepository userRepository;

    public UserAccountCacheService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Cacheable(value = "userAccounts", key = "#username")
    public CachedUserAccount load(String username) {
        return userRepository.findByUsername(username)
                .map(user -> new CachedUserAccount(
                        user.getUsername(),
                        user.getPassword(),
                        user.getRole(),
                        user.isAccountLocked(),
                        user.getTenantId()))
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }
}
