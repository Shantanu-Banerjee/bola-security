package com.example.bola_security.service;

import com.example.bola_security.model.Role;

import java.io.Serializable;

public record CachedUserAccount(
        String username,
        String password,
        Role role,
        boolean accountLocked,
        String tenantId
) implements Serializable {
}
