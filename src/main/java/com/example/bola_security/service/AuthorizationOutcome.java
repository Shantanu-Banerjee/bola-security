package com.example.bola_security.service;

import com.example.bola_security.model.Resource;
import com.example.bola_security.model.User;

public record AuthorizationOutcome(
        User user,
        Resource resource,
        AccessContext context,
        AccessDecision decision
) {
}
