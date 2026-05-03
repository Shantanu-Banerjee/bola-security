package com.example.bola_security.dto;

public record ResourceAccessResponse(
        boolean allowed,
        String reason,
        ResourceResponse resource
) {
}
