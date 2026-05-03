package com.example.bola_security.dto;

import java.time.Instant;
import java.time.LocalDateTime;

public record AuthTokenResponse(
        String accessToken,
        String tokenType,
        Instant accessTokenExpiresAt,
        String refreshToken,
        LocalDateTime refreshTokenExpiresAt
) {
}
