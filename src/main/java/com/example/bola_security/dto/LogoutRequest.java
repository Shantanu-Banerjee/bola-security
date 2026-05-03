package com.example.bola_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LogoutRequest(
        @NotBlank
        @Size(max = 500)
        String refreshToken
) {
}
