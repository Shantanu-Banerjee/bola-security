package com.example.bola_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record LoginRequest(
        @NotBlank
        @Size(max = 80)
        String username,

        @NotBlank
        @Size(max = 255)
        String password
) {
}
