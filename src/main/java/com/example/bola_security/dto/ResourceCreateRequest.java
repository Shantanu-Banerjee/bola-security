package com.example.bola_security.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record ResourceCreateRequest(
        @NotBlank
        @Size(max = 120)
        @Pattern(regexp = "^[A-Za-z0-9 ._()\\-]+$", message = "must contain only letters, numbers, spaces, and basic punctuation")
        String name,

        @NotBlank
        @Size(max = 80)
        @Pattern(regexp = "^[A-Za-z0-9 ._()\\-]+$", message = "must contain only letters, numbers, spaces, and basic punctuation")
        String department,

        @Size(max = 500)
        String description
) {
}
