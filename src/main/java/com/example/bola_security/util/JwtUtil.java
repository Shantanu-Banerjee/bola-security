package com.example.bola_security.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class JwtUtil {

    public String extractToken(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        return header != null ? header.replace("Bearer ", "") : null;
    }

    public String extractUserId(String token) {
        // TEMP: Replace with real JWT parsing later
        return token;
    }
}