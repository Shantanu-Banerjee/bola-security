package com.example.bola_security.service;

import java.time.LocalDateTime;

public record RequestContext(
        String ipAddress,
        String userAgent,
        String sessionId,
        String httpMethod,
        String requestPath,
        LocalDateTime accessTime
) {
}
