package com.example.bola_security.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * DEPRECATED: Custom JWT parsing no longer used. 
 * JWT validation and claim extraction handled by Spring Security oauth2ResourceServer
 * and SecurityContextHolder.getContext().getAuthentication() -> JwtAuthenticationToken.getToken().getClaim("uid").
 * Use JwtTokenService for server-side token operations.
 */
@Deprecated
@Component
public class JwtUtil {

    // Methods disabled - use SecurityContext
}
