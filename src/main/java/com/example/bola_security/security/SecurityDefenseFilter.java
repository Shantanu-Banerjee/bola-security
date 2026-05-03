package com.example.bola_security.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import static jakarta.servlet.http.HttpServletResponse.*;

/**
 * Security defense filter that applies rate limiting and threat detection
 * to all incoming requests.
 */
@Component
public class SecurityDefenseFilter extends OncePerRequestFilter {

    private final SecurityDefenseService securityDefenseService;

    public SecurityDefenseFilter(SecurityDefenseService securityDefenseService) {
        this.securityDefenseService = securityDefenseService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, 
                                  FilterChain filterChain) throws ServletException, IOException {
        
        String ipAddress = getClientIpAddress(request);
        String requestUri = request.getRequestURI();
        String userAgent = request.getHeader("User-Agent");

        // Apply rate limiting
        if (isRateLimited(ipAddress, requestUri)) {
            response.setStatus(429); // HTTP 429 Too Many Requests
            response.getWriter().write("{\"error\":\"Rate limit exceeded\"}");
            return;
        }

        // Apply IP blocking for known malicious IPs
        if (isIpBlocked(ipAddress)) {
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
            response.getWriter().write("{\"error\":\"Access denied\"}");
            return;
        }

        // Continue with the request
        filterChain.doFilter(request, response);
    }

    /**
     * Check if request should be rate limited
     */
    private boolean isRateLimited(String ipAddress, String requestUri) {
        // Different rate limits for different endpoints
        if (requestUri.startsWith("/api/v1/auth/login")) {
            return securityDefenseService.isLoginRateLimited(ipAddress);
        } else if (requestUri.startsWith("/api/v1/")) {
            return securityDefenseService.isIpRateLimited(ipAddress);
        }
        
        return false;
    }

    /**
     * Check if IP is blocked
     */
    private boolean isIpBlocked(String ipAddress) {
        // This would check against a blocked IP list
        // For now, return false (no IPs blocked)
        return false;
    }

    /**
     * Get client IP address considering proxies
     */
    private String getClientIpAddress(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }
        
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }
        
        return request.getRemoteAddr();
    }
}
