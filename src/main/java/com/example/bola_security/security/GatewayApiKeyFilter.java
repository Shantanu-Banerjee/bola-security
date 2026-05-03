package com.example.bola_security.security;

import com.example.bola_security.config.BolaSecurityProperties;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class GatewayApiKeyFilter extends OncePerRequestFilter {

    private static final String GATEWAY_HEADER = "X-Gateway-Api-Key";

    private final BolaSecurityProperties properties;

    public GatewayApiKeyFilter(BolaSecurityProperties properties) {
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (!request.getRequestURI().startsWith("/api/v1/gateway/")) {
            filterChain.doFilter(request, response);
            return;
        }

        String expected = properties.gatewayApiKey();
        String actual = request.getHeader(GATEWAY_HEADER);
        if (expected == null || expected.isBlank() || !expected.equals(actual)) {
            response.sendError(HttpStatus.FORBIDDEN.value(), "Missing or invalid gateway API key.");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
