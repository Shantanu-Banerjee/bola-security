package com.example.bola_security.filter;

import com.example.bola_security.service.BolaDetectionService;
import com.example.bola_security.service.RequestForwardingService;
import com.example.bola_security.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.*;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class BolaSecurityFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;
    private final BolaDetectionService bolaDetectionService;
    private final RequestForwardingService forwardingService;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        if (!request.getRequestURI().startsWith("/api")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = jwtUtil.extractToken(request);

        if (token == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Missing Token");
            return;
        }

        String userId = jwtUtil.extractUserId(token);
        String resourceId = extractResourceId(request);

        boolean allowed = bolaDetectionService.validateAccess(userId, resourceId, request);

        if (!allowed) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "BOLA Attack Detected");
            return;
        }

        forwardingService.forward(request, response);
    }

    private String extractResourceId(HttpServletRequest request) {
        String[] parts = request.getRequestURI().split("/");
        return parts.length >= 3 ? parts[2] : "unknown";
    }
}