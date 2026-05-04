package com.example.bola_security.filter;

import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.service.BolaDetectionService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.springframework.context.annotation.Profile;

@Profile("!test")
@Component
public class BolaSecurityFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BolaSecurityFilter.class);

    private final BolaDetectionService bolaDetectionService;

    // ✅ Constructor injection (no Lombok dependency)
    public BolaSecurityFilter(BolaDetectionService bolaDetectionService) {
        this.bolaDetectionService = bolaDetectionService;
    }

    // Matches /api/.../{id}
    private static final Pattern RESOURCE_ID_PATTERN =
            Pattern.compile("/api(?:/[^/]+)*/(\\d+)");

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // ✅ Only protect API endpoints
        if (!request.getRequestURI().startsWith("/api")) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();

        // ✅ No auth → allow (important for tests/dev)
        if (auth == null || !auth.isAuthenticated()) {
            log.debug("Skipping BOLA (no auth) for {}", request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        // ✅ Safe type check BEFORE casting
        if (!(auth instanceof JwtAuthenticationToken jwtAuth)) {
            log.debug("Skipping BOLA (non-JWT auth)");
            filterChain.doFilter(request, response);
            return;
        }

        // ✅ Extract userId from JWT
        String userIdStr = jwtAuth.getToken().getClaimAsString("uid");

        // ✅ If no UID → skip
        if (userIdStr == null) {
            log.debug("Skipping BOLA (no uid claim)");
            filterChain.doFilter(request, response);
            return;
        }

        // ✅ Extract resource ID from URL
        String resourceIdStr = extractResourceId(request);

        // ✅ If no resource ID → skip
        if (resourceIdStr == null) {
            log.debug("No resource ID, skipping BOLA");
            filterChain.doFilter(request, response);
            return;
        }

        // 🔥 Core BOLA check
        boolean allowed = bolaDetectionService.validateAccess(userIdStr, resourceIdStr, request);

        if (!allowed) {
            log.warn("BOLA blocked: userId={}, resourceId={}, uri={}",
                    userIdStr, resourceIdStr, request.getRequestURI());

            throw new BolaAccessDeniedException("BOLA Attack Detected");
        }

        log.debug("BOLA allowed: userId={}, resourceId={}", userIdStr, resourceIdStr);

        // ✅ Continue request flow
        filterChain.doFilter(request, response);
    }

    // ✅ Extract numeric resource ID from URL
    private String extractResourceId(HttpServletRequest request) {
        Matcher matcher = RESOURCE_ID_PATTERN.matcher(request.getRequestURI());
        return matcher.find() ? matcher.group(1) : null;
    }
}