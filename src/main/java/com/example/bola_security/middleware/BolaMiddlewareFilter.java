package com.example.bola_security.middleware;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * STEP 2 & 4: Working BOLA Authorization Filter
 * 
 * This is the CORE of the BOLA protection middleware.
 * It intercepts requests BEFORE they reach the controller,
 * checks if the logged-in user is authorized to access the requested resource,
 * and either blocks or forwards the request.
 * 
 * HOW IT WORKS (VIVA EXPLANATION):
 * 1. Extracts user identity from the JWT token (the "uid" claim = user ID)
 * 2. Extracts the requested resource ID from the URL path (/api/user/{id})
 * 3. Compares: Is the logged-in user trying to access their OWN data?
 * 4. If YES → forward request to controller (middleware passes through)
 * 5. If NO  → block request with HTTP 403 "BOLA Attack Detected"
 * 6. ADMIN role can access any user's data (legitimate admin access)
 * 
 * WHY OncePerRequestFilter:
 * - Ensures the filter runs exactly once per request
 * - Prevents double-filtering on forwards/includes
 * - Spring's recommended base class for custom filters
 */
@Deprecated(forRemoval = false)
@Tag(name = "Legacy BOLA Demo Filter", description = "Legacy demo filter; runtime enforcement uses BolaAuthorizationFilter")
public class BolaMiddlewareFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BolaMiddlewareFilter.class);
    private static final Pattern USER_PROFILE_PATH = Pattern.compile("^/api/user/(\\d+)$");

    private final RateLimitService rateLimitService;
    private final SecurityLogService securityLogService;
    private final ObjectMapper objectMapper;

    public BolaMiddlewareFilter(RateLimitService rateLimitService,
                                SecurityLogService securityLogService,
                                ObjectMapper objectMapper) {
        this.rateLimitService = rateLimitService;
        this.securityLogService = securityLogService;
        this.objectMapper = objectMapper;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String path = normalizedRequestPath(request);
        String method = request.getMethod();

        Matcher matcher = USER_PROFILE_PATH.matcher(path);
        if (!"GET".equals(method) || !matcher.matches()) {
            filterChain.doFilter(request, response);
            return;
        }

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null || !authentication.isAuthenticated()
                || authentication instanceof AnonymousAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        Long loggedInUserId = extractUserIdFromToken(authentication);
        Long requestedResourceId = Long.valueOf(matcher.group(1));

        if (loggedInUserId == null) {
            sendErrorResponse(response, 401, "Invalid Token",
                    "JWT token is missing required uid claim",
                    "Login again through /api/v1/middleware/login or /api/v1/auth/login.");
            return;
        }

        if (!rateLimitService.isAllowed(loggedInUserId)) {
            securityLogService.logRateLimitEvent(loggedInUserId, path);
            sendErrorResponse(response, 429, "Rate Limit Exceeded",
                    "Too many requests. Maximum 5 requests per minute allowed.",
                    "Wait for the one-minute window to reset before trying again.");
            return;
        }

        if (isBolaAttack(loggedInUserId, requestedResourceId, authentication)) {
            securityLogService.logBolaAttack(loggedInUserId, requestedResourceId, path);
            sendErrorResponse(response, 403, "BOLA Attack Detected",
                    "BOLA Attack Detected",
                    "User " + loggedInUserId + " cannot access profile /api/user/" + requestedResourceId);
            return;
        }

        securityLogService.logAllowedRequest(loggedInUserId, requestedResourceId, path);
        log.info("BOLA_ACCESS_ALLOWED userId={} resourceId={} endpoint={}", loggedInUserId, requestedResourceId, path);
        filterChain.doFilter(request, response);
    }

    /**
     * Extract user ID from JWT token.
     * The JWT contains a "uid" claim set during login (see JwtTokenService).
     */
    private Long extractUserIdFromToken(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            Object uidClaim = jwtAuth.getToken().getClaim("uid");
            if (uidClaim instanceof Number) {
                return ((Number) uidClaim).longValue();
            }
            if (uidClaim instanceof String uid && uid.matches("\\d+")) {
                return Long.parseLong(uid);
            }
        }
        return null;
    }

    /**
     * BOLA Attack Detection Logic:
     * - If user is ADMIN, allow access to any profile for demo admin behavior.
     * - If user ID != requested profile ID, it is a BOLA attempt.
     * - If user ID == requested profile ID, it is legitimate access.
     */
    private boolean isBolaAttack(Long loggedInUserId, Long requestedResourceId, Authentication authentication) {
        if (hasAuthority(authentication, "ROLE_ADMIN") || hasAuthority(authentication, "ADMIN")) {
            return false;
        }
        return !loggedInUserId.equals(requestedResourceId);
    }

    private boolean hasAuthority(Authentication authentication, String authorityName) {
        return authentication.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
                .anyMatch(authorityName::equals);
    }

    private String normalizedRequestPath(HttpServletRequest request) {
        String requestUri = request.getRequestURI();
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isBlank() && requestUri.startsWith(contextPath)) {
            return requestUri.substring(contextPath.length());
        }
        return requestUri;
    }

    /**
     * Send a structured JSON error response.
     * This is what the client receives when blocked by the middleware.
     */
    private void sendErrorResponse(HttpServletResponse response, int status,
                                    String error, String message, String details) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json");
        Map<String, Object> errorBody = Map.of(
            "timestamp", Instant.now().toString(),
            "status", status,
            "error", error,
            "message", message,
            "details", details
        );
        response.getWriter().write(objectMapper.writeValueAsString(errorBody));
    }
}
