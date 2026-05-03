package com.example.bola_security.security;

import com.example.bola_security.service.JwtTokenService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class BolaAuthorizationFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(BolaAuthorizationFilter.class);
    private static final Pattern RESOURCE_ID_PATTERN = Pattern.compile("^/api(?:/[^/]+)*/(?<id>\\d+)/?$");
    private static final String BOLA_DENIED_MESSAGE = "Access Denied: BOLA detected";

    private final JwtTokenService jwtTokenService;

    public BolaAuthorizationFilter(JwtTokenService jwtTokenService) {
        this.jwtTokenService = jwtTokenService;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain
    ) throws ServletException, IOException {
        MDC.put("endpoint", request.getRequestURI());
        MDC.put("httpMethod", request.getMethod());

        try {
            Optional<Long> requestedResourceId = extractResourceId(request);
            if (requestedResourceId.isEmpty()) {
                logDecision("UNKNOWN", request.getRequestURI(), "ALLOWED");
                filterChain.doFilter(request, response);
                return;
            }

            Long resourceId = requestedResourceId.get();

            MDC.put("resourceId", String.valueOf(resourceId));
            Long loggedInUserId = jwtTokenService.extractUserIdFromAuthorizationHeader(
                    request.getHeader("Authorization"));
            MDC.put("userId", String.valueOf(loggedInUserId));

            if (!loggedInUserId.equals(resourceId)) {
                blockBolaRequest(response, loggedInUserId, resourceId, request.getRequestURI());
                return;
            }

            logDecision(String.valueOf(loggedInUserId), request.getRequestURI(), "ALLOWED");
            filterChain.doFilter(request, response);
        } catch (IllegalArgumentException | JwtException exception) {
            MDC.put("decision", "BLOCKED");
            MDC.put("userId", "UNKNOWN");
            log.warn("BOLA authorization failed before controller userId=UNKNOWN endpoint={} decision=BLOCKED reason={}",
                    request.getRequestURI(),
                    exception.getMessage());
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setContentType(MediaType.TEXT_PLAIN_VALUE);
            response.getWriter().write(BOLA_DENIED_MESSAGE);
        } finally {
            MDC.clear();
        }
    }

    private Optional<Long> extractResourceId(HttpServletRequest request) {
        Matcher matcher = RESOURCE_ID_PATTERN.matcher(request.getRequestURI());
        if (!matcher.matches()) {
            return Optional.empty();
        }
        return Optional.of(Long.parseLong(matcher.group("id")));
    }

    private void blockBolaRequest(
            HttpServletResponse response,
            Long loggedInUserId,
            Long resourceId,
            String endpoint
    ) throws IOException {
        MDC.put("decision", "BLOCKED");
        log.warn("BOLA attack detected userId={} endpoint={} requestedResourceId={} decision=BLOCKED",
                loggedInUserId,
                endpoint,
                resourceId);
        response.setStatus(HttpStatus.FORBIDDEN.value());
        response.setContentType(MediaType.TEXT_PLAIN_VALUE);
        response.getWriter().write(BOLA_DENIED_MESSAGE);
    }

    private void logDecision(String userId, String endpoint, String decision) {
        MDC.put("decision", decision);
        log.info("BOLA authorization request userId={} endpoint={} decision={}", userId, endpoint, decision);
    }
}
