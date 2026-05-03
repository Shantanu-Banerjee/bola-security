package com.example.bola_security.service;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.LocalDateTime;

@Service
public class RequestContextService {

    private static final Logger log = LoggerFactory.getLogger(RequestContextService.class);

    private final Clock clock;
    private final TrustedProxyService trustedProxyService;

    public RequestContextService(Clock clock, TrustedProxyService trustedProxyService) {
        this.clock = clock;
        this.trustedProxyService = trustedProxyService;
    }

    public RequestContext extract(HttpServletRequest request) {
        String clientIp = trustedProxyService.resolveClientIp(request);
        log.debug("Extracted request context: ip={}, method={}, path={}", clientIp, request.getMethod(), request.getRequestURI());
        return new RequestContext(
                clientIp,
                request.getHeader("User-Agent"),
                request.getSession(false) == null ? "NO_SESSION" : request.getSession(false).getId(),
                request.getMethod(),
                request.getRequestURI(),
                LocalDateTime.now(clock)
        );
    }
}
