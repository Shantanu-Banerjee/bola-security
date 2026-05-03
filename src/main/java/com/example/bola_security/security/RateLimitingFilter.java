package com.example.bola_security.security;

import com.example.bola_security.service.RateLimitingService;
import com.example.bola_security.service.TrustedProxyService;
import io.micrometer.core.instrument.MeterRegistry;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class RateLimitingFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(RateLimitingFilter.class);

    private final RateLimitingService rateLimitingService;
    private final TrustedProxyService trustedProxyService;
    private final MeterRegistry meterRegistry;

    public RateLimitingFilter(
            RateLimitingService rateLimitingService,
            TrustedProxyService trustedProxyService,
            MeterRegistry meterRegistry
    ) {
        this.rateLimitingService = rateLimitingService;
        this.trustedProxyService = trustedProxyService;
        this.meterRegistry = meterRegistry;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        String clientIp = trustedProxyService.resolveClientIp(request);
        String path = request.getRequestURI();

        if (path.startsWith("/doLogin") || path.equals("/login")) {
            if (!rateLimitingService.allowLoginRequest(clientIp)) {
                log.warn("Login rate limit exceeded for IP: {}", clientIp);
                meterRegistry.counter("bola.rate_limit.blocks", "channel", "login").increment();
                response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(),
                        "Too many login attempts. Please try again later.");
                return;
            }
        } else if (path.startsWith("/api/")) {
            if (!rateLimitingService.allowApiRequest(clientIp)) {
                log.warn("API rate limit exceeded for IP: {}", clientIp);
                meterRegistry.counter("bola.rate_limit.blocks", "channel", "api").increment();
                response.sendError(HttpStatus.TOO_MANY_REQUESTS.value(),
                        "Rate limit exceeded. Please slow down.");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }
}
