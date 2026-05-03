package com.example.bola_security.service;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;

import static org.assertj.core.api.Assertions.assertThat;
import static com.example.bola_security.TestSecurityProperties.properties;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RequestContextServiceTest {

    @Mock
    private HttpServletRequest request;

    @Test
    void extractsRequestContextWithAllFields() {
        Clock fixedClock = Clock.fixed(Instant.parse("2025-01-01T12:00:00Z"), ZoneId.of("UTC"));
        RequestContextService service = service(fixedClock);

        when(request.getRemoteAddr()).thenReturn("192.168.1.100");
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(request.getSession(false)).thenReturn(null);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/v1/resources/123");

        RequestContext context = service.extract(request);

        assertThat(context.ipAddress()).isEqualTo("192.168.1.100");
        assertThat(context.userAgent()).isEqualTo("Mozilla/5.0");
        assertThat(context.sessionId()).isEqualTo("NO_SESSION");
        assertThat(context.httpMethod()).isEqualTo("GET");
        assertThat(context.requestPath()).isEqualTo("/api/v1/resources/123");
        assertThat(context.accessTime()).isEqualTo(LocalDateTime.of(2025, 1, 1, 12, 0, 0));
    }

    @Test
    void prefersXForwardedForOverRemoteAddr() {
        Clock fixedClock = Clock.systemUTC();
        RequestContextService service = service(fixedClock);

        when(request.getHeader("X-Forwarded-For")).thenReturn("10.0.0.5, 10.0.0.6");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("User-Agent")).thenReturn(null);
        when(request.getSession(false)).thenReturn(null);
        when(request.getMethod()).thenReturn("POST");
        when(request.getRequestURI()).thenReturn("/api/v1/resources");

        RequestContext context = service.extract(request);

        assertThat(context.ipAddress()).isEqualTo("10.0.0.5");
        assertThat(context.userAgent()).isNull();
        assertThat(context.httpMethod()).isEqualTo("POST");
        assertThat(context.requestPath()).isEqualTo("/api/v1/resources");
    }

    @Test
    void usesXRealIpWhenXForwardedForIsMissing() {
        Clock fixedClock = Clock.systemUTC();
        RequestContextService service = service(fixedClock);

        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getHeader("X-Real-IP")).thenReturn("10.0.0.7");
        when(request.getRemoteAddr()).thenReturn("127.0.0.1");
        when(request.getHeader("User-Agent")).thenReturn("curl/7.68.0");
        when(request.getSession(false)).thenReturn(null);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/v1/resources/456");

        RequestContext context = service.extract(request);

        assertThat(context.ipAddress()).isEqualTo("10.0.0.7");
        assertThat(context.userAgent()).isEqualTo("curl/7.68.0");
        assertThat(context.httpMethod()).isEqualTo("GET");
        assertThat(context.requestPath()).isEqualTo("/api/v1/resources/456");
    }

    @Test
    void fallsBackToRemoteAddrWhenHeadersMissing() {
        Clock fixedClock = Clock.systemUTC();
        RequestContextService service = service(fixedClock);

        when(request.getHeader("X-Forwarded-For")).thenReturn(null);
        when(request.getHeader("X-Real-IP")).thenReturn(null);
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");
        when(request.getHeader("User-Agent")).thenReturn(null);
        when(request.getSession(false)).thenReturn(null);
        when(request.getMethod()).thenReturn("DELETE");
        when(request.getRequestURI()).thenReturn("/api/v1/resources/789");

        RequestContext context = service.extract(request);

        assertThat(context.ipAddress()).isEqualTo("192.168.1.100");
        assertThat(context.userAgent()).isNull();
        assertThat(context.httpMethod()).isEqualTo("DELETE");
        assertThat(context.requestPath()).isEqualTo("/api/v1/resources/789");
    }

    @Test
    void extractsSessionIdWhenSessionExists() {
        Clock fixedClock = Clock.systemUTC();
        RequestContextService service = service(fixedClock);

        jakarta.servlet.http.HttpSession session = org.mockito.Mockito.mock(jakarta.servlet.http.HttpSession.class);
        when(session.getId()).thenReturn("session-123");

        when(request.getRemoteAddr()).thenReturn("192.168.1.100");
        when(request.getHeader("User-Agent")).thenReturn("Mozilla/5.0");
        when(request.getSession(false)).thenReturn(session);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/v1/resources/1");

        RequestContext context = service.extract(request);

        assertThat(context.sessionId()).isEqualTo("session-123");
    }

    @Test
    void handlesBlankXForwardedForHeader() {
        Clock fixedClock = Clock.systemUTC();
        RequestContextService service = service(fixedClock);

        when(request.getHeader("X-Forwarded-For")).thenReturn("");
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");
        when(request.getHeader("User-Agent")).thenReturn("test-agent");
        when(request.getSession(false)).thenReturn(null);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/v1/resources/2");

        RequestContext context = service.extract(request);

        assertThat(context.ipAddress()).isEqualTo("192.168.1.100");
        assertThat(context.userAgent()).isEqualTo("test-agent");
    }

    @Test
    void ignoresForwardedHeadersFromUntrustedRemoteAddress() {
        Clock fixedClock = Clock.systemUTC();
        RequestContextService service = service(fixedClock);

        when(request.getHeader("X-Forwarded-For")).thenReturn("10.0.0.5");
        when(request.getRemoteAddr()).thenReturn("192.168.1.100");
        when(request.getHeader("User-Agent")).thenReturn("test-agent");
        when(request.getSession(false)).thenReturn(null);
        when(request.getMethod()).thenReturn("GET");
        when(request.getRequestURI()).thenReturn("/api/v1/resources/2");

        RequestContext context = service.extract(request);

        assertThat(context.ipAddress()).isEqualTo("192.168.1.100");
    }

    private RequestContextService service(Clock clock) {
        return new RequestContextService(clock, new TrustedProxyService(
                properties(5, 10, false, false, false, 9, 18, true, 80, 5)));
    }
}
