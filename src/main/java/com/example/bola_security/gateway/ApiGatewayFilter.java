package com.example.bola_security.gateway;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.util.ContentCachingRequestWrapper;
import org.springframework.web.util.ContentCachingResponseWrapper;

import java.io.IOException;

/**
 * API Gateway Filter - Intercepts all incoming requests for security processing
 * Acts as the first line of defense in the middleware architecture
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class ApiGatewayFilter implements Filter {

    private static final Logger logger = LoggerFactory.getLogger(ApiGatewayFilter.class);
    
    private final GatewaySecurityProcessor securityProcessor;
    private final GatewayRequestLogger requestLogger;
    private final GatewayResponseHandler responseHandler;

    public ApiGatewayFilter(GatewaySecurityProcessor securityProcessor,
                           GatewayRequestLogger requestLogger,
                           GatewayResponseHandler responseHandler) {
        this.securityProcessor = securityProcessor;
        this.requestLogger = requestLogger;
        this.responseHandler = responseHandler;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // Wrap request/response for caching
        ContentCachingRequestWrapper wrappedRequest = new ContentCachingRequestWrapper(httpRequest);
        ContentCachingResponseWrapper wrappedResponse = new ContentCachingResponseWrapper(httpResponse);

        String clientIp = extractClientIp(httpRequest);
        String sessionId = extractSessionId(httpRequest);

        // Extract request metadata
        GatewayRequestContext context = GatewayRequestContext.builder()
            .requestId(generateRequestId())
            .timestamp(System.currentTimeMillis())
            .clientIp(clientIp)
            .userAgent(httpRequest.getHeader("User-Agent"))
            .sessionId(sessionId)
            .method(httpRequest.getMethod())
            .path(httpRequest.getRequestURI())
            .query(httpRequest.getQueryString())
            .headers(extractHeaders(httpRequest))
            .build();

        // Log incoming request
        requestLogger.logIncomingRequest(context);

        try {
            // Process security checks
            GatewaySecurityResult securityResult = securityProcessor.processRequest(context, wrappedRequest);
            
            if (securityResult.isAllowed()) {
                // Request is allowed, proceed to backend
                chain.doFilter(wrappedRequest, wrappedResponse);
                
                // Log successful response
                requestLogger.logSuccessfulResponse(context, wrappedResponse);
                
            } else {
                // Request is blocked, handle security violation
                responseHandler.handleSecurityViolation(wrappedResponse, securityResult);
                requestLogger.logBlockedRequest(context, securityResult);
            }
            
        } catch (Exception e) {
            logger.error("Gateway processing error for request: " + context.getRequestId(), e);
            responseHandler.handleProcessingError(wrappedResponse, e);
            requestLogger.logProcessingError(context, e);
        } finally {
            // Ensure response is written
            wrappedResponse.copyBodyToResponse();
        }
    }

    private String generateRequestId() {
        return "GW-" + System.currentTimeMillis() + "-" + 
               Integer.toHexString((int) (Math.random() * 0xFFFF));
    }

    private String extractClientIp(HttpServletRequest request) {
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

    private String extractSessionId(HttpServletRequest request) {
        // Try to extract from various session headers
        String sessionId = request.getHeader("X-Session-ID");
        if (sessionId == null) {
            sessionId = request.getHeader("Authorization");
            if (sessionId != null && sessionId.startsWith("Bearer ")) {
                sessionId = sessionId.substring(7);
            }
        }
        if (sessionId == null) {
            sessionId = request.getRequestedSessionId();
        }
        if (sessionId == null || sessionId.isBlank()) {
            sessionId = "anonymous:" + getClientIpForSession(request) + ":" + request.getMethod() + ":" + request.getRequestURI();
        }
        return sessionId;
    }

    private String getClientIpForSession(HttpServletRequest request) {
        String clientIp = extractClientIp(request);
        return clientIp == null || clientIp.isBlank() ? "unknown" : clientIp;
    }

    private java.util.Map<String, String> extractHeaders(HttpServletRequest request) {
        java.util.Map<String, String> headers = new java.util.HashMap<>();
        java.util.Enumeration<String> headerNames = request.getHeaderNames();
        
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            // Filter sensitive headers
            if (!isSensitiveHeader(headerName)) {
                headers.put(headerName, request.getHeader(headerName));
            }
        }
        return headers;
    }

    private boolean isSensitiveHeader(String headerName) {
        String lowerName = headerName.toLowerCase();
        return lowerName.contains("authorization") || 
               lowerName.contains("cookie") ||
               lowerName.contains("token") ||
               lowerName.contains("password");
    }
}
