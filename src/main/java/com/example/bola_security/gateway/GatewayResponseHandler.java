package com.example.bola_security.gateway;

import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Gateway Response Handler - Manages HTTP responses for security violations and errors
 */
@Component
public class GatewayResponseHandler {

    private static final Logger logger = LoggerFactory.getLogger(GatewayResponseHandler.class);

    /**
     * Handle security violations by returning appropriate HTTP error responses
     */
    public void handleSecurityViolation(HttpServletResponse response, GatewaySecurityResult result) throws IOException {
        response.setStatus(result.getHttpStatus());
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        // Add security headers
        addSecurityHeaders(response);
        
        // Create error response body
        String errorResponse = createErrorResponse(result);
        
        try {
            response.getWriter().write(errorResponse);
            response.getWriter().flush();
            
            logger.warn("Security violation blocked - Type: {}, Reason: {}, IP: {}, Status: {}", 
                result.getViolationType(), result.getReason(), 
                "IP_NOT_AVAILABLE", result.getHttpStatus());
                
        } catch (IOException e) {
            logger.error("Failed to write security violation response", e);
            throw e;
        }
    }

    /**
     * Handle processing errors with generic error response
     */
    public void handleProcessingError(HttpServletResponse response, Exception e) throws IOException {
        response.setStatus(500);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        addSecurityHeaders(response);
        
        String errorResponse = """
            {
                "error": {
                    "type": "PROCESSING_ERROR",
                    "message": "Security processing failed",
                    "code": "SECURITY_GATEWAY_ERROR",
                    "timestamp": "%d"
                }
            }
            """.formatted(System.currentTimeMillis());
        
        try {
            response.getWriter().write(errorResponse);
            response.getWriter().flush();
            
            logger.error("Security processing error returned to client", e);
            
        } catch (IOException ioException) {
            logger.error("Failed to write processing error response", ioException);
            throw ioException;
        }
    }

    /**
     * Add security headers to all responses
     */
    private void addSecurityHeaders(HttpServletResponse response) {
        // Security headers
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-Frame-Options", "DENY");
        response.setHeader("X-XSS-Protection", "1; mode=block");
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
        response.setHeader("Content-Security-Policy", "default-src 'self'");
        response.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
        
        // Gateway identification
        response.setHeader("X-Gateway-Version", "1.0");
        response.setHeader("X-Security-Processed", "true");
        response.setHeader("X-Request-Timestamp", String.valueOf(System.currentTimeMillis()));
    }

    /**
     * Create standardized error response based on security result
     */
    private String createErrorResponse(GatewaySecurityResult result) {
        String errorType = mapViolationTypeToErrorType(result.getViolationType());
        String userMessage = createUserFriendlyMessage(result);
        
        return """
            {
                "error": {
                    "type": "%s",
                    "message": "%s",
                    "code": "%s",
                    "severity": "%s",
                    "timestamp": %d,
                    "requestId": "%s",
                    "retryAfter": %d
                }
            }
            """.formatted(
                errorType,
                userMessage,
                result.getViolationType(),
                getSeverity(result.getRiskScore()),
                System.currentTimeMillis(),
                "REQ-" + System.currentTimeMillis(),
                getRetryAfter(result.getViolationType())
            );
    }

    /**
     * Map internal violation types to user-friendly error types
     */
    private String mapViolationTypeToErrorType(String violationType) {
        return switch (violationType) {
            case "IDOR_ATTEMPT" -> "ACCESS_DENIED";
            case "SEQUENTIAL_PROBING" -> "RATE_LIMITED";
            case "POOR_IP_REPUTATION" -> "BLOCKED";
            case "SUSPICIOUS_SESSION" -> "SESSION_INVALID";
            case "UNAUTHORIZED_SENSITIVE_ACCESS" -> "INSUFFICIENT_PERMISSIONS";
            case "RATE_LIMIT_EXCEEDED" -> "RATE_LIMITED";
            case "SUSPICIOUS_OBJECT_ACCESS" -> "ACCESS_DENIED";
            case "PROCESSING_ERROR" -> "INTERNAL_ERROR";
            default -> "SECURITY_VIOLATION";
        };
    }

    /**
     * Create user-friendly error messages
     */
    private String createUserFriendlyMessage(GatewaySecurityResult result) {
        return switch (result.getViolationType()) {
            case "IDOR_ATTEMPT" -> "Access to this resource is not authorized";
            case "SEQUENTIAL_PROBING" -> "Too many requests detected. Please slow down.";
            case "POOR_IP_REPUTATION" -> "Access from this location is temporarily blocked";
            case "SUSPICIOUS_SESSION" -> "Your session has been invalidated for security reasons";
            case "UNAUTHORIZED_SENSITIVE_ACCESS" -> "You don't have permission to access this feature";
            case "RATE_LIMIT_EXCEEDED" -> "Request limit exceeded. Please try again later.";
            case "SUSPICIOUS_OBJECT_ACCESS" -> "Access denied due to unusual activity pattern";
            case "PROCESSING_ERROR" -> "A temporary error occurred. Please try again.";
            default -> "Access denied for security reasons";
        };
    }

    /**
     * Get severity level based on risk score
     */
    private String getSeverity(int riskScore) {
        if (riskScore >= 80) return "HIGH";
        if (riskScore >= 60) return "MEDIUM";
        if (riskScore >= 40) return "LOW";
        return "INFO";
    }

    /**
     * Get retry after duration in seconds based on violation type
     */
    private int getRetryAfter(String violationType) {
        return switch (violationType) {
            case "RATE_LIMIT_EXCEEDED", "SEQUENTIAL_PROBING" -> 60;
            case "POOR_IP_REPUTATION" -> 300;
            case "SUSPICIOUS_SESSION" -> 0; // No retry for session issues
            case "IDOR_ATTEMPT" -> 0; // No retry for authorization issues
            case "PROCESSING_ERROR" -> 5;
            default -> 30;
        };
    }

    /**
     * Handle successful request completion
     */
    public void handleSuccessfulResponse(HttpServletResponse response) {
        // Add security headers even for successful responses
        addSecurityHeaders(response);
    }

    /**
     * Handle request timeout
     */
    public void handleTimeout(HttpServletResponse response) throws IOException {
        response.setStatus(408);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        addSecurityHeaders(response);
        
        String timeoutResponse = """
            {
                "error": {
                    "type": "TIMEOUT",
                    "message": "Request processing timeout",
                    "code": "GATEWAY_TIMEOUT",
                    "timestamp": %d
                }
            }
            """.formatted(System.currentTimeMillis());
        
        response.getWriter().write(timeoutResponse);
        response.getWriter().flush();
    }

    /**
     * Handle service unavailable
     */
    public void handleServiceUnavailable(HttpServletResponse response) throws IOException {
        response.setStatus(503);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        addSecurityHeaders(response);
        response.setHeader("Retry-After", "30");
        
        String unavailableResponse = """
            {
                "error": {
                    "type": "SERVICE_UNAVAILABLE",
                    "message": "Security service temporarily unavailable",
                    "code": "GATEWAY_UNAVAILABLE",
                    "timestamp": %d,
                    "retryAfter": 30
                }
            }
            """.formatted(System.currentTimeMillis());
        
        response.getWriter().write(unavailableResponse);
        response.getWriter().flush();
    }

    /**
     * Handle malformed request
     */
    public void handleMalformedRequest(HttpServletResponse response, String details) throws IOException {
        response.setStatus(400);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        addSecurityHeaders(response);
        
        String badRequestResponse = """
            {
                "error": {
                    "type": "BAD_REQUEST",
                    "message": "Invalid request format",
                    "code": "MALFORMED_REQUEST",
                    "details": "%s",
                    "timestamp": %d
                }
            }
            """.formatted(
                details != null ? details : "Request format is invalid",
                System.currentTimeMillis()
            );
        
        response.getWriter().write(badRequestResponse);
        response.getWriter().flush();
    }
}
