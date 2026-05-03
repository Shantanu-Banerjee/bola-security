package com.example.bola_security.gateway;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Gateway Management API - Real integration endpoints for testing and monitoring
 */
@RestController
@RequestMapping("/api/gateway")
public class GatewayManagementController {

    private final GatewayRequestLogger requestLogger;
    private final GatewaySecurityProcessor securityProcessor;

    public GatewayManagementController(GatewayRequestLogger requestLogger,
                                     GatewaySecurityProcessor securityProcessor) {
        this.requestLogger = requestLogger;
        this.securityProcessor = securityProcessor;
    }

    /**
     * Get gateway statistics
     */
    @GetMapping("/stats")
    public ResponseEntity<GatewayRequestLogger.GatewayStatistics> getGatewayStats() {
        return ResponseEntity.ok(requestLogger.getStatistics());
    }

    /**
     * Get security logs
     */
    @GetMapping("/logs/security")
    public ResponseEntity<?> getSecurityLogs(@RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(Map.of(
            "logs", requestLogger.getSecurityLogs(limit),
            "total", requestLogger.getSecurityLogs(limit).size()
        ));
    }

    /**
     * Get attack logs
     */
    @GetMapping("/logs/attacks")
    public ResponseEntity<?> getAttackLogs(@RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(Map.of(
            "logs", requestLogger.getAttackLogs(limit),
            "total", requestLogger.getAttackLogs(limit).size()
        ));
    }

    /**
     * Get access logs
     */
    @GetMapping("/logs/access")
    public ResponseEntity<?> getAccessLogs(@RequestParam(defaultValue = "50") int limit) {
        return ResponseEntity.ok(Map.of(
            "logs", requestLogger.getAccessLogs(limit),
            "total", requestLogger.getAccessLogs(limit).size()
        ));
    }

    /**
     * Get attack timeline
     */
    @GetMapping("/timeline/attacks")
    public ResponseEntity<?> getAttackTimeline() {
        return ResponseEntity.ok(Map.of(
            "timeline", requestLogger.getAttackTimeline()
        ));
    }

    /**
     * Get IP reputation data
     */
    @GetMapping("/reputation/ip")
    public ResponseEntity<?> getIpReputation() {
        return ResponseEntity.ok(Map.of(
            "reputations", requestLogger.getIpReputation()
        ));
    }

    /**
     * Export logs to CSV
     */
    @GetMapping("/export/logs")
    public ResponseEntity<String> exportLogs(@RequestParam String logType) {
        String csv = requestLogger.exportLogsToCsv(logType);
        return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=" + logType + "_logs.csv")
            .header("Content-Type", "text/csv")
            .body(csv);
    }

    /**
     * Test endpoint for legitimate access
     */
    @GetMapping("/test/legitimate")
    public ResponseEntity<?> testLegitimateAccess(@RequestHeader(value = "X-User-ID", required = false) String userId) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "success");
        response.put("message", "Legitimate access test passed");
        response.put("userId", userId != null ? userId : "anonymous");
        response.put("timestamp", System.currentTimeMillis());
        response.put("gateway", "active");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test endpoint for IDOR attack simulation
     */
    @GetMapping("/test/resources/{resourceId}")
    public ResponseEntity<?> testIdorAccess(@PathVariable String resourceId,
                                           @RequestHeader(value = "X-User-ID", required = false) String userId) {
        // Simulate resource access that might trigger IDOR detection
        Map<String, Object> response = new HashMap<>();
        response.put("resourceId", resourceId);
        response.put("userId", userId != null ? userId : "anonymous");
        response.put("access", "denied"); // This will be handled by gateway
        response.put("message", "IDOR test endpoint");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test endpoint for sequential probing
     */
    @GetMapping("/test/sequential/{id}")
    public ResponseEntity<?> testSequentialProbing(@PathVariable String id) {
        Map<String, Object> response = new HashMap<>();
        response.put("id", id);
        response.put("message", "Sequential probing test");
        response.put("timestamp", System.currentTimeMillis());
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test endpoint for sensitive operation
     */
    @PostMapping("/test/sensitive")
    public ResponseEntity<?> testSensitiveOperation(@RequestBody Map<String, Object> request,
                                                  @RequestHeader(value = "X-User-ID", required = false) String userId) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "processed");
        response.put("operation", "sensitive");
        response.put("userId", userId);
        response.put("requestData", request);
        response.put("message", "Sensitive operation test");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Test endpoint for bulk operations
     */
    @PostMapping("/test/bulk")
    public ResponseEntity<?> testBulkOperation(@RequestBody java.util.List<Map<String, Object>> requests,
                                             @RequestHeader(value = "X-User-ID", required = false) String userId) {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "processed");
        response.put("operation", "bulk");
        response.put("userId", userId);
        response.put("processedCount", requests.size());
        response.put("message", "Bulk operation test");
        
        return ResponseEntity.ok(response);
    }

    /**
     * Health check endpoint
     */
    @GetMapping("/health")
    public ResponseEntity<?> healthCheck() {
        GatewayRequestLogger.GatewayStatistics stats = requestLogger.getStatistics();
        
        Map<String, Object> health = new HashMap<>();
        health.put("status", "healthy");
        health.put("gateway", "active");
        health.put("timestamp", System.currentTimeMillis());
        health.put("statistics", Map.of(
            "totalRequests", stats.getTotalRequests(),
            "blockedRequests", stats.getBlockedRequests(),
            "attackAttempts", stats.getAttackAttempts(),
            "blockRate", String.format("%.2f%%", stats.getBlockRate() * 100),
            "attackRate", String.format("%.2f%%", stats.getAttackRate() * 100)
        ));
        
        return ResponseEntity.ok(health);
    }

    /**
     * Get Postman collection configuration
     */
    @GetMapping("/postman/collection")
    public ResponseEntity<?> getPostmanCollection() {
        Map<String, Object> collection = Map.of(
            "info", Map.of(
                "name", "BOLA Security Gateway Test Collection",
                "description", "Collection for testing BOLA security middleware",
                "schema", "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
            ),
            "item", java.util.List.of(
                Map.of(
                    "name", "Legitimate Access Test",
                    "request", Map.of(
                        "method", "GET",
                        "header", java.util.List.of(
                            Map.of("key", "X-User-ID", "value", "user123"),
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/test/legitimate",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "test", "legitimate")
                        )
                    )
                ),
                Map.of(
                    "name", "IDOR Attack Test",
                    "request", Map.of(
                        "method", "GET",
                        "header", java.util.List.of(
                            Map.of("key", "X-User-ID", "value", "attacker456"),
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/test/resources/999",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "test", "resources", "999")
                        )
                    )
                ),
                Map.of(
                    "name", "Sequential Probing Test",
                    "request", Map.of(
                        "method", "GET",
                        "header", java.util.List.of(
                            Map.of("key", "X-User-ID", "value", "prober789"),
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/test/sequential/{{$randomInt}}",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "test", "sequential", "{{$randomInt}}")
                        )
                    )
                ),
                Map.of(
                    "name", "Sensitive Operation Test",
                    "request", Map.of(
                        "method", "POST",
                        "header", java.util.List.of(
                            Map.of("key", "X-User-ID", "value", "user123"),
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "body", Map.of(
                            "mode", "raw",
                            "raw", "{\"action\": \"delete_user\", \"targetId\": \"admin\"}"
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/test/sensitive",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "test", "sensitive")
                        )
                    )
                ),
                Map.of(
                    "name", "Bulk Operation Test",
                    "request", Map.of(
                        "method", "POST",
                        "header", java.util.List.of(
                            Map.of("key", "X-User-ID", "value", "user123"),
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "body", Map.of(
                            "mode", "raw",
                            "raw", "[{\"id\": 1}, {\"id\": 2}, {\"id\": 3}, {\"id\": 4}, {\"id\": 5}]"
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/test/bulk",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "test", "bulk")
                        )
                    )
                ),
                Map.of(
                    "name", "Gateway Statistics",
                    "request", Map.of(
                        "method", "GET",
                        "header", java.util.List.of(
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/stats",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "stats")
                        )
                    )
                ),
                Map.of(
                    "name", "Attack Logs",
                    "request", Map.of(
                        "method", "GET",
                        "header", java.util.List.of(
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/logs/attacks",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "logs", "attacks")
                        )
                    )
                ),
                Map.of(
                    "name", "IP Reputation",
                    "request", Map.of(
                        "method", "GET",
                        "header", java.util.List.of(
                            Map.of("key", "Content-Type", "value", "application/json")
                        ),
                        "url", Map.of(
                            "raw", "{{baseUrl}}/api/gateway/reputation/ip",
                            "host", java.util.List.of("{{baseUrl}}"),
                            "path", java.util.List.of("api", "gateway", "reputation", "ip")
                        )
                    )
                )
            ),
            "variable", java.util.List.of(
                Map.of("key", "baseUrl", "value", "http://localhost:8080")
            )
        );
        
        return ResponseEntity.ok(collection);
    }

    /**
     * Get testing guide
     */
    @GetMapping("/testing-guide")
    public ResponseEntity<?> getTestingGuide() {
        Map<String, Object> guide = Map.of(
            "title", "BOLA Security Gateway Testing Guide",
            "description", "Comprehensive guide for testing the BOLA security middleware",
            "setup", Map.of(
                "baseUrl", "http://localhost:8080",
                "authentication", "Use X-User-ID header to simulate user authentication",
                "headers", java.util.List.of(
                    "X-User-ID: user123 (legitimate user)",
                    "X-User-ID: attacker456 (malicious user)",
                    "Content-Type: application/json"
                )
            ),
            "testScenarios", java.util.List.of(
                Map.of(
                    "name", "Legitimate Access",
                    "description", "Test normal user access to allowed resources",
                    "method", "GET",
                    "url", "/api/gateway/test/legitimate",
                    "headers", Map.of("X-User-ID", "user123"),
                    "expectedStatus", 200
                ),
                Map.of(
                    "name", "IDOR Attack",
                    "description", "Test Insecure Direct Object Reference attack",
                    "method", "GET",
                    "url", "/api/gateway/test/resources/999",
                    "headers", Map.of("X-User-ID", "attacker456"),
                    "expectedStatus", 403
                ),
                Map.of(
                    "name", "Sequential Probing",
                    "description", "Test sequential resource enumeration attack",
                    "method", "GET",
                    "url", "/api/gateway/test/sequential/1,2,3,4,5,6,7,8,9,10",
                    "headers", Map.of("X-User-ID", "prober789"),
                    "expectedStatus", 429
                ),
                Map.of(
                    "name", "Sensitive Operation",
                    "description", "Test access to sensitive endpoints",
                    "method", "POST",
                    "url", "/api/gateway/test/sensitive",
                    "headers", Map.of("X-User-ID", "user123"),
                    "body", "{\"action\": \"delete_user\", \"targetId\": \"admin\"}",
                    "expectedStatus", 200
                ),
                Map.of(
                    "name", "Bulk Operation",
                    "description", "Test bulk operations that might trigger rate limiting",
                    "method", "POST",
                    "url", "/api/gateway/test/bulk",
                    "headers", Map.of("X-User-ID", "user123"),
                    "body", "[{\"id\": 1}, {\"id\": 2}, {\"id\": 3}, {\"id\": 4}, {\"id\": 5}]",
                    "expectedStatus", 200
                )
            ),
            "monitoring", Map.of(
                "statistics", "/api/gateway/stats",
                "securityLogs", "/api/gateway/logs/security",
                "attackLogs", "/api/gateway/logs/attacks",
                "accessLogs", "/api/gateway/logs/access",
                "attackTimeline", "/api/gateway/timeline/attacks",
                "ipReputation", "/api/gateway/reputation/ip",
                "healthCheck", "/api/gateway/health"
            ),
            "postman", Map.of(
                "collection", "/api/gateway/postman/collection",
                "import", "Import the collection into Postman and update baseUrl variable"
            ),
            "expectedResults", Map.of(
                "legitimateRequests", "Should pass through gateway (HTTP 200)",
                "idorAttempts", "Should be blocked (HTTP 403)",
                "sequentialProbing", "Should be rate limited (HTTP 429)",
                "sensitiveOps", "Should be logged and monitored",
                "bulkOps", "Should be tracked for abuse patterns"
            )
        );
        
        return ResponseEntity.ok(guide);
    }
}
