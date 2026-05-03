package com.example.bola_security.middleware;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.bind.annotation.*;

import java.util.Comparator;
import java.util.List;
import java.util.Map;

/**
 * STEP 7: Basic Security Dashboard
 * 
 * Provides a simple API endpoint that shows:
 * - Total requests processed
 * - Number of blocked BOLA attacks
 * - Number of rate-limited requests
 * - Recent security events
 * - Per-user attack statistics
 * 
 * VIVA NOTE: In a real application, you'd build a proper HTML dashboard
 * with charts and real-time updates. Here we provide a JSON endpoint
 * that can be viewed in the browser or Postman.
 */
@RestController
@RequestMapping("/api/v1/middleware/dashboard")
@Tag(name = "Security Dashboard", description = "Monitor BOLA attacks and request statistics")
public class DashboardController {

    private final SecurityLogService securityLogService;
    private final RateLimitService rateLimitService;

    public DashboardController(SecurityLogService securityLogService,
                               RateLimitService rateLimitService) {
        this.securityLogService = securityLogService;
        this.rateLimitService = rateLimitService;
    }

    @Operation(
        summary = "Get security statistics",
        description = "Returns total requests, blocked attacks, rate limits, and active attackers"
    )
    @GetMapping("/stats")
    public ResponseEntity<Map<String, Object>> getStats() {
        Map<String, Object> stats = securityLogService.getStatistics();
        return ResponseEntity.ok(stats);
    }

    @Operation(
        summary = "Get recent security events",
        description = "Returns the last 50 security events (access, BOLA attacks, rate limits)"
    )
    @GetMapping("/events")
    public ResponseEntity<?> getRecentEvents() {
        return ResponseEntity.ok(Map.of(
            "events", securityLogService.getRecentEvents(),
            "total", securityLogService.getRecentEvents().size()
        ));
    }

    @Operation(
        summary = "Get per-user attack statistics",
        description = "Shows which user IDs have attempted BOLA attacks and how many times"
    )
    @GetMapping("/attackers")
    public ResponseEntity<?> getAttackerStats() {
        return ResponseEntity.ok(Map.of(
            "userAttackCounts", securityLogService.getUserAttackCounts()
        ));
    }

    @Operation(
        summary = "Get rate limit configuration",
        description = "Shows current rate limit settings"
    )
    @GetMapping("/rate-limit-config")
    public ResponseEntity<?> getRateLimitConfig() {
        return ResponseEntity.ok(Map.of(
            "maxRequestsPerWindow", rateLimitService.getMaxRequestsPerWindow(),
            "windowSizeSeconds", rateLimitService.getWindowSizeSeconds()
        ));
    }

    @Operation(
        summary = "Get complete dashboard overview",
        description = "Returns all dashboard data in a single response"
    )
    @GetMapping
    public ResponseEntity<Map<String, Object>> getFullDashboard() {
        return ResponseEntity.ok(Map.of(
            "statistics", securityLogService.getStatistics(),
            "recentEvents", securityLogService.getRecentEvents(),
            "attackers", securityLogService.getUserAttackCounts(),
            "rateLimitConfig", Map.of(
                "maxRequestsPerWindow", rateLimitService.getMaxRequestsPerWindow(),
                "windowSizeSeconds", rateLimitService.getWindowSizeSeconds()
            )
        ));
    }

    @Operation(
        summary = "View HTML dashboard",
        description = "Simple browser dashboard for total requests, blocked attacks, and recent logs"
    )
    @GetMapping(value = "/view", produces = MediaType.TEXT_HTML_VALUE)
    public String getDashboardPage() {
        Map<String, Object> stats = securityLogService.getStatistics();
        List<SecurityLogService.SecurityEvent> events = securityLogService.getRecentEvents()
                .stream()
                .sorted(Comparator.comparing(SecurityLogService.SecurityEvent::timestamp).reversed())
                .toList();

        String rows = events.stream()
                .map(event -> """
                    <tr>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                        <td>%s</td>
                    </tr>
                    """.formatted(
                        escape(event.timestamp()),
                        escape(event.type()),
                        escape(String.valueOf(event.userId())),
                        escape(String.valueOf(event.resourceId())),
                        escape(event.endpoint()),
                        escape(event.status())
                ))
                .reduce("", String::concat);

        return """
            <!doctype html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>BOLA Middleware Dashboard</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 32px; background: #f7f9fb; color: #172033; }
                    h1 { margin-bottom: 8px; }
                    .subtitle { color: #526071; margin-bottom: 24px; }
                    .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin-bottom: 28px; }
                    .stat { background: white; border: 1px solid #d8e0ea; border-radius: 8px; padding: 16px; }
                    .label { color: #526071; font-size: 13px; }
                    .value { font-size: 30px; font-weight: 700; margin-top: 6px; }
                    table { width: 100%%; border-collapse: collapse; background: white; border: 1px solid #d8e0ea; }
                    th, td { padding: 10px 12px; border-bottom: 1px solid #e7edf4; text-align: left; font-size: 14px; }
                    th { background: #eef3f8; color: #26364a; }
                </style>
            </head>
            <body>
                <h1>BOLA Middleware Dashboard</h1>
                <div class="subtitle">Live in-memory monitoring for the demo prototype.</div>
                <section class="stats">
                    <div class="stat"><div class="label">Total Requests</div><div class="value">%s</div></div>
                    <div class="stat"><div class="label">Allowed Requests</div><div class="value">%s</div></div>
                    <div class="stat"><div class="label">Blocked BOLA Attacks</div><div class="value">%s</div></div>
                    <div class="stat"><div class="label">Rate Limited</div><div class="value">%s</div></div>
                </section>
                <h2>Recent Logs</h2>
                <table>
                    <thead>
                        <tr><th>Time</th><th>Type</th><th>User ID</th><th>Resource ID</th><th>Endpoint</th><th>Status</th></tr>
                    </thead>
                    <tbody>%s</tbody>
                </table>
            </body>
            </html>
            """.formatted(
                stats.get("totalRequests"),
                stats.get("allowedRequests"),
                stats.get("blockedAttacks"),
                stats.get("rateLimitedRequests"),
                rows.isBlank() ? "<tr><td colspan=\"6\">No requests logged yet.</td></tr>" : rows
        );
    }

    private String escape(String value) {
        return HtmlUtils.htmlEscape(value == null ? "" : value);
    }
}
