package com.example.bola_security.gateway;

import java.util.Map;

/**
 * Gateway request context containing all metadata for security processing
 */
public class GatewayRequestContext {
    
    private final String requestId;
    private final long timestamp;
    private final String clientIp;
    private final String userAgent;
    private final String sessionId;
    private final String method;
    private final String path;
    private final String query;
    private final Map<String, String> headers;
    
    private GatewayRequestContext(Builder builder) {
        this.requestId = builder.requestId;
        this.timestamp = builder.timestamp;
        this.clientIp = builder.clientIp;
        this.userAgent = builder.userAgent;
        this.sessionId = builder.sessionId;
        this.method = builder.method;
        this.path = builder.path;
        this.query = builder.query;
        this.headers = builder.headers;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    // Getters
    public String getRequestId() { return requestId; }
    public long getTimestamp() { return timestamp; }
    public String getClientIp() { return clientIp; }
    public String getUserAgent() { return userAgent; }
    public String getSessionId() { return sessionId; }
    public String getMethod() { return method; }
    public String getPath() { return path; }
    public String getQuery() { return query; }
    public Map<String, String> getHeaders() { return headers; }
    
    public static class Builder {
        private String requestId;
        private long timestamp;
        private String clientIp;
        private String userAgent;
        private String sessionId;
        private String method;
        private String path;
        private String query;
        private Map<String, String> headers;
        
        public Builder requestId(String requestId) { this.requestId = requestId; return this; }
        public Builder timestamp(long timestamp) { this.timestamp = timestamp; return this; }
        public Builder clientIp(String clientIp) { this.clientIp = clientIp; return this; }
        public Builder userAgent(String userAgent) { this.userAgent = userAgent; return this; }
        public Builder sessionId(String sessionId) { this.sessionId = sessionId; return this; }
        public Builder method(String method) { this.method = method; return this; }
        public Builder path(String path) { this.path = path; return this; }
        public Builder query(String query) { this.query = query; return this; }
        public Builder headers(Map<String, String> headers) { this.headers = headers; return this; }
        
        public GatewayRequestContext build() {
            return new GatewayRequestContext(this);
        }
    }
}
