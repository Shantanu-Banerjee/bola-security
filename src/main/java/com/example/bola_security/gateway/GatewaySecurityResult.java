package com.example.bola_security.gateway;

/**
 * Result of security processing for a gateway request
 */
public class GatewaySecurityResult {
    
    private final boolean allowed;
    private final String reason;
    private final String violationType;
    private final int httpStatus;
    private final String userId;
    private final String objectId;
    private final int riskScore;
    private final long processingTimeMs;
    
    private GatewaySecurityResult(Builder builder) {
        this.allowed = builder.allowed;
        this.reason = builder.reason;
        this.violationType = builder.violationType;
        this.httpStatus = builder.httpStatus;
        this.userId = builder.userId;
        this.objectId = builder.objectId;
        this.riskScore = builder.riskScore;
        this.processingTimeMs = builder.processingTimeMs;
    }
    
    public static Builder builder() {
        return new Builder();
    }
    
    public static GatewaySecurityResult allowed() {
        return builder().allowed(true).build();
    }
    
    public static GatewaySecurityResult blocked(String reason, String violationType) {
        return builder()
            .allowed(false)
            .reason(reason)
            .violationType(violationType)
            .httpStatus(403)
            .build();
    }
    
    // Getters
    public boolean isAllowed() { return allowed; }
    public String getReason() { return reason; }
    public String getViolationType() { return violationType; }
    public int getHttpStatus() { return httpStatus; }
    public String getUserId() { return userId; }
    public String getObjectId() { return objectId; }
    public int getRiskScore() { return riskScore; }
    public long getProcessingTimeMs() { return processingTimeMs; }
    
    public static class Builder {
        private boolean allowed = true;
        private String reason;
        private String violationType;
        private int httpStatus = 200;
        private String userId;
        private String objectId;
        private int riskScore = 0;
        private long processingTimeMs = 0;
        
        public Builder allowed(boolean allowed) { this.allowed = allowed; return this; }
        public Builder reason(String reason) { this.reason = reason; return this; }
        public Builder violationType(String violationType) { this.violationType = violationType; return this; }
        public Builder httpStatus(int httpStatus) { this.httpStatus = httpStatus; return this; }
        public Builder userId(String userId) { this.userId = userId; return this; }
        public Builder objectId(String objectId) { this.objectId = objectId; return this; }
        public Builder riskScore(int riskScore) { this.riskScore = riskScore; return this; }
        public Builder processingTimeMs(long processingTimeMs) { this.processingTimeMs = processingTimeMs; return this; }
        
        public GatewaySecurityResult build() {
            return new GatewaySecurityResult(this);
        }
    }
}
