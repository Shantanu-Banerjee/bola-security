package com.example.bola_security.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "access_logs", indexes = {
        @Index(name = "idx_access_logs_user_time", columnList = "userId,timestamp"),
        @Index(name = "idx_access_logs_resource", columnList = "resourceId")
})
public class AccessLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false)
    private Long resourceId;

    @Column(nullable = false)
    private Long resourceOwnerId;

    @Column(nullable = false, length = 30)
    private String result;

    @Column(nullable = false, length = 200)
    private String reason;

    @Column(nullable = false)
    private LocalDateTime timestamp;

    @Column(length = 80)
    private String username;

    @Column(length = 80)
    private String userTenantId;

    @Column(length = 80)
    private String userDepartment;

    @Column(length = 80)
    private String resourceTenantId;

    @Column(length = 80)
    private String resourceDepartment;

    @Column(length = 30)
    private String userRole;

    private boolean ownerMatch;

    private boolean sameDepartment;

    private boolean tenantMatch;

    @Column(length = 80)
    private String ipAddress;

    @Column(length = 500)
    private String userAgent;

    @Column(length = 120)
    private String sessionId;

    @Column(length = 20)
    private String httpMethod;

    @Column(length = 250)
    private String requestPath;

    private int accessHour;

    private long recentDistinctResourceCount;

    private int riskScore;

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public Long getResourceId() {
        return resourceId;
    }

    public void setResourceId(Long resourceId) {
        this.resourceId = resourceId;
    }

    public Long getResourceOwnerId() {
        return resourceOwnerId;
    }

    public void setResourceOwnerId(Long resourceOwnerId) {
        this.resourceOwnerId = resourceOwnerId;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getReason() {
        return reason;
    }

    public void setReason(String reason) {
        this.reason = reason;
    }

    public LocalDateTime getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(LocalDateTime timestamp) {
        this.timestamp = timestamp;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getUserTenantId() {
        return userTenantId;
    }

    public void setUserTenantId(String userTenantId) {
        this.userTenantId = userTenantId;
    }

    public String getUserDepartment() {
        return userDepartment;
    }

    public void setUserDepartment(String userDepartment) {
        this.userDepartment = userDepartment;
    }

    public String getResourceTenantId() {
        return resourceTenantId;
    }

    public void setResourceTenantId(String resourceTenantId) {
        this.resourceTenantId = resourceTenantId;
    }

    public String getResourceDepartment() {
        return resourceDepartment;
    }

    public void setResourceDepartment(String resourceDepartment) {
        this.resourceDepartment = resourceDepartment;
    }

    public String getUserRole() {
        return userRole;
    }

    public void setUserRole(String userRole) {
        this.userRole = userRole;
    }

    public boolean isOwnerMatch() {
        return ownerMatch;
    }

    public void setOwnerMatch(boolean ownerMatch) {
        this.ownerMatch = ownerMatch;
    }

    public boolean isSameDepartment() {
        return sameDepartment;
    }

    public void setSameDepartment(boolean sameDepartment) {
        this.sameDepartment = sameDepartment;
    }

    public boolean isTenantMatch() {
        return tenantMatch;
    }

    public void setTenantMatch(boolean tenantMatch) {
        this.tenantMatch = tenantMatch;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public void setHttpMethod(String httpMethod) {
        this.httpMethod = httpMethod;
    }

    public String getRequestPath() {
        return requestPath;
    }

    public void setRequestPath(String requestPath) {
        this.requestPath = requestPath;
    }

    public int getAccessHour() {
        return accessHour;
    }

    public void setAccessHour(int accessHour) {
        this.accessHour = accessHour;
    }

    public long getRecentDistinctResourceCount() {
        return recentDistinctResourceCount;
    }

    public void setRecentDistinctResourceCount(long recentDistinctResourceCount) {
        this.recentDistinctResourceCount = recentDistinctResourceCount;
    }

    public int getRiskScore() {
        return riskScore;
    }

    public void setRiskScore(int riskScore) {
        this.riskScore = riskScore;
    }
}
