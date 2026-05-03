package com.example.bola_security.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

import java.time.LocalDateTime;

@Entity
@Table(name = "refresh_tokens", indexes = {
        @Index(name = "idx_refresh_tokens_token_hash", columnList = "tokenHash", unique = true),
        @Index(name = "idx_refresh_tokens_user_expiry", columnList = "userId,expiresAt"),
        @Index(name = "idx_refresh_tokens_revoked", columnList = "revokedAt")
})
public class RefreshToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private Long userId;

    @Column(nullable = false, length = 80)
    private String username;

    @Column(nullable = false, length = 80)
    private String tenantId = "default";

    @Column(nullable = false, unique = true, length = 88)
    private String tokenHash;

    @Column(nullable = false)
    private LocalDateTime createdAt;

    @Column(nullable = false)
    private LocalDateTime expiresAt;

    private LocalDateTime revokedAt;

    @Column(length = 88)
    private String replacedByTokenHash;

    @Column(nullable = false)
    private String deviceFingerprint; // Device/browser fingerprint

    @Column(nullable = false)
    private String ipAddress;

    @Column(nullable = false)
    private LocalDateTime lastUsedAt;

    @Column(nullable = false)
    private boolean used = false; // Track if token has been used (for rotation)

    @Column(nullable = false)
    private int usageCount = 0;

    @Column(length = 500)
    private String userAgent;

    public Long getId() {
        return id;
    }

    public Long getUserId() {
        return userId;
    }

    public void setUserId(Long userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getTokenHash() {
        return tokenHash;
    }

    public void setTokenHash(String tokenHash) {
        this.tokenHash = tokenHash;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(LocalDateTime expiresAt) {
        this.expiresAt = expiresAt;
    }

    public LocalDateTime getRevokedAt() {
        return revokedAt;
    }

    public void setRevokedAt(LocalDateTime revokedAt) {
        this.revokedAt = revokedAt;
    }

    public String getReplacedByTokenHash() {
        return replacedByTokenHash;
    }

    public void setReplacedByTokenHash(String replacedByTokenHash) {
        this.replacedByTokenHash = replacedByTokenHash;
    }

    public String getDeviceFingerprint() {
        return deviceFingerprint;
    }

    public void setDeviceFingerprint(String deviceFingerprint) {
        this.deviceFingerprint = deviceFingerprint;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public LocalDateTime getLastUsedAt() {
        return lastUsedAt;
    }

    public void setLastUsedAt(LocalDateTime lastUsedAt) {
        this.lastUsedAt = lastUsedAt;
    }

    public boolean isUsed() {
        return used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }

    public int getUsageCount() {
        return usageCount;
    }

    public void setUsageCount(int usageCount) {
        this.usageCount = usageCount;
    }

    public String getUserAgent() {
        return userAgent;
    }

    public void setUserAgent(String userAgent) {
        this.userAgent = userAgent;
    }

    /**
     * Check if token is expired
     */
    public boolean isExpired() {
        return LocalDateTime.now().isAfter(expiresAt);
    }

    /**
     * Check if token is revoked
     */
    public boolean isRevoked() {
        return revokedAt != null;
    }

    /**
     * Check if token is valid (not expired, not revoked)
     */
    public boolean isValid() {
        return !isExpired() && !isRevoked();
    }

    /**
     * Mark token as used (for refresh rotation)
     */
    public void markAsUsed() {
        this.used = true;
        this.lastUsedAt = LocalDateTime.now();
        this.usageCount++;
    }

    /**
     * Revoke token
     */
    public void revoke() {
        this.revokedAt = LocalDateTime.now();
    }
}
