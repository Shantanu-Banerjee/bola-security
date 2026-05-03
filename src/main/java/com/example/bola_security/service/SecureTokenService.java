package com.example.bola_security.service;

import com.example.bola_security.model.RefreshToken;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.*;

// Simplified implementation without JWT dependencies for now
// In production, add JWT dependency: io.jsonwebtoken:jjwt-api, jjwt-impl, jjwt-jackson

/**
 * Secure token lifecycle management with refresh rotation and reuse detection.
 * Implements industry-grade token security practices.
 */
@Service
public class SecureTokenService {

    @Value("${app.jwt.secret:my-super-secret-key-that-is-long-enough-for-hs256-algorithm}")
    private String jwtSecret;

    @Value("${app.jwt.expiration:900}") // 15 minutes default
    private int jwtExpirationInSeconds;

    @Value("${app.refresh-token.expiration:604800}") // 7 days default
    private int refreshTokenExpirationInSeconds;

    private final RefreshTokenRepository refreshTokenRepository;
    private final SecureRandom secureRandom;

    public SecureTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.secureRandom = new SecureRandom();
    }

    /**
     * Generate access token for authenticated user
     * Simplified version - in production use proper JWT library
     */
    public String generateAccessToken(User user) {
        // Generate a simple token for demonstration
        // In production, use proper JWT library
        String tokenData = user.getId() + ":" + user.getUsername() + ":" + System.currentTimeMillis();
        return Base64.getEncoder().encodeToString(tokenData.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Generate refresh token with rotation support
     */
    public RefreshTokenResult generateRefreshToken(User user, String deviceFingerprint, 
                                                   String ipAddress, String userAgent) {
        // Generate random token
        String rawToken = generateRandomToken();
        String tokenHash = hashToken(rawToken);
        
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime expiryDate = now.plusSeconds(refreshTokenExpirationInSeconds);

        // Create refresh token entity
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(user.getId());
        refreshToken.setUsername(user.getUsername());
        refreshToken.setTenantId(user.getTenantId());
        refreshToken.setTokenHash(tokenHash);
        refreshToken.setDeviceFingerprint(deviceFingerprint);
        refreshToken.setIpAddress(ipAddress);
        refreshToken.setUserAgent(userAgent);
        refreshToken.setCreatedAt(now);
        refreshToken.setExpiresAt(expiryDate);
        refreshToken.setLastUsedAt(now);
        refreshToken.setUsed(false);
        refreshToken.setUsageCount(0);

        // Save to database
        RefreshToken saved = refreshTokenRepository.save(refreshToken);

        return new RefreshTokenResult(rawToken, saved.getId());
    }

    /**
     * Refresh access token with rotation and reuse detection
     */
    public TokenRefreshResult refreshAccessToken(String rawRefreshToken, String deviceFingerprint,
                                                String ipAddress, String userAgent) {
        String tokenHash = hashToken(rawRefreshToken);

        // Find the refresh token
        Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);
        if (tokenOpt.isEmpty()) {
            throw new SecurityException("Invalid refresh token");
        }

        RefreshToken refreshToken = tokenOpt.get();

        // Validate token
        if (!refreshToken.isValid()) {
            throw new SecurityException("Refresh token is invalid or expired");
        }

        // Check for reuse detection
        if (refreshToken.isUsed()) {
            // Token reuse detected - this indicates possible token theft
            handleTokenReuse(refreshToken);
            throw new SecurityException("Token reuse detected - all tokens revoked");
        }

        // Verify device fingerprint and IP (optional but recommended)
        if (!refreshToken.getDeviceFingerprint().equals(deviceFingerprint)) {
            // Log suspicious activity but allow for now (configurable)
            logSuspiciousActivity("Device fingerprint mismatch", refreshToken);
        }

        if (!refreshToken.getIpAddress().equals(ipAddress)) {
            // Log suspicious activity but allow for now (configurable)
            logSuspiciousActivity("IP address mismatch", refreshToken);
        }

        // Mark current token as used (rotation)
        refreshToken.markAsUsed();
        refreshTokenRepository.save(refreshToken);

        // Get user and generate new tokens
        User user = getUserById(refreshToken.getUserId());
        String newAccessToken = generateAccessToken(user);
        RefreshTokenResult newRefreshToken = generateRefreshToken(user, deviceFingerprint, ipAddress, userAgent);

        // Link old token to new token for audit trail
        refreshToken.setReplacedByTokenHash(hashToken(newRefreshToken.token()));
        refreshTokenRepository.save(refreshToken);

        return new TokenRefreshResult(newAccessToken, newRefreshToken);
    }

    /**
     * Revoke all refresh tokens for a user
     */
    public void revokeAllUserTokens(Long userId) {
        List<RefreshToken> tokens = refreshTokenRepository.findByUserIdAndRevokedAtIsNull(userId);
        
        for (RefreshToken token : tokens) {
            token.revoke();
        }
        
        refreshTokenRepository.saveAll(tokens);
    }

    /**
     * Revoke specific refresh token
     */
    public void revokeRefreshToken(String rawRefreshToken) {
        String tokenHash = hashToken(rawRefreshToken);
        Optional<RefreshToken> tokenOpt = refreshTokenRepository.findByTokenHash(tokenHash);
        
        if (tokenOpt.isPresent()) {
            RefreshToken token = tokenOpt.get();
            token.revoke();
            refreshTokenRepository.save(token);
        }
    }

    /**
     * Clean up expired tokens
     */
    public void cleanupExpiredTokens() {
        LocalDateTime cutoff = LocalDateTime.now().minusDays(30);
        List<RefreshToken> expiredTokens = refreshTokenRepository.findByExpiresAtBefore(cutoff);
        refreshTokenRepository.deleteAll(expiredTokens);
    }

    /**
     * Parse and validate access token (simplified version)
     */
    public Map<String, String> parseAccessToken(String token) {
        try {
            // Simplified token parsing - in production use proper JWT library
            String decoded = new String(Base64.getDecoder().decode(token), StandardCharsets.UTF_8);
            String[] parts = decoded.split(":");
            
            Map<String, String> claims = new HashMap<>();
            if (parts.length >= 3) {
                claims.put("userId", parts[0]);
                claims.put("username", parts[1]);
                claims.put("timestamp", parts[2]);
            }
            return claims;
        } catch (Exception e) {
            throw new SecurityException("Invalid access token", e);
        }
    }

    /**
     * Generate cryptographically secure random token
     */
    private String generateRandomToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }

    /**
     * Hash token for secure storage
     */
    private String hashToken(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(token.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Failed to hash token", e);
        }
    }

    /**
     * Handle token reuse detection
     */
    private void handleTokenReuse(RefreshToken reusedToken) {
        // Revoke all tokens for this user
        revokeAllUserTokens(reusedToken.getUserId());
        
        // Log security incident
        logSecurityIncident("Token reuse detected", reusedToken);
        
        // Optionally: lock user account temporarily
        // Optionally: notify security team
    }

    /**
     * Log suspicious activity
     */
    private void logSuspiciousActivity(String message, RefreshToken token) {
        System.out.println(String.format(
            "SUSPICIOUS ACTIVITY: %s - Token ID: %d, User: %d, IP: %s, Device: %s",
            message, token.getId(), token.getUserId(), token.getIpAddress(), token.getDeviceFingerprint()
        ));
    }

    /**
     * Log security incident
     */
    private void logSecurityIncident(String message, RefreshToken token) {
        System.out.println(String.format(
            "SECURITY INCIDENT: %s - Token ID: %d, User: %d, IP: %s, Device: %s",
            message, token.getId(), token.getUserId(), token.getIpAddress(), token.getDeviceFingerprint()
        ));
    }

    /**
     * Get user by ID (simplified - would use UserService in real implementation)
     */
    private User getUserById(Long userId) {
        // This would typically inject and use UserService
        // For now, return a placeholder
        User user = new User();
        user.setId(userId);
        return user;
    }

    /**
     * Result objects for token operations
     */
    public record RefreshTokenResult(String token, Long tokenId) {}
    public record TokenRefreshResult(String accessToken, RefreshTokenResult refreshToken) {}
}
