package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import com.example.bola_security.exception.InvalidRefreshTokenException;
import com.example.bola_security.model.RefreshToken;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;
    private final BolaSecurityProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Clock clock;

    public RefreshTokenService(
            RefreshTokenRepository refreshTokenRepository,
            BolaSecurityProperties properties,
            Clock clock
    ) {
        this.refreshTokenRepository = refreshTokenRepository;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public IssuedRefreshToken issue(User user) {
        String token = randomToken();
        LocalDateTime now = LocalDateTime.now(clock);
        LocalDateTime expiresAt = now.plus(properties.refreshTokenTtl());

        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUserId(user.getId());
        refreshToken.setUsername(user.getUsername());
        refreshToken.setTenantId(user.getTenantId());
        refreshToken.setTokenHash(hash(token));
        refreshToken.setCreatedAt(now);
        refreshToken.setExpiresAt(expiresAt);
        refreshToken.setDeviceFingerprint("server-issued");
        refreshToken.setIpAddress("unknown");
        refreshToken.setLastUsedAt(now);
        refreshToken.setUserAgent("unknown");
        refreshTokenRepository.save(refreshToken);

        return new IssuedRefreshToken(token, refreshToken.getTokenHash(), expiresAt);
    }

    @Transactional
    public RefreshToken consume(String rawToken) {
        RefreshToken refreshToken = refreshTokenRepository.findByTokenHash(hash(rawToken))
                .orElseThrow(InvalidRefreshTokenException::new);
        LocalDateTime now = LocalDateTime.now(clock);
        if (refreshToken.getRevokedAt() != null || !refreshToken.getExpiresAt().isAfter(now)) {
            throw new InvalidRefreshTokenException();
        }
        refreshToken.setUsed(true);
        refreshToken.setUsageCount(refreshToken.getUsageCount() + 1);
        refreshToken.setLastUsedAt(now);
        refreshToken.setRevokedAt(now);
        return refreshTokenRepository.save(refreshToken);
    }

    @Transactional
    public void markReplaced(RefreshToken consumedToken, String replacementHash) {
        consumedToken.setReplacedByTokenHash(replacementHash);
        refreshTokenRepository.save(consumedToken);
    }

    @Transactional
    public void revoke(String rawToken) {
        refreshTokenRepository.findByTokenHash(hash(rawToken)).ifPresent(refreshToken -> {
            if (refreshToken.getRevokedAt() == null) {
                refreshToken.setRevokedAt(LocalDateTime.now(clock));
                refreshTokenRepository.save(refreshToken);
            }
        });
    }

    private String randomToken() {
        byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    public String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return Base64.getUrlEncoder().withoutPadding()
                    .encodeToString(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is required for refresh token hashing", exception);
        }
    }

    public record IssuedRefreshToken(String token, String tokenHash, LocalDateTime expiresAt) {
    }
}
