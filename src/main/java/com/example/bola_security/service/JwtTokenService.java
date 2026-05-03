package com.example.bola_security.service;

import com.example.bola_security.config.BolaSecurityProperties;
import com.example.bola_security.dto.AuthTokenResponse;
import com.example.bola_security.exception.InvalidRefreshTokenException;
import com.example.bola_security.model.RefreshToken;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.UserRepository;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;

@Service
public class JwtTokenService {

    private static final String BEARER_PREFIX = "Bearer ";
    private static final String USER_ID_CLAIM = "uid";

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final BolaSecurityProperties properties;
    private final Clock clock;

    public JwtTokenService(
            JwtEncoder jwtEncoder,
            JwtDecoder jwtDecoder,
            RefreshTokenService refreshTokenService,
            UserRepository userRepository,
            BolaSecurityProperties properties,
            Clock clock
    ) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.refreshTokenService = refreshTokenService;
        this.userRepository = userRepository;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public AuthTokenResponse issueTokens(User user) {
        if (user.isAccountLocked()) {
            throw new LockedException("Account is locked");
        }
        Instant now = clock.instant();
        Instant accessTokenExpiresAt = now.plus(properties.accessTokenTtl());
        String accessToken = encodeAccessToken(user, now, accessTokenExpiresAt);
        RefreshTokenService.IssuedRefreshToken refreshToken = refreshTokenService.issue(user);

        return new AuthTokenResponse(
                accessToken,
                "Bearer",
                accessTokenExpiresAt,
                refreshToken.token(),
                refreshToken.expiresAt()
        );
    }

    @Transactional
    public AuthTokenResponse refresh(String rawRefreshToken) {
        RefreshToken consumedToken = refreshTokenService.consume(rawRefreshToken);
        User user = userRepository.findById(consumedToken.getUserId())
                .orElseThrow(InvalidRefreshTokenException::new);
        AuthTokenResponse response = issueTokens(user);
        refreshTokenService.markReplaced(consumedToken, refreshTokenService.hash(response.refreshToken()));
        return response;
    }

    public Long extractUserIdFromAuthorizationHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.startsWith(BEARER_PREFIX)) {
            throw new IllegalArgumentException("Missing bearer token");
        }

        Jwt jwt = jwtDecoder.decode(authorizationHeader.substring(BEARER_PREFIX.length()));
        Object userIdClaim = jwt.getClaims().get(USER_ID_CLAIM);
        if (userIdClaim == null) {
            throw new IllegalArgumentException("JWT is missing uid claim");
        }

        if (userIdClaim instanceof Number number) {
            return number.longValue();
        }

        if (userIdClaim instanceof String userIdText) {
            try {
                return Long.parseLong(userIdText);
            } catch (NumberFormatException exception) {
                throw new IllegalArgumentException("JWT uid claim is not numeric", exception);
            }
        }

        throw new IllegalArgumentException("JWT uid claim has unsupported type");
    }

    private String encodeAccessToken(User user, Instant issuedAt, Instant expiresAt) {
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(properties.jwtIssuer())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .subject(user.getUsername())
                .claim("uid", user.getId())
                .claim("tid", user.getTenantId())
                .claim("department", user.getDepartment())
                .claim("authorities", List.of("ROLE_" + user.getRole().name()))
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
