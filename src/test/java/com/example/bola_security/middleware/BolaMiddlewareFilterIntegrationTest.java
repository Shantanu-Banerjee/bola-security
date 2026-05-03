package com.example.bola_security.middleware;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.test.web.servlet.MockMvc;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class BolaMiddlewareFilterIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Autowired
    private RateLimitService rateLimitService;

    @Autowired
    private SecurityLogService securityLogService;

    @BeforeEach
    void resetMiddlewareState() {
        rateLimitService.reset();
        securityLogService.reset();
    }

    @Test
    void validOwnerRequestReachesBackendApi() throws Exception {
        mockMvc.perform(get("/api/user/1")
                        .header(HttpHeaders.AUTHORIZATION, bearerToken(1L, "USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", equalTo("1")))
                .andExpect(jsonPath("$.name", equalTo("Alice Johnson")));
    }

    @Test
    void bolaAttemptIsBlockedBeforeController() throws Exception {
        mockMvc.perform(get("/api/user/2")
                        .header(HttpHeaders.AUTHORIZATION, bearerToken(1L, "USER")))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void repeatedMatchingRequestsAreHandledByRealtimeBolaFilter() throws Exception {
        String token = bearerToken(1L, "USER");

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(get("/api/user/1")
                            .header(HttpHeaders.AUTHORIZATION, token))
                    .andExpect(status().isOk());
        }

        mockMvc.perform(get("/api/user/1")
                        .header(HttpHeaders.AUTHORIZATION, token))
                .andExpect(status().isOk());
    }

    @Test
    void legacyDashboardIsNotUpdatedByRealtimeBolaFilter() throws Exception {
        mockMvc.perform(get("/api/user/1")
                        .header(HttpHeaders.AUTHORIZATION, bearerToken(1L, "USER")))
                .andExpect(status().isOk());

        mockMvc.perform(get("/api/user/2")
                        .header(HttpHeaders.AUTHORIZATION, bearerToken(1L, "USER")))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/v1/middleware/dashboard/stats"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalRequests", equalTo(0)))
                .andExpect(jsonPath("$.allowedRequests", equalTo(0)))
                .andExpect(jsonPath("$.blockedAttacks", equalTo(0)));
    }

    private String bearerToken(Long userId, String role) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject("demo-user-" + userId)
                .issuedAt(now)
                .expiresAt(now.plus(Duration.ofMinutes(15)))
                .claim("uid", userId)
                .claim("authorities", List.of("ROLE_" + role))
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return "Bearer " + token;
    }
}
