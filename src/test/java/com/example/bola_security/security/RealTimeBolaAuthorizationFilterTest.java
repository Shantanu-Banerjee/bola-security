package com.example.bola_security.security;

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
class RealTimeBolaAuthorizationFilterTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtEncoder jwtEncoder;

    @Test
    void matchingJwtUidReachesController() throws Exception {
        mockMvc.perform(get("/api/user/1")
                        .header(HttpHeaders.AUTHORIZATION, bearerToken(1L)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id", equalTo("1")));
    }

    @Test
    void mismatchedJwtUidIsBlockedBeforeController() throws Exception {
        mockMvc.perform(get("/api/user/999")
                        .header(HttpHeaders.AUTHORIZATION, bearerToken(1L)))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    private String bearerToken(Long userId) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .subject("user-" + userId)
                .issuedAt(now)
                .expiresAt(now.plus(Duration.ofMinutes(15)))
                .claim("uid", userId)
                .claim("authorities", List.of("ROLE_USER"))
                .build();

        JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        String token = jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return "Bearer " + token;
    }
}
