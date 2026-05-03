package com.example.bola_security.controller;

import com.example.bola_security.model.Resource;
import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.repository.UserRepository;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class GatewayAuthorizationApiControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private UserRepository userRepository;
    @Autowired private ResourceRepository resourceRepository;
    @Autowired private PasswordEncoder passwordEncoder;
    @Autowired private ObjectMapper objectMapper;

    private Long aliceResourceId;
    private Long carolResourceId;

    @BeforeEach
    void setUp() {
        resourceRepository.deleteAll();
        userRepository.deleteAll();

        User alice = new User();
        alice.setUsername("alice");
        alice.setPassword(passwordEncoder.encode("password"));
        alice.setRole(Role.USER);
        alice.setTenantId("tenant-alpha");
        alice.setDepartment("Engineering");
        alice = userRepository.save(alice);

        User carol = new User();
        carol.setUsername("carol");
        carol.setPassword(passwordEncoder.encode("password"));
        carol.setRole(Role.USER);
        carol.setTenantId("tenant-beta");
        carol.setDepartment("Engineering");
        carol = userRepository.save(carol);

        Resource aliceResource = new Resource();
        aliceResource.setName("Alice record");
        aliceResource.setOwnerId(alice.getId());
        aliceResource.setTenantId("tenant-alpha");
        aliceResource.setDepartment("Engineering");
        aliceResourceId = resourceRepository.save(aliceResource).getId();

        Resource carolResource = new Resource();
        carolResource.setName("Carol record");
        carolResource.setOwnerId(carol.getId());
        carolResource.setTenantId("tenant-beta");
        carolResource.setDepartment("Engineering");
        carolResourceId = resourceRepository.save(carolResource).getId();
    }

    @Test
    void gatewayAuthorizeAllowsSameTenantResource() throws Exception {
        String accessToken = login("alice", "password").get("accessToken").asText();

        mockMvc.perform(post("/api/v1/gateway/authorize")
                        .header("Authorization", "Bearer " + accessToken)
                        .header("X-Gateway-Api-Key", "test-gateway-key")
                        .contentType("application/json")
                        .content("""
                                {
                                  "resourceId": %d,
                                  "httpMethod": "GET",
                                  "requestPath": "/api/v1/resources/%d",
                                  "ipAddress": "10.0.0.9",
                                  "userAgent": "GatewayJUnit",
                                  "sourceService": "edge-gateway"
                                }
                                """.formatted(aliceResourceId, aliceResourceId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(true))
                .andExpect(jsonPath("$.reason").value("OWNER_MATCH"))
                .andExpect(jsonPath("$.tenantId").value("tenant-alpha"));
    }

    @Test
    void gatewayAuthorizeReturnsDeniedDecisionForCrossTenantResource() throws Exception {
        String accessToken = login("alice", "password").get("accessToken").asText();

        mockMvc.perform(post("/api/v1/gateway/authorize")
                        .header("Authorization", "Bearer " + accessToken)
                        .header("X-Gateway-Api-Key", "test-gateway-key")
                        .contentType("application/json")
                        .content("""
                                {
                                  "resourceId": %d,
                                  "httpMethod": "GET",
                                  "requestPath": "/api/v1/resources/%d",
                                  "ipAddress": "10.0.0.9",
                                  "userAgent": "GatewayJUnit",
                                  "sourceService": "edge-gateway"
                                }
                                """.formatted(carolResourceId, carolResourceId)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.allowed").value(false))
                .andExpect(jsonPath("$.reason").value("TENANT_BOUNDARY_VIOLATION"));
    }

    private JsonNode login(String username, String password) throws Exception {
        String response = mockMvc.perform(post("/api/v1/auth/login")
                        .contentType("application/json")
                        .content("{\"username\":\"" + username + "\",\"password\":\"" + password + "\"}"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        return objectMapper.readTree(response);
    }
}
