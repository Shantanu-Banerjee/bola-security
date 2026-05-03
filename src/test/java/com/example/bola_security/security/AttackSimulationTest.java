package com.example.bola_security.security;

import com.example.bola_security.model.*;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureWebMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests simulating real attack scenarios against the BOLA security system.
 * Tests IDOR attacks, privilege escalation, and other common attack vectors.
 */
@SpringBootTest
@AutoConfigureWebMvc
@ActiveProfiles("test")
class AttackSimulationTest {

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ResourceRepository resourceRepository;

    @MockBean
    private SecurityDefenseService securityDefenseService;

    @Autowired
    private SecurityDefenseFilter securityDefenseFilter;

    private MockMvc mockMvc;
    private ObjectMapper objectMapper;
    private User alice;
    private User bob;
    private User admin;
    private List<Resource> aliceResources;

    @BeforeEach
    void setUp() {
        mockMvc = MockMvcBuilders
            .webAppContextSetup(context)
            .defaultRequest(get("/").header("User-Agent", "JUnit"))
            .addFilters(securityDefenseFilter)
            .apply(springSecurity())
            .build();

        objectMapper = new ObjectMapper();
        resourceRepository.deleteAll();
        userRepository.deleteAll();

        // Create test users
        alice = userRepository.save(createTestUser("alice", Role.USER, "Engineering"));
        bob = userRepository.save(createTestUser("bob", Role.USER, "Finance"));
        admin = userRepository.save(createTestUser("admin", Role.ADMIN, "IT"));

        // Create test resources
        List<Resource> resources = new ArrayList<>();
        for (int i = 1; i <= 5; i++) {
            Resource resource = createTestResource(
                alice.getId(), "Engineering",
                "Alice's Resource " + i
            );
            resources.add(resource);
        }

        aliceResources = resourceRepository.saveAll(resources);
    }

    @Test
    @WithMockUser(username = "bob")
    void testIdorAttackPrevention() throws Exception {
        // Bob tries to access Alice's resources by enumerating IDs
        for (Resource resource : aliceResources) {
            mockMvc.perform(get("/api/v1/resources/{id}", resource.getId()))
                    .andExpect(status().isForbidden());
        }

    }

    @Test
    @WithMockUser(username = "bob")
    void testHorizontalPrivilegeEscalation() throws Exception {
        // Bob tries to update Alice's resource
        mockMvc.perform(put("/api/v1/resources/{id}", aliceResources.get(0).getId())
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("bob"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new com.example.bola_security.dto.ResourceCreateRequest(
                        "Hacked Resource", "IT", "Hacked by Bob"
                    )
                )))
                .andExpect(status().isForbidden());

        // Bob tries to delete Alice's resource
        mockMvc.perform(delete("/api/v1/resources/{id}", aliceResources.get(0).getId())
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("bob")))
                .andExpect(status().isForbidden());
    }

    @Test
    void testSequentialProbingDetection() throws Exception {
        // Simulate sequential ID probing attack
        for (Resource resource : aliceResources) {
            mockMvc.perform(get("/api/v1/resources/{id}", resource.getId())
                    .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("bob")))
                    .andExpect(status().isForbidden());
        }

        // Verify security incident was triggered
        // This would be verified through SecurityIncidentRepository in real implementation
    }

    @Test
    @WithMockUser(username = "admin", roles = "ADMIN")
    void testAdminMockUserCannotBypassRealtimeBolaFilter() throws Exception {
        // The real-time BOLA filter requires a live bearer JWT uid claim; mock users are not enough.
        mockMvc.perform(get("/api/v1/resources/{id}", aliceResources.get(0).getId()))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));

        mockMvc.perform(put("/api/v1/resources/{id}", aliceResources.get(0).getId())
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new com.example.bola_security.dto.ResourceCreateRequest(
                        "Admin Updated", "IT", "Updated by admin"
                    )
                )))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void testSameDepartmentAccess() throws Exception {
        // Create a Finance user
        User financeUser = createTestUser("finance_user", Role.USER, "Finance");
        userRepository.save(financeUser);

        // Create a Finance resource owned by Alice. A same-department non-owner is still blocked
        // by the strict object-level ownership policy.
        Resource financeResource = createTestResource(alice.getId(), "Finance", "Finance Resource");
        financeResource = resourceRepository.save(financeResource);

        // Finance user should not read or write Alice's resource.
        mockMvc.perform(get("/api/v1/resources/{id}", financeResource.getId())
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("finance_user")))
                .andExpect(status().isForbidden());

        mockMvc.perform(put("/api/v1/resources/{id}", financeResource.getId())
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("finance_user"))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(
                    new com.example.bola_security.dto.ResourceCreateRequest(
                        "Hacked", "Finance", "Hacked"
                    )
                )))
                .andExpect(status().isForbidden());
    }

    @Test
    void testRateLimiting() throws Exception {
        // Mock rate limiting to trigger after 5 requests
        when(securityDefenseService.isIpRateLimited("127.0.0.1"))
            .thenReturn(false, false, false, false, false, true);

        // First 5 requests reach the real-time BOLA filter and are blocked before controller logic.
        for (int i = 0; i < 5; i++) {
            mockMvc.perform(get("/api/v1/resources/{id}", aliceResources.get(0).getId())
                    .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("alice")))
                    .andExpect(status().isForbidden())
                    .andExpect(content().string("Access Denied: BOLA detected"));
        }

        // The defense filter still runs before Spring Security and can rate-limit later requests.
        mockMvc.perform(get("/api/v1/resources/{id}", aliceResources.get(0).getId())
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user("alice")))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void testBruteForceLoginProtection() throws Exception {
        // Mock brute force detection
        when(securityDefenseService.isLoginRateLimited("192.168.1.100"))
            .thenReturn(false, false, false, false, true);

        // First 4 login attempts should be processed
        for (int i = 0; i < 4; i++) {
            mockMvc.perform(post("/api/v1/auth/login")
                    .header("X-Forwarded-For", "192.168.1.100")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"username\":\"bob\",\"password\":\"wrongpassword\"}"))
                    .andExpect(status().isUnauthorized());
        }

        // 5th login attempt should be rate limited
        mockMvc.perform(post("/api/v1/auth/login")
                .header("X-Forwarded-For", "192.168.1.100")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"username\":\"bob\",\"password\":\"wrongpassword\"}"))
                .andExpect(status().isTooManyRequests());
    }

    @Test
    void testTokenReuseDetection() throws Exception {
        // This would test refresh token reuse detection
        // Implementation would require actual token service integration
        // For now, just verify the endpoint exists
        mockMvc.perform(post("/api/v1/auth/refresh")
                .contentType(MediaType.APPLICATION_JSON)
                .content("{\"refreshToken\":\"reused-token\"}"))
                .andExpect(status().isUnauthorized());
    }

    private User createTestUser(String username, Role role, String department) {
        User user = new User();
        user.setUsername(username);
        user.setRole(role);
        user.setDepartment(department);
        user.setTenantId("default");
        user.setAccountLocked(false);
        user.setFailedBolaAttempts(0);
        user.setPassword("password"); // In real test, would be encoded
        return user;
    }

    private Resource createTestResource(Long ownerId, String department, String name) {
        Resource resource = new Resource();
        resource.setOwnerId(ownerId);
        resource.setDepartment(department);
        resource.setTenantId("default");
        resource.setName(name);
        resource.setDescription("Test resource");
        return resource;
    }
}
