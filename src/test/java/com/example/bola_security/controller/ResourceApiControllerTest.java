package com.example.bola_security.controller;

import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;

import static org.hamcrest.Matchers.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
class ResourceApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ResourceRepository resourceRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

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

        User bob = new User();
        bob.setUsername("bob");
        bob.setPassword(passwordEncoder.encode("password"));
        bob.setRole(Role.USER);
        bob.setTenantId("tenant-alpha");
        bob.setDepartment("Finance");
        userRepository.save(bob);

        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("admin123"));
        admin.setRole(Role.ADMIN);
        admin.setTenantId("tenant-alpha");
        admin.setDepartment("Security");
        userRepository.save(admin);

        User carol = new User();
        carol.setUsername("carol");
        carol.setPassword(passwordEncoder.encode("password"));
        carol.setRole(Role.USER);
        carol.setTenantId("tenant-beta");
        carol.setDepartment("Engineering");
        carol = userRepository.save(carol);

        com.example.bola_security.model.Resource resource = new com.example.bola_security.model.Resource();
        resource.setName("Alice payroll record");
        resource.setOwnerId(alice.getId());
        resource.setTenantId("tenant-alpha");
        resource.setDepartment("Engineering");
        resource.setDescription("Owned by Alice.");
        aliceResourceId = resourceRepository.save(resource).getId();

        com.example.bola_security.model.Resource carolResource = new com.example.bola_security.model.Resource();
        carolResource.setName("Carol tenant beta record");
        carolResource.setOwnerId(carol.getId());
        carolResource.setTenantId("tenant-beta");
        carolResource.setDepartment("Engineering");
        carolResource.setDescription("Owned by Carol.");
        carolResourceId = resourceRepository.save(carolResource).getId();
    }

    @Test
    void unauthenticatedNumericResourceAccessIsBlockedBeforeController() throws Exception {
        mockMvc.perform(get("/api/v1/resources/{id}", aliceResourceId))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void mockUserOwnerCannotBypassJwtUidCheck() throws Exception {
        mockMvc.perform(get("/api/v1/resources/{id}", aliceResourceId)
                        .header("User-Agent", "JUnit")
                        .with(user("alice").password("password").roles("USER")))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void nonOwnerNonAdminIsBlocked() throws Exception {
        mockMvc.perform(get("/api/v1/resources/{id}", aliceResourceId)
                        .header("User-Agent", "JUnit")
                        .with(user("bob").password("password").roles("USER")))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void adminMockUserCannotBypassJwtUidCheck() throws Exception {
        mockMvc.perform(get("/api/v1/resources/{id}", aliceResourceId)
                        .header("User-Agent", "JUnit")
                        .with(user("admin").password("admin123").roles("ADMIN")))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void crossTenantAccessIsBlocked() throws Exception {
        mockMvc.perform(get("/api/v1/resources/{id}", carolResourceId)
                        .header("User-Agent", "JUnit")
                        .with(user("alice").password("password").roles("USER")))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void nonExistentNumericResourceIsBlockedBeforeControllerLookup() throws Exception {
        mockMvc.perform(get("/api/v1/resources/{id}", 99999L)
                        .header("User-Agent", "JUnit")
                        .with(user("alice").password("password").roles("USER")))
                .andExpect(status().isForbidden())
                .andExpect(content().string("Access Denied: BOLA detected"));
    }

    @Test
    void myResourcesReturnsOnlyOwnedResources() throws Exception {
        mockMvc.perform(get("/api/v1/resources/mine")
                        .with(user("alice").password("password").roles("USER")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content", hasSize(greaterThanOrEqualTo(1))))
                .andExpect(jsonPath("$.content[0].ownerId").exists());
    }

    @Test
    void createResourceSucceeds() throws Exception {
        mockMvc.perform(post("/api/v1/resources")
                        .with(user("alice").password("password").roles("USER"))
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"name\":\"New resource\",\"department\":\"Engineering\"}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.name").value("New resource"))
                .andExpect(jsonPath("$.ownerId").exists());
    }

    @Test
    void createResourceWithBlankNameFailsValidation() throws Exception {
        mockMvc.perform(post("/api/v1/resources")
                        .with(user("alice").password("password").roles("USER"))
                        .with(csrf())
                        .contentType("application/json")
                        .content("{\"name\":\"\",\"department\":\"Engineering\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }
}
