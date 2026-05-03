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

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityIncidentApiControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ResourceRepository resourceRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setUp() {
        resourceRepository.deleteAll();
        userRepository.deleteAll();

        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword(passwordEncoder.encode("admin123"));
        admin.setRole(Role.ADMIN);
        admin.setTenantId("tenant-alpha");
        admin.setDepartment("Security");
        userRepository.save(admin);

        User user = new User();
        user.setUsername("alice");
        user.setPassword(passwordEncoder.encode("password"));
        user.setRole(Role.USER);
        user.setTenantId("tenant-alpha");
        user.setDepartment("Engineering");
        userRepository.save(user);
    }

    @Test
    void adminCanViewIncidents() throws Exception {
        mockMvc.perform(get("/api/v1/security/incidents")
                        .with(user("admin").password("admin123").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content").isArray());
    }

    @Test
    void nonAdminCannotViewIncidents() throws Exception {
        mockMvc.perform(get("/api/v1/security/incidents")
                        .with(user("alice").password("password").roles("USER")))
                .andExpect(status().isForbidden());
    }

    @Test
    void unauthenticatedCannotViewIncidents() throws Exception {
        mockMvc.perform(get("/api/v1/security/incidents"))
                .andExpect(status().isUnauthorized());
    }
}
