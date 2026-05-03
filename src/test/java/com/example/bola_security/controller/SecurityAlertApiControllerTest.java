package com.example.bola_security.controller;

import com.example.bola_security.model.Resource;
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

import static org.hamcrest.Matchers.greaterThanOrEqualTo;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class SecurityAlertApiControllerTest {

    @Autowired private MockMvc mockMvc;
    @Autowired private UserRepository userRepository;
    @Autowired private ResourceRepository resourceRepository;
    @Autowired private PasswordEncoder passwordEncoder;

    private Long crossTenantResourceId;

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

        User alice = new User();
        alice.setUsername("alice");
        alice.setPassword(passwordEncoder.encode("password"));
        alice.setRole(Role.USER);
        alice.setTenantId("tenant-alpha");
        alice.setDepartment("Engineering");
        userRepository.save(alice);

        User carol = new User();
        carol.setUsername("carol");
        carol.setPassword(passwordEncoder.encode("password"));
        carol.setRole(Role.USER);
        carol.setTenantId("tenant-beta");
        carol.setDepartment("Engineering");
        carol = userRepository.save(carol);

        Resource resource = new Resource();
        resource.setName("Carol record");
        resource.setOwnerId(carol.getId());
        resource.setTenantId("tenant-beta");
        resource.setDepartment("Engineering");
        crossTenantResourceId = resourceRepository.save(resource).getId();
    }

    @Test
    void adminCanViewRaisedAlerts() throws Exception {
        mockMvc.perform(get("/api/v1/resources/{id}", crossTenantResourceId)
                        .header("User-Agent", "JUnit")
                        .with(user("alice").password("password").roles("USER")))
                .andExpect(status().isForbidden());

        mockMvc.perform(get("/api/v1/security/alerts")
                        .with(user("admin").password("admin123").roles("ADMIN")))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.content.length()", greaterThanOrEqualTo(1)))
                .andExpect(jsonPath("$.content[0].alertType").exists());
    }
}
