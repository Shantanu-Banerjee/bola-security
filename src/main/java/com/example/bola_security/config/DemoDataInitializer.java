package com.example.bola_security.config;

import com.example.bola_security.model.Resource;
import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class DemoDataInitializer implements CommandLineRunner {

    private final BolaSecurityProperties properties;
    private final UserRepository userRepository;
    private final ResourceRepository resourceRepository;
    private final PasswordEncoder passwordEncoder;

    public DemoDataInitializer(
            BolaSecurityProperties properties,
            UserRepository userRepository,
            ResourceRepository resourceRepository,
            PasswordEncoder passwordEncoder
    ) {
        this.properties = properties;
        this.userRepository = userRepository;
        this.resourceRepository = resourceRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (!properties.seedDemoData() || userRepository.count() > 0) {
            return;
        }

        User alice = createUser("alice", "password123", Role.USER, "tenant-alpha", "Engineering");
        User bob = createUser("bob", "password123", Role.USER, "tenant-alpha", "Finance");
        User carol = createUser("carol", "password123", Role.MANAGER, "tenant-alpha", "Engineering");
        User admin = createUser("admin", "password123", Role.ADMIN, "tenant-alpha", "Security");

        createResource("Alice payroll record", alice.getId(), alice.getTenantId(), "Engineering", "Owned by Alice.");
        createResource("Bob invoice archive", bob.getId(), bob.getTenantId(), "Finance", "Owned by Bob.");
        createResource("Carol research budget", carol.getId(), carol.getTenantId(), "Engineering", "Tenant beta owned record.");
        createResource("Security incident report", admin.getId(), admin.getTenantId(), "Security", "Admin-owned security record.");
    }

    private User createUser(String username, String rawPassword, Role role, String tenantId, String department) {
        User user = new User();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(rawPassword));
        user.setRole(role);
        user.setTenantId(tenantId);
        user.setDepartment(department);
        return userRepository.save(user);
    }

    private void createResource(String name, Long ownerId, String tenantId, String department, String description) {
        Resource resource = new Resource();
        resource.setName(name);
        resource.setOwnerId(ownerId);
        resource.setTenantId(tenantId);
        resource.setDepartment(department);
        resource.setDescription(description);
        resourceRepository.save(resource);
    }
}
