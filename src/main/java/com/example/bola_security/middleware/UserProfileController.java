package com.example.bola_security.middleware;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * STEP 1: Dummy Backend REST API
 * 
 * This is the PROTECTED RESOURCE that our BOLA middleware guards.
 * It returns simple mocked user data.
 * 
 * VIVA NOTE: This simulates a real backend API that stores user profiles.
 * In production, this would query a database. Here we use a static map
 * to keep things simple and demo-ready.
 */
@RestController
@RequestMapping("/api/user")
@Tag(name = "User Profile API", description = "Protected user profile endpoints - BOLA target")
public class UserProfileController {

    // Mock user data - simulates the backend database protected by the middleware.
    private static final Map<Long, Map<String, String>> USER_DATABASE = Map.of(
        1L, Map.of("id", "1", "name", "Alice Johnson", "email", "alice@example.com", "role", "USER", "department", "Engineering"),
        2L, Map.of("id", "2", "name", "Bob Smith", "email", "bob@example.com", "role", "USER", "department", "Finance"),
        3L, Map.of("id", "3", "name", "Carol Davis", "email", "carol@example.com", "role", "MANAGER", "department", "Engineering"),
        4L, Map.of("id", "4", "name", "Admin User", "email", "admin@example.com", "role", "ADMIN", "department", "IT")
    );

    @Operation(
        summary = "Get user profile by ID",
        description = "Returns user profile data. This is the endpoint protected by BOLA middleware. "
                    + "Only the logged-in user can access their own profile (unless they are ADMIN)."
    )
    @GetMapping("/{id}")
    public ResponseEntity<Map<String, String>> getUserProfile(@PathVariable Long id) {
        Map<String, String> user = USER_DATABASE.get(id);
        if (user == null) {
            return ResponseEntity.notFound().build();
        }
        return ResponseEntity.ok(user);
    }
}
