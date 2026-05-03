package com.example.bola_security.middleware;

import com.example.bola_security.dto.AuthTokenResponse;
import com.example.bola_security.dto.LoginRequest;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.UserRepository;
import com.example.bola_security.service.JwtTokenService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Demo Login Endpoint for the BOLA middleware prototype.
 * 
 * VIVA NOTE: This endpoint lets you authenticate and get a JWT token.
 * The JWT token contains a "uid" claim with the user's ID, which
 * our BolaMiddlewareFilter uses to check authorization.
 * 
 * Demo users (created by DataInitializer):
 *   alice  / password123  → User ID 1, Role USER
 *   bob    / password123  → User ID 2, Role USER
 *   carol  / password123  → User ID 3, Role MANAGER
 *   admin  / password123  → User ID 4, Role ADMIN
 */
@RestController
@RequestMapping("/api/v1/middleware")
@Tag(name = "Demo Authentication", description = "Login endpoint to get JWT tokens for testing")
public class DemoAuthController {

    private static final Logger log = LoggerFactory.getLogger(DemoAuthController.class);

    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;
    private final UserRepository userRepository;

    public DemoAuthController(AuthenticationManager authenticationManager,
                              JwtTokenService jwtTokenService,
                              UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.userRepository = userRepository;
    }

    @Operation(
        summary = "Login and get JWT token",
        description = "Authenticate with username/password to receive a JWT access token. "
                    + "Use this token in the Authorization header (Bearer) for subsequent API calls."
    )
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.username(), request.password()));

            User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            AuthTokenResponse tokenResponse = jwtTokenService.issueTokens(user);

            log.info("🔑 LOGIN SUCCESS: User {} (id={}, role={})", user.getUsername(), user.getId(), user.getRole());

            return ResponseEntity.ok(Map.of(
                "accessToken", tokenResponse.accessToken(),
                "tokenType", "Bearer",
                "expiresAt", tokenResponse.accessTokenExpiresAt(),
                "userId", user.getId(),
                "username", user.getUsername(),
                "role", user.getRole().name(),
                "message", "Use this token in Authorization header: Bearer <accessToken>"
            ));
        } catch (Exception e) {
            log.warn("❌ LOGIN FAILED: {} - {}", request.username(), e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Authentication failed", "message", "Invalid username or password"));
        }
    }
}
