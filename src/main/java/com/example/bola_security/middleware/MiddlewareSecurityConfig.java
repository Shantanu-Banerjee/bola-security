package com.example.bola_security.middleware;

import com.example.bola_security.security.BolaAuthorizationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * STEP 3: Middleware Security Configuration
 * 
 * Configures the Spring Security filter chain to:
 * 1. Require JWT authentication for /api/user/** endpoints
 * 2. Insert the real-time BOLA authorization filter before controller dispatch
 * 3. Allow public access to login, dashboard, swagger, and actuator
 * 
 * VIVA NOTE: The filter ordering is CRITICAL:
 * - First: BearerTokenAuthenticationFilter validates the JWT token
 * - Then: BolaAuthorizationFilter checks BOLA authorization
 * - Finally: Controller handles the request
 * 
 * This ensures that by the time our filter runs, we already know
 * WHO the user is (from the JWT), so we can check WHAT they can access.
 */
@Configuration
public class MiddlewareSecurityConfig {

    /**
     * API Security Filter Chain - protects /api/user/** endpoints
     * Order(1) means this runs BEFORE the main web filter chain
     */
    @Bean
    @Order(1)
    public SecurityFilterChain middlewareApiFilterChain(
            HttpSecurity http,
            BolaAuthorizationFilter bolaAuthorizationFilter
    ) throws Exception {
        http
            .securityMatcher("/api/user/**")
            .cors(cors -> cors.configurationSource(middlewareCorsConfig()))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .exceptionHandling(ex -> ex.authenticationEntryPoint(
                new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/api/user/*").authenticated()
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(middlewareJwtConverter())))
            .addFilterBefore(bolaAuthorizationFilter, AuthorizationFilter.class);

        return http.build();
    }

    /**
     * Public endpoints filter chain - no authentication required.
     * Allows access to login, dashboard, swagger, actuator, H2 console
     */
    @Bean
    @Order(0)
    public SecurityFilterChain middlewarePublicFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher(
                "/api/v1/auth/login",
                "/api/v1/auth/refresh",
                "/api/v1/middleware/login",
                "/api/v1/middleware/dashboard",
                "/api/v1/middleware/dashboard/**",
                "/swagger-ui/**",
                "/swagger-ui.html",
                "/api-docs",
                "/api-docs/**",
                "/v3/api-docs/**",
                "/actuator/**",
                "/h2-console/**"
            )
            .cors(cors -> cors.configurationSource(middlewareCorsConfig()))
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
            .headers(headers -> headers.frameOptions(frame -> frame.sameOrigin()));

        return http.build();
    }

    private CorsConfigurationSource middlewareCorsConfig() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("*"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type", "X-User-ID"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);
        return source;
    }

    private JwtAuthenticationConverter middlewareJwtConverter() {
        JwtGrantedAuthoritiesConverter authoritiesConverter = new JwtGrantedAuthoritiesConverter();
        authoritiesConverter.setAuthoritiesClaimName("authorities");
        authoritiesConverter.setAuthorityPrefix("");

        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(authoritiesConverter);
        return converter;
    }

}
