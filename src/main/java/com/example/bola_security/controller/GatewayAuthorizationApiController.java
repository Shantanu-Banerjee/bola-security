package com.example.bola_security.controller;

import com.example.bola_security.dto.GatewayAuthorizationRequest;
import com.example.bola_security.dto.GatewayAuthorizationResponse;
import com.example.bola_security.service.GatewayAuthorizationService;
import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/gateway")
public class GatewayAuthorizationApiController {

    private final GatewayAuthorizationService gatewayAuthorizationService;

    public GatewayAuthorizationApiController(GatewayAuthorizationService gatewayAuthorizationService) {
        this.gatewayAuthorizationService = gatewayAuthorizationService;
    }

    @PostMapping("/authorize")
    public GatewayAuthorizationResponse authorize(@Valid @RequestBody GatewayAuthorizationRequest request) {
        return gatewayAuthorizationService.authorize(request);
    }
}
