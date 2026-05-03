package com.example.bola_security.controller;

import com.example.bola_security.dto.AttackSimulationRequest;
import com.example.bola_security.dto.AttackSimulationResponse;
import com.example.bola_security.service.AttackSimulationService;
import jakarta.validation.Valid;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/security/simulations")
public class AttackSimulationApiController {

    private final AttackSimulationService attackSimulationService;

    public AttackSimulationApiController(AttackSimulationService attackSimulationService) {
        this.attackSimulationService = attackSimulationService;
    }

    @PostMapping("/attacks")
    @PreAuthorize("hasRole('ADMIN')")
    public AttackSimulationResponse simulate(@Valid @RequestBody AttackSimulationRequest request) {
        return attackSimulationService.simulate(request);
    }
}
