package com.example.bola_security.controller;

import com.example.bola_security.dto.ResourceAccessResponse;
import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.exception.ResourceNotFoundException;
import com.example.bola_security.service.ResourceAccessService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class ResourceController {

    private final ResourceAccessService resourceAccessService;

    public ResourceController(ResourceAccessService resourceAccessService) {
        this.resourceAccessService = resourceAccessService;
    }

    @PostMapping("/resource/access")
    public String accessResource(@RequestParam Long resourceId, Model model, HttpServletRequest request) {
        try {
            ResourceAccessResponse response = resourceAccessService.access(resourceId, request);
            model.addAttribute("message", "Access granted: " + response.reason());
            model.addAttribute("resource", response.resource());
        } catch (ResourceNotFoundException exception) {
            model.addAttribute("message", "Resource not found");
        } catch (BolaAccessDeniedException exception) {
            model.addAttribute("message", "BOLA access blocked: " + exception.getMessage());
        }
        return "dashboard";
    }
}
