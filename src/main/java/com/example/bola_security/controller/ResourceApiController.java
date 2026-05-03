package com.example.bola_security.controller;

import com.example.bola_security.dto.ResourceAccessResponse;
import com.example.bola_security.dto.ResourceCreateRequest;
import com.example.bola_security.dto.ResourceResponse;
import com.example.bola_security.model.Resource;
import com.example.bola_security.service.ResourceAccessService;
import com.example.bola_security.repository.ResourceRepository;
import com.example.bola_security.exception.ResourceNotFoundException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;

/**
 * Resource API controller with centralized authorization.
 * All access control decisions are now handled by the centralized authorization system.
 */
@RestController
@RequestMapping("/api/v1/resources")
public class ResourceApiController {

    private final ResourceAccessService resourceAccessService;
    private final ResourceRepository resourceRepository;

    public ResourceApiController(ResourceAccessService resourceAccessService, 
                                ResourceRepository resourceRepository) {
        this.resourceAccessService = resourceAccessService;
        this.resourceRepository = resourceRepository;
    }

    /**
     * Access a specific resource with centralized authorization.
     * Uses @PreAuthorize to enforce access control before method execution.
     */
    @GetMapping("/{id}")
    @PreAuthorize("hasPermission(#id, 'Resource', 'READ')")
    public ResourceAccessResponse access(@PathVariable Long id, HttpServletRequest request) {
        return resourceAccessService.access(id, request);
    }

    /**
     * Get current user's resources - no authorization check needed as it's filtered by owner.
     */
    @GetMapping("/mine")
    public Page<ResourceResponse> mine(Pageable pageable) {
        return resourceAccessService.myResources(pageable);
    }

    /**
     * Create a new resource - ownership is automatically assigned to current user.
     */
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ResourceResponse create(@Valid @RequestBody ResourceCreateRequest request) {
        return resourceAccessService.create(request);
    }

    /**
     * Update a resource with centralized authorization.
     * Demonstrates object-level permission check.
     */
    @PutMapping("/{id}")
    @PreAuthorize("hasPermission(#id, 'Resource', 'WRITE')")
    public ResourceResponse update(@PathVariable Long id, 
                                 @Valid @RequestBody ResourceCreateRequest request,
                                 Authentication authentication) {
        Resource resource = resourceRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException(id));
        
        // Update logic here
        resource.setName(request.name());
        resource.setDepartment(request.department());
        resource.setDescription(request.description());
        
        Resource saved = resourceRepository.save(resource);
        return ResourceResponse.from(saved);
    }

    /**
     * Delete a resource with centralized authorization.
     * Demonstrates DELETE permission check.
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasPermission(#id, 'Resource', 'DELETE')")
    public void delete(@PathVariable Long id) {
        Resource resource = resourceRepository.findById(id)
            .orElseThrow(() -> new ResourceNotFoundException(id));
        
        resourceRepository.delete(resource);
    }
}
