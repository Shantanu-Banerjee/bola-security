package com.example.bola_security.service;

import com.example.bola_security.exception.BolaAccessDeniedException;
import com.example.bola_security.model.Resource;
import com.example.bola_security.model.Role;
import com.example.bola_security.model.User;
import com.example.bola_security.repository.ResourceRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.time.LocalDateTime;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ResourceAccessServiceTest {

    @Mock private ResourceRepository resourceRepository;
    @Mock private ResourceAuthorizationEngine resourceAuthorizationEngine;
    @Mock private AuthenticatedUserService authenticatedUserService;
    @Mock private RequestContextService requestContextService;
    @Mock private HttpServletRequest httpRequest;

    private ResourceAccessService service;
    private User alice;
    private Resource aliceResource;
    private RequestContext requestContext;

    @BeforeEach
    void setUp() {
        service = new ResourceAccessService(
                resourceRepository,
                resourceAuthorizationEngine,
                authenticatedUserService,
                requestContextService
        );

        alice = new User();
        alice.setId(1L);
        alice.setUsername("alice");
        alice.setRole(Role.USER);
        alice.setTenantId("tenant-alpha");
        alice.setDepartment("Engineering");

        aliceResource = new Resource();
        aliceResource.setId(10L);
        aliceResource.setName("Payroll");
        aliceResource.setOwnerId(1L);
        aliceResource.setTenantId("tenant-alpha");
        aliceResource.setDepartment("Engineering");

        requestContext = new RequestContext("127.0.0.1", "JUnit", "session", "GET", "/api/resources/10", LocalDateTime.now());
        when(authenticatedUserService.currentUser()).thenReturn(alice);
        lenient().when(requestContextService.extract(httpRequest)).thenReturn(requestContext);
    }

    @Test
    void returnsAuthorizedResourceResponse() {
        AccessContext accessContext = AccessContext.from(alice, aliceResource, requestContext, 0);
        when(resourceAuthorizationEngine.authorize(eq(alice), eq(10L), eq(requestContext)))
                .thenReturn(new AuthorizationOutcome(alice, aliceResource, accessContext, new AccessDecision(true, "OWNER_MATCH")));

        var response = service.access(10L, httpRequest);

        assertThat(response.allowed()).isTrue();
        assertThat(response.reason()).isEqualTo("OWNER_MATCH");
        assertThat(response.resource().tenantId()).isEqualTo("tenant-alpha");
    }

    @Test
    void propagatesAuthorizationFailures() {
        when(resourceAuthorizationEngine.authorize(eq(alice), eq(10L), eq(requestContext)))
                .thenThrow(new BolaAccessDeniedException("TENANT_BOUNDARY_VIOLATION"));

        assertThatThrownBy(() -> service.access(10L, httpRequest))
                .isInstanceOf(BolaAccessDeniedException.class)
                .hasMessage("TENANT_BOUNDARY_VIOLATION");
    }

    @Test
    void myResourcesScopesByTenant() {
        when(resourceRepository.findByOwnerIdAndTenantId(1L, "tenant-alpha", PageRequest.of(0, 20)))
                .thenReturn(new PageImpl<>(List.of(aliceResource)));

        var response = service.myResources(PageRequest.of(0, 20));

        assertThat(response.getContent()).hasSize(1);
        assertThat(response.getContent().get(0).tenantId()).isEqualTo("tenant-alpha");
    }

    @Test
    void createAssignsCurrentTenantToResource() {
        when(resourceRepository.save(any(Resource.class))).thenAnswer(invocation -> invocation.getArgument(0));

        service.create(new com.example.bola_security.dto.ResourceCreateRequest("New resource", "Engineering", "desc"));

        ArgumentCaptor<Resource> captor = ArgumentCaptor.forClass(Resource.class);
        verify(resourceRepository).save(captor.capture());
        assertThat(captor.getValue().getTenantId()).isEqualTo("tenant-alpha");
    }
}
