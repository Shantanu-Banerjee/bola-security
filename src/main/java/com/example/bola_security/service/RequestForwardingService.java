package com.example.bola_security.service;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

/**
 * DEPRECATED: Proxy forwarding removed for standard middleware architecture.
 * Validated requests now continue through filter chain to application controllers.
 */
@Deprecated
@Service
public class RequestForwardingService {

    // No proxying needed
}
