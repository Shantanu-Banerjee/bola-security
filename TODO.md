# BOLA Security Production Middleware Implementation Plan

## Progress Tracker
- [x] 1. Create this TODO.md ✅
- [x] 2. Read and analyze SecurityConfig.java (JWT oauth2, existing BolaAuthorizationFilter)
- [x] 3. Deprecate JwtUtil (use SecurityContext/JwtTokenService) ✅
- [x] 4. Refactor BolaDetectionService.java to DB-backed (AuthorizationService + repos) ✅
- [x] 5. Update BolaSecurityFilter.java: Use SecurityContextHolder for user, extract resourceId, validate via service, chain.doFilter on success, log/throw on fail ✅
- [x] 6. Update FilterConfig.java to proper order/paths (order 3 after auth) ✅
- [x] 7. Deprecate/remove RequestForwardingService.java (no proxy needed) ✅
- [x] 8. Add SLF4J logging to filter/service for security events ✅
- [ ] 9. Ensure GlobalExceptionHandler catches BOLA exceptions (already does)
- [ ] 10. Create integration tests
- [ ] 11. Run mvn clean test
- [ ] 12. Run mvn spring-boot:run and test flow: login alice/password123, GET /api/resources/{alice-id} vs other
- [ ] 13. Create blackboxai/bola-prod-ready branch, commit, PR

## Notes
- Core middleware ready: Spring Security JWT auth -> BOLA filter (DB/policy ownership/tenant check) -> controllers.
- Leverages existing PolicyEngine for advanced rules (role/dept).
- Logging, exceptions handled.
- Demo data auto-seeds on start (H2 mem DB).
- Complements existing BolaAuthorizationFilter.

Current step: 9/13
