# Gateway and Service Split

This repo now enforces BOLA checks inside a global Spring Security filter, which makes it behave like embedded middleware for the application itself.

It also now exposes a gateway-facing authorization endpoint at `/api/v1/gateway/authorize`. The intended contract is:

1. Gateway authenticates the caller's bearer token.
2. Gateway forwards the user token plus `X-Gateway-Api-Key`.
3. This service returns an allow or deny decision payload.

If you want to evolve it into a standalone authorization service, the clean next split is:

1. Keep JWT validation at the edge or gateway.
2. Forward a trusted identity context to a dedicated `/authorize` API.
3. Move resource metadata lookup and policy evaluation into that service.
4. Let application backends call the service before serving object-level data.

For Spring Cloud Gateway, the recommended shape is:

1. Gateway validates the bearer token.
2. Gateway filter extracts `userId`, `role`, `path`, `method`, and target `resourceId`.
3. Gateway calls the BOLA authorization service.
4. Gateway forwards only approved requests to downstream services.

The current code already provides the pieces needed for that split:

- Global route interception in [`BolaAuthorizationFilter`](../src/main/java/com/example/bola_security/security/BolaAuthorizationFilter.java)
- Config-driven role policy in [`AccessPolicyEngine`](../src/main/java/com/example/bola_security/service/AccessPolicyEngine.java)
- Behavioral tracking in [`BehavioralAnalysisService`](../src/main/java/com/example/bola_security/service/BehavioralAnalysisService.java)
- JWT auth and refresh flow in [`AuthApiController`](../src/main/java/com/example/bola_security/controller/AuthApiController.java)
