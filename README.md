# BOLA Defense System

Deployable Spring Boot application that demonstrates Broken Object Level Authorization defense with JWT-authenticated users, automatic API-level object checks, centralized authorization policy, multi-tenant isolation, alerting, Prometheus metrics, and a small web UI.

## Security Model

- Users authenticate through Spring Security with BCrypt-hashed passwords, short-lived JWT access tokens, and rotating refresh tokens.
- Every protected API request passes through a global `OncePerRequestFilter` before it reaches the controller.
- Each access decision is enriched with contextual parameters:
  - user ID, username, role, and department
  - resource ID, owner ID, and department
  - owner match and department match flags
  - client IP address
  - user agent
  - session ID
  - HTTP method and request path
  - access timestamp and access hour
  - recent distinct resource access count
  - sequential resource probing run length
  - calculated risk score
- Access policy is centralized and configuration-driven:
  - `USER` defaults to `OWN`
  - `MANAGER` defaults to `SAME_DEPARTMENT`
  - `ADMIN` defaults to `ANY`
- Tenant boundaries are enforced before role or ownership policy decisions.
- Repeated access to many distinct resource IDs within a short window is blocked as likely ID enumeration.
- Sequential probing such as `/resources/101 -> /resources/102 -> /resources/103` is blocked as suspicious behavior.
- Optional business-hour enforcement can block access outside configured hours.
- Requests missing a user agent can be blocked to reduce scripted abuse.
- All allowed and blocked decisions are written to `access_logs`.
- Denied BOLA attempts create records in `security_incidents`.
- High-severity and tenant-boundary incidents raise `security_alerts` for operator review.
- Repeated suspicious attempts increment a user-level counter and can lock the account.
- Access policy decisions can be cached, and rate limiting plus behavioral tracking can use Redis when enabled.
- JSON structured logs include request and decision context for downstream log aggregation.
- API documentation is available at `/swagger-ui.html`.
- Database schema is versioned through Flyway migrations.
- Prometheus metrics are exposed at `/actuator/prometheus`.

## Run Locally

Create a MySQL database named `bola_db`, then run:

```powershell
mvn "-Dmaven.repo.local=target\.m2" spring-boot:run
```

Useful environment variables:

```text
DB_URL=jdbc:mysql://localhost:3306/bola_db
DB_USERNAME=bola_app
DB_PASSWORD=strong-password
DDL_AUTO=validate
JWT_SECRET=replace-with-at-least-32-random-bytes-for-hs256
JWT_ISSUER=bola-security
BOLA_SCOPE_USER=OWN
BOLA_SCOPE_MANAGER=SAME_DEPARTMENT
BOLA_SCOPE_ADMIN=ANY
BOLA_GATEWAY_API_KEY=replace-with-gateway-shared-secret
BOLA_ALERT_SEVERITY_THRESHOLD=HIGH
BOLA_ENUMERATION_THRESHOLD=5
BOLA_ENUMERATION_WINDOW_SECONDS=10
BOLA_SEQUENTIAL_ACCESS_THRESHOLD=3
BOLA_SEED_DEMO_DATA=true
BOLA_BUSINESS_HOURS_ONLY=false
BOLA_BUSINESS_HOUR_START=9
BOLA_BUSINESS_HOUR_END=18
BOLA_BLOCK_MISSING_USER_AGENT=true
BOLA_HIGH_RISK_THRESHOLD=80
BOLA_ACCOUNT_LOCK_THRESHOLD=5
```

## Run With Docker

Copy `.env.example` to `.env`, change the passwords, then run:

```powershell
docker compose up --build
```

The app will be available at `http://localhost:8080`, Prometheus at `http://localhost:9090`, and Grafana at `http://localhost:3000`.

When `BOLA_SEED_DEMO_DATA=true`, demo accounts are created:

```text
alice / password123  -> user ID 1, role USER
bob / password123    -> user ID 2, role USER
carol / password123  -> user ID 3, role MANAGER
admin / password123  -> user ID 4, role ADMIN
```

Do not enable demo data in production.

## College Demo: Working Middleware Prototype

This simple path demonstrates real request interception instead of only simulating BOLA detection:

```text
Client -> JWT authentication -> BolaMiddlewareFilter -> GET /api/user/{id}
```

Start the app:

```bash
sh mvnw spring-boot:run
```

Login as Alice and save the access token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/middleware/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"password123"}' \
  | jq -r '.accessToken')
```

Valid request, Alice accessing her own profile:

```bash
curl -i http://localhost:8080/api/user/1 \
  -H "Authorization: Bearer $TOKEN"
```

Expected result: `200 OK` with Alice's mocked profile.

BOLA attack, Alice trying to access Bob's profile:

```bash
curl -i http://localhost:8080/api/user/2 \
  -H "Authorization: Bearer $TOKEN"
```

Expected result: `403 Forbidden` with JSON containing `"message":"BOLA Attack Detected"`.

Rate limit demo:

```bash
for i in 1 2 3 4 5 6; do
  curl -s -o /dev/null -w "%{http_code}\n" http://localhost:8080/api/user/1 \
    -H "Authorization: Bearer $TOKEN"
done
```

Expected result: the sixth request returns `429`.

Open the monitoring dashboard at `http://localhost:8080/api/v1/middleware/dashboard/view`, JSON dashboard at `/api/v1/middleware/dashboard`, and Swagger UI at `http://localhost:8080/swagger-ui.html`.

## Web Routes

- `GET /login` - login page
- `GET /dashboard` - resource access UI
- `POST /resource/access` - server-side BOLA checked resource access
- `GET /logs` - latest audit logs, admin only
- `GET /swagger-ui.html` - OpenAPI documentation UI

## REST Routes

- `POST /api/v1/auth/login` - exchange username/password for JWT + refresh token
- `POST /api/v1/auth/refresh` - rotate refresh token and issue a new access token
- `POST /api/v1/auth/logout` - revoke a refresh token
- `POST /api/v1/middleware/login` - demo login endpoint that returns a JWT with a `uid` claim
- `GET /api/user/{id}` - mocked backend user profile API protected by the BOLA middleware
- `GET /api/v1/middleware/dashboard` - JSON middleware monitoring dashboard
- `GET /api/v1/middleware/dashboard/view` - browser dashboard with request and attack counters
- `GET /api/v1/resources/{id}` - access one resource after automatic BOLA checks in the filter
- `GET /api/v1/resources/mine` - list resources owned by the current user
- `POST /api/v1/resources` - create a resource owned by the current user
- `GET /api/v1/security/incidents` - latest security incidents, admin only
- `GET /api/v1/security/alerts` - raised security alerts, admin only
- `POST /api/v1/security/simulations/attacks` - run attack simulations through the live authorization engine, admin only
- `POST /api/v1/gateway/authorize` - gateway-facing authorization decision endpoint secured by JWT plus `X-Gateway-Api-Key`

## Operational Notes

- Application configuration now lives in [`src/main/resources/application.yml`](src/main/resources/application.yml).
- Monitoring stack configuration lives in [`ops/prometheus/prometheus.yml`](ops/prometheus/prometheus.yml) and [`ops/grafana/provisioning/datasources/prometheus.yml`](ops/grafana/provisioning/datasources/prometheus.yml).
- The embedded BOLA middleware flow is `Client -> Security Filter Chain -> BOLA Authorization Filter -> Controller`.
- The external gateway flow is `Gateway -> /api/v1/gateway/authorize -> Central Authorization Engine -> allow/deny decision`.
- A future gateway or standalone authorization-service split is outlined in [`docs/gateway-integration.md`](docs/gateway-integration.md).
- Deployment notes for AWS/Render-style hosting live in [`docs/deployment.md`](docs/deployment.md).

## Tests

```powershell
mvn "-Dmaven.repo.local=target\.m2" test
```
