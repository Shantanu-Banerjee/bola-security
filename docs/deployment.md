# Deployment Notes

This project is ready to run as a containerized Spring Boot service with external MySQL and Redis.

## Minimum production components

1. App container
2. MySQL database
3. Redis
4. Reverse proxy or gateway that terminates TLS
5. Prometheus and Grafana, if you want the bundled monitoring stack

## Required environment variables

```text
DB_URL
DB_USERNAME
DB_PASSWORD
JWT_SECRET
JWT_ISSUER
REDIS_HOST
REDIS_PORT
BOLA_REDIS_RATE_LIMITING_ENABLED=true
BOLA_GATEWAY_API_KEY
```

## AWS-friendly shape

1. Push the app image to ECR.
2. Run the app on ECS Fargate or App Runner.
3. Use Amazon RDS for MySQL.
4. Use ElastiCache for Redis.
5. Put the app behind an ALB or API Gateway.
6. Store `JWT_SECRET` and database credentials in Secrets Manager or SSM Parameter Store.

## Render-friendly shape

1. Deploy the app as a Docker web service.
2. Point it at managed MySQL and Redis services.
3. Set all secrets through the Render dashboard.
4. Expose only the app publicly; keep Prometheus and Grafana private unless you explicitly need external access.

## Production hardening checklist

1. Replace demo credentials and disable demo data seeding.
2. Set `DDL_AUTO=validate`.
3. Use a long random `JWT_SECRET`.
4. Restrict `TRUSTED_PROXIES` to your real ingress layer.
5. Enable Redis-backed rate limiting.
6. Scrape `/actuator/prometheus` from your monitoring network only.
