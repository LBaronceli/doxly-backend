# Doxly Backend (Monorepo)

Go services + local Docker Compose for a multi-tenant SaaS sample:

- auth-service (JWT, JWKS)
- customer-api (CRUD)
- attachments-service (presigned S3)

## Quickstart

1. Generate Ed25519 keys

cmd: make gen-keys

Copy the base64 outputs into:
a)deploy/local/env/auth.env
b)deploy/local/env/customer.env
c)deploy/local/env/attachments.env

2. Start local stack

`bash make compose-up`

3. Apply migrations (one time)

`bash make migrate`

Endpoints (health/metrics)

Auth: http://localhost:8081/healthz
| http://localhost:8081/.well-known/jwks.json

Customer: http://localhost:8082/healthz

Attachments: http://localhost:8083/healthz

MinIO console: http://localhost:9001
