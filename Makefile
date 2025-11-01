SHELL := /bin/bash

.PHONY: help
help:
	@echo "make gen-keys     # generate Ed25519 keys and print base64"
	@echo "make compose-up   # build and start local stack"
	@echo "make compose-down # stop local stack"
	@echo "make migrate      # apply db migrations (inside a temp container)"

gen-keys-macos:
	@OPENSSL="$$(brew --prefix openssl@3)/bin/openssl"; \
	$$OPENSSL genpkey -algorithm Ed25519 -out ed25519.key.pem; \
	$$OPENSSL pkey -in ed25519.key.pem -pubout -out ed25519.pub.pem; \
	$$OPENSSL pkcs8 -topk8 -nocrypt -in ed25519.key.pem -outform DER | base64 > private.key.b64; \
	$$OPENSSL pkey -in ed25519.key.pem -pubout -outform DER | base64 > public.key.b64; \
	echo "Wrote private.key.b64 and public.key.b64"

gen-keys:
	@openssl genpkey -algorithm ed25519 -out ed25519.key
	@openssl pkey -in ed25519.key -pubout -out ed25519.pub
	@echo "---- PRIVATE (base64 PKCS8) ----"
	@base64 -i ed25519.key
	@echo "---- PUBLIC (base64 SPKI) ----"
	@base64 -i ed25519.pub

compose-up:
	cd deploy/local && docker compose up --build -d

compose-down:
	cd deploy/local && docker compose down -v

migrate:
	# Try to detect the compose network (fallback to doxly_default)
	@NET=$$(docker network ls --format '{{.Name}}' | grep -E '(^|_)doxly(_|$$)' | head -n1); \
	if [ -z "$$NET" ]; then NET=doxly_default; fi; \
	docker run --rm \
	  -v "$$PWD/db/migrations:/migrations" \
	  --network $$NET \
	  migrate/migrate:latest \
	  -path=/migrations \
	  -database 'postgres://postgres:postgres@postgres:5432/doxly?sslmode=disable' \
	  up
