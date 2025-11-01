SHELL := /bin/bash

.PHONY: help
help:
	@echo "make gen-keys     # generate Ed25519 keys and print base64"
	@echo "make compose-up   # build and start local stack"
	@echo "make compose-down # stop local stack"
	@echo "make migrate      # apply db migrations (inside a temp container)"

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
	docker run --rm -v $$PWD/db/migrations:/migrations --network=host \
	  ghcr.io/golang-migrate/migrate:latest \
	  -path=/migrations -database 'postgres://postgres:postgres@localhost:5432/doxly?sslmode=disable' up
