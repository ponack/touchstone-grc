.PHONY: help build run worker test migrate up down logs lint tidy

help:
	@echo "Touchstone — common targets"
	@echo "  make tidy      — go mod tidy in api/"
	@echo "  make build     — build the api binary"
	@echo "  make run       — run the api locally (requires Postgres + MinIO running)"
	@echo "  make worker    — run the worker locally"
	@echo "  make test      — run unit + integration tests"
	@echo "  make up        — docker compose up -d"
	@echo "  make down      — docker compose down"
	@echo "  make logs      — tail compose logs"

tidy:
	cd api && go mod tidy

build:
	cd api && go build -o bin/touchstone ./cmd/touchstone

run:
	cd api && go run ./cmd/touchstone serve

worker:
	cd api && go run ./cmd/touchstone worker

test:
	cd api && go test ./...

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=200
