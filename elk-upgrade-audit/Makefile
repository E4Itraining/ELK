# ELK Upgrade Audit Tool - Makefile
# ==================================
#
# Usage:
#   make build       Build Docker image
#   make run         Run interactive mode
#   make audit       Run pre-upgrade audit
#   make validate    Run post-upgrade validation
#   make shell       Open shell in container
#   make clean       Remove Docker image and containers

.PHONY: help build run audit compat backup validate shell logs clean test

# Default target
.DEFAULT_GOAL := help

# Variables
IMAGE_NAME := elk-upgrade-audit
IMAGE_TAG := latest
CONTAINER_NAME := elk-audit
DOCKER_RUN := docker run -it --rm

# Environment variables (can be overridden)
ES_HOSTS ?= https://localhost:9200
ES_USERNAME ?= elastic
ES_PASSWORD ?=
ES_VERIFY_CERTS ?= false
TARGET_VERSION ?= 8.11.0

# Common docker run options
DOCKER_OPTS := \
	-e ES_HOSTS=$(ES_HOSTS) \
	-e ES_USERNAME=$(ES_USERNAME) \
	-e ES_PASSWORD=$(ES_PASSWORD) \
	-e ES_VERIFY_CERTS=$(ES_VERIFY_CERTS) \
	-e TARGET_VERSION=$(TARGET_VERSION) \
	-v $(PWD)/reports:/app/reports \
	-v $(PWD)/logs:/app/logs

## help: Show this help message
help:
	@echo "╔════════════════════════════════════════════════════════════╗"
	@echo "║          ELK Upgrade Audit Tool - Docker Commands          ║"
	@echo "╚════════════════════════════════════════════════════════════╝"
	@echo ""
	@echo "Usage: make [target] [VAR=value]"
	@echo ""
	@echo "Targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'
	@echo ""
	@echo "Variables:"
	@echo "  ES_HOSTS         Elasticsearch URL (default: https://localhost:9200)"
	@echo "  ES_USERNAME      Elasticsearch username (default: elastic)"
	@echo "  ES_PASSWORD      Elasticsearch password"
	@echo "  ES_VERIFY_CERTS  Verify SSL certs (default: false)"
	@echo "  TARGET_VERSION   Target ES version (default: 8.11.0)"
	@echo ""
	@echo "Examples:"
	@echo "  make build"
	@echo "  make run"
	@echo "  make audit ES_HOSTS=https://my-cluster:9200 ES_PASSWORD=secret"
	@echo "  make validate TARGET_VERSION=8.12.0"

## build: Build Docker image
build:
	@echo "Building Docker image..."
	docker build -t $(IMAGE_NAME):$(IMAGE_TAG) .
	@echo "Done! Image: $(IMAGE_NAME):$(IMAGE_TAG)"

## run: Run in interactive mode
run: ensure-image ensure-dirs
	@echo "Starting interactive mode..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) interactive

## audit: Run pre-upgrade audit
audit: ensure-image ensure-dirs
	@echo "Running pre-upgrade audit..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) audit \
		--target-version $(TARGET_VERSION) \
		--output /app/reports \
		--format html

## compat: Check version compatibility
compat: ensure-image
	@echo "Checking version compatibility..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) compat \
		--target-version $(TARGET_VERSION) \
		--check-indices

## backup: Check backup readiness
backup: ensure-image
	@echo "Checking backup status..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) backup check

## backup-list: List snapshots
backup-list: ensure-image
	@echo "Listing snapshots..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) backup list

## backup-create: Create pre-upgrade snapshot
backup-create: ensure-image
	@echo "Creating pre-upgrade snapshot..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) backup create

## upgrade-plan: Show upgrade plan
upgrade-plan: ensure-image
	@echo "Showing upgrade plan..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) upgrade plan \
		--target-version $(TARGET_VERSION)

## validate: Run post-upgrade validation
validate: ensure-image ensure-dirs
	@echo "Running post-upgrade validation..."
	$(DOCKER_RUN) $(DOCKER_OPTS) $(IMAGE_NAME):$(IMAGE_TAG) validate \
		--output /app/reports \
		--format html

## shell: Open shell in container
shell: ensure-image
	@echo "Opening shell..."
	$(DOCKER_RUN) $(DOCKER_OPTS) --entrypoint /bin/bash $(IMAGE_NAME):$(IMAGE_TAG)

## logs: Show container logs
logs:
	@docker logs $(CONTAINER_NAME) 2>/dev/null || echo "No logs available"

## clean: Remove Docker image and containers
clean:
	@echo "Cleaning up..."
	-docker rm -f $(CONTAINER_NAME) 2>/dev/null
	-docker rmi $(IMAGE_NAME):$(IMAGE_TAG) 2>/dev/null
	@echo "Done!"

## clean-reports: Remove generated reports
clean-reports:
	@echo "Removing reports..."
	rm -rf reports/*.html reports/*.json reports/*.md
	@echo "Done!"

## test-local: Test with local Elasticsearch
test-local: ensure-image
	@echo "Starting local Elasticsearch for testing..."
	docker-compose --profile with-es up -d elasticsearch
	@echo "Waiting for Elasticsearch to start..."
	@sleep 30
	@echo "Running audit against local Elasticsearch..."
	$(DOCKER_RUN) --network elk-audit-network $(DOCKER_OPTS) \
		-e ES_HOSTS=http://elasticsearch:9200 \
		$(IMAGE_NAME):$(IMAGE_TAG) audit --target-version $(TARGET_VERSION)

## stop-local: Stop local Elasticsearch
stop-local:
	docker-compose --profile with-es down

# Internal targets
ensure-image:
	@docker image inspect $(IMAGE_NAME):$(IMAGE_TAG) > /dev/null 2>&1 || $(MAKE) build

ensure-dirs:
	@mkdir -p reports logs
