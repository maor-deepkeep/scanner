# ModelTotal Makefile - Convenient commands for development and testing

.PHONY: help up down test test-all test-quick test-scanner test-coverage test-shell clean logs

# Colors for output
YELLOW := \033[1;33m
GREEN := \033[0;32m
RED := \033[0;31m
NC := \033[0m # No Color

help: ## Show this help message
	@echo "$(GREEN)ModelTotal - Development Commands$(NC)"
	@echo ""
	@echo "$(YELLOW)Available commands:$(NC)"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(GREEN)%-15s$(NC) %s\n", $$1, $$2}'
	@echo ""
	@echo "$(YELLOW)Testing commands:$(NC)"
	@echo "  $(GREEN)make test-scanner name=picklescan$(NC)  # Test specific scanner"
	@echo "  $(GREEN)make test-debug test=test_name$(NC)     # Debug specific test"

# Docker commands
up: ## Start all Docker services
	docker-compose up -d
	@echo "$(GREEN)✓ Services started$(NC)"

down: ## Stop all Docker services
	docker-compose down
	@echo "$(YELLOW)Services stopped$(NC)"

restart: ## Restart all Docker services
	docker-compose restart
	@echo "$(GREEN)✓ Services restarted$(NC)"

build: ## Rebuild Docker images
	docker-compose build
	@echo "$(GREEN)✓ Images rebuilt$(NC)"

logs: ## Show logs from all services
	docker-compose logs -f

logs-api: ## Show logs from API service
	docker-compose logs -f model-total

logs-worker: ## Show logs from worker service
	docker-compose logs -f tasks-worker

# Testing commands
test: test-quick ## Run quick smoke tests (default)

test-all: ## Run all unit tests in Docker
	@./test.sh all

test-quick: ## Run quick smoke tests
	@./test.sh quick

test-scanner: ## Run specific scanner tests (usage: make test-scanner name=picklescan)
	@./test.sh scanner $(name)

test-integration: ## Run integration tests
	@./test.sh integration

test-coverage: ## Run tests with coverage report
	@./test.sh coverage

test-debug: ## Debug specific test (usage: make test-debug test=test_name)
	@./test.sh debug $(test)

test-shell: ## Open interactive shell in test container
	@./test.sh shell

test-file: ## Run specific test file (usage: make test-file path=tests/unit/test_validator.py)
	@./test.sh file $(path)

# Utility commands
clean: ## Clean test results and cache
	@./test.sh clean
	@find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name .pytest_cache -exec rm -rf {} + 2>/dev/null || true
	@echo "$(GREEN)✓ Cleaned test results and cache$(NC)"

shell-api: ## Open shell in API container
	docker exec -it model-total bash

shell-worker: ## Open shell in worker container
	docker exec -it tasks-worker bash

shell-mongo: ## Open MongoDB shell
	docker exec -it mongodb mongosh -u admin -p password123

status: ## Show status of all services
	@echo "$(YELLOW)Service Status:$(NC)"
	@docker-compose ps

# Development shortcuts
dev: up logs-api ## Start services and show API logs

test-watch: ## Run tests in watch mode (reruns on file changes)
	@echo "$(YELLOW)Watching for file changes...$(NC)"
	@while true; do \
		./test.sh all; \
		echo "$(YELLOW)Waiting for changes... (Press Ctrl+C to stop)$(NC)"; \
		fswatch -1 tests/ app/; \
	done

# Installation check
check-deps: ## Check if Docker and docker-compose are installed
	@command -v docker >/dev/null 2>&1 || { echo "$(RED)Docker is not installed$(NC)"; exit 1; }
	@command -v docker-compose >/dev/null 2>&1 || { echo "$(RED)docker-compose is not installed$(NC)"; exit 1; }
	@echo "$(GREEN)✓ All dependencies installed$(NC)"

# Quick test for each scanner
test-picklescan: ## Test picklescan scanner
	@./test.sh scanner picklescan

test-modelscan: ## Test modelscan scanner
	@./test.sh scanner modelscan

test-fickling: ## Test fickling scanner
	@./test.sh scanner fickling

test-trivy: ## Test trivy scanner
	@./test.sh scanner trivy

test-validator: ## Test validator
	@./test.sh file tests/unit/test_validator.py

# Summary of recent test results
test-summary: ## Show summary of recent test results
	@if [ -d "test-results" ]; then \
		echo "$(YELLOW)Recent Test Results:$(NC)"; \
		ls -lt test-results/*.log 2>/dev/null | head -5 | awk '{print "  " $$9}'; \
		echo ""; \
		if [ -f "test-results/$$(ls -t test-results/summary_*.txt 2>/dev/null | head -1 | xargs basename 2>/dev/null)" ]; then \
			echo "$(GREEN)Latest Summary:$(NC)"; \
			cat test-results/$$(ls -t test-results/summary_*.txt | head -1 | xargs basename); \
		fi \
	else \
		echo "$(YELLOW)No test results found. Run 'make test' first.$(NC)"; \
	fi