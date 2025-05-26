.PHONY: help install install-dev clean test lint format type-check \
        certs keys setup-dev start validate 

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := pip3
PORT := 8443
HOST := 0.0.0.0
CONFIG := config.yaml
TLS_CERT := certs/server.crt
TLS_KEY := certs/server.key
JWT_PUBLIC_KEY := keys/public_key.pem
JWT_PRIVATE_KEY := keys/private_key.pem

# Colors for output - ensure proper escaping
RED := \033[0;31m
GREEN := \033[0;32m
YELLOW := \033[1;33m
BLUE := \033[0;34m
NC := \033[0m

# Installation and Setup
install: ## Install production dependencies
	@echo -e "$(GREEN)Installing production dependencies...$(NC)"
	$(PIP) install -r requirements.txt

install-dev: ## Install development dependencies
	@echo -e "$(GREEN)Installing development dependencies...$(NC)"
	$(PIP) install -r requirements.txt
	$(PIP) install pytest pytest-cov pytest-asyncio black flake8 mypy

setup-dev: install-dev certs keys ## Complete development environment setup
	@echo -e "$(GREEN)Development environment setup complete!$(NC)"
	@echo -e "$(YELLOW)You can now start the proxy with: make start$(NC)"

# Certificate and Key Generation
certs: ## Generate TLS certificates for development
	@echo -e "$(GREEN)Generating TLS certificates...$(NC)"
	@chmod +x utils/generate_tls_certs.sh
	./utils/generate_tls_certs.sh

keys: ## Generate JWT keys for development
	@echo -e "$(GREEN)Generating JWT keys...$(NC)"
	@chmod +x utils/generate_jwt_keys.sh
	./utils/generate_jwt_keys.sh

certs-and-keys: certs keys ## Generate both TLS certificates and JWT keys
	@echo -e "$(GREEN)Setup of all certificates and keys complete!$(NC)"

# Development Server
start: validate ## Start proxy server with TLS
	@echo -e "$(GREEN)Starting muza-proxy server (HTTPS)...$(NC)"
	$(PYTHON) muza-proxy.py \
		--config $(CONFIG) \
		--host $(HOST) \
		--port $(PORT) \
		--tls-cert $(TLS_CERT) \
		--tls-key $(TLS_KEY) \
		--jwt-public-key $(JWT_PUBLIC_KEY) \
		--jwt-private-key $(JWT_PRIVATE_KEY)

validate: ## Validate configuration without starting server
	@echo -e "$(GREEN)Validating configuration...$(NC)"
	$(PYTHON) muza-proxy.py --config $(CONFIG) --validate-only

# Testing and Quality Assurance
test: ## Run tests
	@echo -e "$(GREEN)Running tests...$(NC)"
	$(PYTHON) -m pytest tests/ -v --cov=src --cov-report=term-missing

test-verbose: ## Run tests with verbose output
	@echo -e "$(GREEN)Running tests (verbose)...$(NC)"
	$(PYTHON) -m pytest tests/ -vv --cov=src --cov-report=html

lint: ## Run linting checks
	@echo -e "$(GREEN)Running linting checks...$(NC)"
	$(PYTHON) -m flake8 src/ utils/ muza-proxy.py --max-line-length=120

format: ## Format code with black
	@echo -e "$(GREEN)Formatting code...$(NC)"
	$(PYTHON) -m black src/ utils/ muza-proxy.py --line-length=120

format-check: ## Check code formatting without making changes
	@echo -e "$(GREEN)Checking code formatting...$(NC)"
	$(PYTHON) -m black src/ utils/ muza-proxy.py --line-length=120 --check

type-check: ## Run type checking with mypy
	@echo -e "$(GREEN)Running type checks...$(NC)"
	$(PYTHON) -m mypy src/ --ignore-missing-imports

quality: lint format-check type-check ## Run all quality checks

# Token utilities
generate-token: ## Generate a test JWT token (usage: make generate-token USER=user123 AUD=user)
	@if [ -z "$(USER)" ]; then \
		echo -e "$(RED)Error: USER variable is required$(NC)"; \
		echo -e "$(YELLOW)Usage: make generate-token USER=user123 [AUD=user] [EXPIRES=24]$(NC)"; \
		exit 1; \
	fi
	@echo -e "$(GREEN)Generating JWT token for user: $(USER)$(NC)"
	$(PYTHON) utils/sign.py $(JWT_PRIVATE_KEY) $(USER) \
		$(if $(AUD),--audience $(AUD)) \
		$(if $(EXPIRES),--expires $(EXPIRES)) \
		--verbose

verify-token: ## Verify a JWT token (usage: make verify-token TOKEN="...")
	@if [ -z "$(TOKEN)" ]; then \
		echo -e "$(RED)Error: TOKEN variable is required$(NC)"; \
		echo -e "$(YELLOW)Usage: make verify-token TOKEN=\"eyJhbGciOi...\"$(NC)"; \
		exit 1; \
	fi
	@echo -e "$(GREEN)Verifying JWT token...$(NC)"
	$(PYTHON) utils/verify.py "$(TOKEN)" $(JWT_PUBLIC_KEY)

# Cleanup
clean: ## Clean temporary files and directories
	@echo -e "$(GREEN)Cleaning temporary files...$(NC)"
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ .coverage htmlcov/ .pytest_cache/ .mypy_cache/

clean-certs: ## Remove generated certificates and keys
	@echo -e "$(YELLOW)Removing certificates and keys...$(NC)"
	rm -rf certs/ keys/

clean-all: clean clean-certs ## Clean everything including certificates

# Help target
help: ## Show this help message
	@echo -e "$(BLUE)Muza-Proxy Development Commands$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "$(GREEN)%-20s$(NC) %s\n", $$1, $$2}' $(MAKEFILE_LIST)
