.PHONY: setup run test lint init clean help

# Default target
help: ## Show this help
	@echo "Security Agent – Makefile targets"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Quick start:"
	@echo "  make setup"
	@echo "  make run TARGET=https://example.com"

setup: ## Install dependencies and Playwright browsers
	pip install -e ".[dev]"
	playwright install chromium
	@echo ""
	@echo "✅ Setup complete! Next steps:"
	@echo "  make init TARGET=https://example.com   # generate config"
	@echo "  make run TARGET=https://example.com     # start agent"

init: ## Generate starter config (use TARGET=https://...)
	security-agent init $(if $(TARGET),--target $(TARGET),)
	@echo ""
	@echo "Edit agent_config.json to add session tokens, then: make run"

run: ## Run the agent (use TARGET=https://... or config file)
ifdef TARGET
	security-agent run --target $(TARGET) $(EXTRA_ARGS)
else
	security-agent run $(EXTRA_ARGS)
endif

test: ## Run tests
	python -m pytest tests/ -v

lint: ## Run linting (if configured)
	@echo "No linter configured. Add ruff or mypy to pyproject.toml if needed."

validate: ## Validate the config file
	security-agent validate

clean: ## Remove state, reports, and caches
	rm -rf agent_state/ reports/ .pytest_cache/ __pycache__/
	find . -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	@echo "✅ Cleaned"

docker-build: ## Build the Docker image
	docker build -t security-agent .

docker-run: ## Run in Docker (use TARGET=https://... BURP_HOST=host.docker.internal)
	docker run --rm -it \
		-e TARGET_URL=$(TARGET) \
		-e BURP_MCP_HOST=$(or $(BURP_HOST),host.docker.internal) \
		-v $$(pwd)/reports:/app/reports \
		-v $$(pwd)/agent_state:/app/agent_state \
		security-agent
