.PHONY: build install clean test fmt clippy docker-build docker-run help

help:
	@echo "Available targets:"
	@echo "  build         - Build all components"
	@echo "  install       - Install to system (requires root)"
	@echo "  clean         - Clean build artifacts"
	@echo "  test          - Run tests"
	@echo "  fmt           - Format code"
	@echo "  clippy        - Run clippy linter"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  help          - Show this help"

build:
	@echo "Building secrds Security Monitor..."
	@chmod +x build.sh
	@./build.sh

install:
	@echo "Installing secrds Security Monitor..."
	@sudo chmod +x install.sh
	@sudo ./install.sh

clean:
	@echo "Cleaning build artifacts..."
	@cd secrds-programs && make clean || true
	@rm -rf target/release/secrds-*

test:
	@echo "Running tests..."
	@cargo test

fmt:
	@echo "Formatting code..."
	@cargo fmt

clippy:
	@echo "Running clippy..."
	@cargo clippy -- -D warnings

docker-build:
	@echo "Building Docker image..."
	@docker build -t secrds:latest .

docker-run:
	@echo "Running Docker container..."
	@docker-compose up -d

