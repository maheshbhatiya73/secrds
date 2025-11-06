#!/bin/bash
set -e

echo "Building secrds Security Monitor..."

# Build C kernel programs (required for secrds-agent)
echo "Building C kernel programs..."
cd secrds-programs
make
cd ..

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "Error: Go is not installed. Please install Go 1.21 or later."
    echo "Visit: https://golang.org/dl/"
    exit 1
fi

# Build secrds-agent
echo "Building secrds-agent..."
cd secrds-agent
go mod download
go build -o ../target/release/secrds-agent .
cd ..

# Build secrds-cli
echo "Building secrds-cli..."
cd secrds-cli
go mod download
go build -o ../target/release/secrds-cli .
cd ..

echo "Build complete!"
echo ""
echo "Binaries:"
echo "  - Agent: target/release/secrds-agent"
echo "  - CLI: target/release/secrds-cli"

