#!/bin/bash

# IMPORTANT: This script is designed to be executed from the 'iris-dev' root directory.
# To run: ./scripts/setup_environment.sh

# Exit on error
set -e

echo "Starting setup process..."

# Check if conda is installed
if ! command -v conda &> /dev/null; then
    echo "Error: conda is not installed. Please install conda first."
    exit 1
fi

# Create conda environment from environment.yml
echo "Creating conda environment 'iris' from environment.yml..."
if [ ! -f "environment.yml" ]; then
    echo "Error: environment.yml not found in current directory"
    exit 1
fi

# Remove existing environment if it exists
conda env remove -n iris 2>/dev/null || true

# Create new environment
conda env create -f environment.yml

# Create necessary directories
echo "Creating directories..."
PROJECT_ROOT=$(pwd)
CODEQL_DIR="$PROJECT_ROOT/codeql"
mkdir -p "$CODEQL_DIR"
mkdir -p "$PROJECT_ROOT/data/codeql-dbs"

echo "Downloading patched CodeQL..."
CODEQL_URL="https://github.com/iris-sast/iris/releases/download/codeql-0.8.3-patched/codeql.zip"
CODEQL_ZIP="codeql.zip"
if ! curl -L -o "$CODEQL_ZIP" "$CODEQL_URL"; then
    echo "Error: Failed to download CodeQL"
    exit 1
fi

echo "Extracting CodeQL..."
TEMP_DIR="$PROJECT_ROOT/temp_codeql_extract"
mkdir -p "$TEMP_DIR"

if ! unzip -qo "$CODEQL_ZIP" -d "$TEMP_DIR"; then
    echo "Error: Failed to extract CodeQL"
    rm -f "$CODEQL_ZIP"
    rm -rf "$TEMP_DIR"
    exit 1
fi

mv "$TEMP_DIR/codeql"/* "$CODEQL_DIR"
rm -rf "$TEMP_DIR"
rm -f "$CODEQL_ZIP"

echo "export PATH=\"$CODEQL_DIR:$PATH\"" >> ~/.bashrc
export PATH="$CODEQL_DIR:$PATH"

echo "Setup completed successfully!"
echo "- Conda environment 'iris' has been created"
echo "- CodeQL has been downloaded and extracted to $CODEQL_DIR"
echo "- Created '$PROJECT_ROOT/data/codeql-dbs' directory"
echo "- Added CodeQL to PATH in ~/.bashrc"
echo ""
echo "To activate the environment, run: conda activate iris"
echo "You may need to restart your terminal or run 'source ~/.bashrc' for PATH changes to take effect"
