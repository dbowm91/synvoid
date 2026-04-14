#!/bin/bash
#
# Build script for creating a custom RustWAF binary with embedded Axum app
#
# Usage:
#   ./build.sh                    # Build release binary
#   ./build.sh debug              # Build debug binary
#   ./build.sh clean              # Clean and build
#
# This script creates a combined binary with both the WAF and your app.
# The app is compiled directly into the binary for maximum performance.

set -e

MODE="${1:-release}"

APP_NAME="my-waf-app"
APP_CRATE="myapp"

echo "Building $APP_NAME with embedded Axum app..."

if [ "$1" = "clean" ]; then
    echo "Cleaning build artifacts..."
    rm -rf target/
    rm -rf "$APP_NAME"
fi

echo "Building in $MODE mode..."

# Build the combined binary
# This expects your app to be in ./myapp/ with a Cargo.toml
cargo build --$MODE \
    --package rustwaf \
    --features axum-embedded

echo ""
echo "Build complete!"
echo "Binary: target/$MODE/rustwaf"
echo ""
echo "To run:"
echo "  ./target/$MODE/rustwaf --config config/main.toml"
