#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WEBSITE_DIR="$SCRIPT_DIR/website"

echo "Building SynVoid Website..."

# Build frontend with trunk
echo "Building frontend (trunk)"
cd "$WEBSITE_DIR"
trunk build

# Copy fonts and styles to dist
echo "Copying static assets"
mkdir -p dist/fonts
cp src/fonts/* dist/fonts/
cp src/styles.css dist/
cp src/challenge.html dist/
cp src/challenge.css dist/
cp src/test.html dist/
cp src/test.css dist/

# Build server binary
echo "Building server binary"
cargo build --features server --release -p website

# Copy release binary to website directory (so it can find dist/ relative to its location)
cp "$SCRIPT_DIR/target/release/website-server" "$WEBSITE_DIR/website-server"

echo ""
echo "Build complete"
echo "Run with: $WEBSITE_DIR/website-server"
echo "Server will be available at http://localhost:5999"
