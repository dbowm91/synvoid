#!/bin/bash
#
# Build script for creating a dynamic Axum plugin (.so/.dylib)
#
# This builds your Axum app as a shared library that can be loaded
# by RustWAF at runtime using libloading.
#
# Usage:
#   ./build-plugin.sh           # Build release plugin
#   ./build-plugin.sh debug    # Build debug plugin
#

set -e

MODE="${1:-release}"

echo "Building dynamic Axum plugin..."

# Build as shared library
RUSTFLAGS="-C link-args=-shared" cargo build --$MODE

PLUGIN_NAME="libmyapp.so"
if [ -f "target/$MODE/libmyapp.so" ]; then
    echo "Plugin built successfully: target/$MODE/$PLUGIN_NAME"
    echo ""
    echo "To use with RustWAF, add to your site config:"
    echo ""
    echo '  [site.backend]'
    echo '  type = "axum-dynamic"'
    echo '  plugin = "target/$MODE/$PLUGIN_NAME"'
    echo '  socket = "/run/rustwaf/app.sock"'
else
    echo "Build failed - check errors above"
    exit 1
fi
