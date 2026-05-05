#!/bin/bash

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
STATIC_DIR="$PROJECT_ROOT/static"
WASM_POW_DIR="$PROJECT_ROOT/src/wasm_pow"
ADMIN_UI_DIR="$PROJECT_ROOT/admin-ui"
DIST_DIR="$ADMIN_UI_DIR/dist"

echo "SynVoid Production Build Script"
echo ""

check_command() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is required but not installed."
        exit 1
    fi
}

echo "Step 1: Checking prerequisites"
check_command "rustc"
check_command "cargo"
check_command "wasm-pack"

if command -v node &> /dev/null; then
    echo "  - node: found"
else
    echo "  - node: not found (admin UI CSS will not be built)"
fi

if command -v trunk &> /dev/null; then
    echo "  - trunk: found"
    BUILD_ADMIN=true
else
    echo "  - trunk: not found (admin UI will not be built)"
    BUILD_ADMIN=false
fi

echo ""
echo "Step 2: Building WASM POW Module"

if [ -d "$WASM_POW_DIR" ]; then
    echo "  Building wasm-pow crate..."
    cd "$WASM_POW_DIR"

    # Clean up any previous build
    rm -rf pkg
    rm -rf target
    rm -f "$STATIC_DIR/pow.wasm"
    rm -f "$STATIC_DIR/mesh_pow.wasm"

    wasm-pack build --target web --out-dir pkg --release

    echo "  Copying WASM files to static directory..."
    mkdir -p "$STATIC_DIR"

    if [ -f "$WASM_POW_DIR/pkg/wasm_pow_bg.wasm" ]; then
        cp "$WASM_POW_DIR/pkg/wasm_pow_bg.wasm" "$STATIC_DIR/pow.wasm"
        echo "  - pow.wasm: copied"
    else
        echo "  Warning: WASM file not found after build"
    fi

    # Copy mesh_pow.wasm (same crate, different output name)
    if [ -f "$WASM_POW_DIR/pkg/wasm_pow_bg.wasm" ]; then
        cp "$WASM_POW_DIR/pkg/wasm_pow_bg.wasm" "$STATIC_DIR/mesh_pow.wasm"
        echo "  - mesh_pow.wasm: copied"
    fi

    # Update the JS to use the correct WASM path and copy to static
    if [ -f "$WASM_POW_DIR/pkg/wasm_pow.js" ]; then
        # Cross-platform sed replacement
        if [[ "$OSTYPE" == "darwin"* ]]; then
            sed -i '' "s|wasm_pow_bg.wasm|pow.wasm|g" "$WASM_POW_DIR/pkg/wasm_pow.js"
        else
            sed -i "s|wasm_pow_bg.wasm|pow.wasm|g" "$WASM_POW_DIR/pkg/wasm_pow.js"
        fi
        cp "$WASM_POW_DIR/pkg/wasm_pow.js" "$STATIC_DIR/pow_wasm.js"
        echo "  - pow_wasm.js: copied"
    fi

    cd "$PROJECT_ROOT"
    echo "  WASM build complete!"
else
    echo "  Warning: wasm-pow directory not found, skipping WASM build"
fi

echo ""
echo "Step 3: Building Admin UI"

if [ "$BUILD_ADMIN" = true ]; then
    if [ -d "$ADMIN_UI_DIR" ]; then
        echo "  Building admin UI with trunk..."
        cd "$ADMIN_UI_DIR"

        if [ -f "package.json" ] && command -v node &> /dev/null; then
            if [ ! -d "node_modules" ]; then
                echo "  Installing npm dependencies..."
                npm install
            fi
            echo "  Building Tailwind CSS..."
            npm run build:css
        fi

        trunk build --release

        if [ -d "$DIST_DIR" ]; then
            echo "  Admin UI built successfully"

            if [ -f "src/styles.css" ]; then
                echo "  Copying CSS and fonts to dist..."
                cp src/styles.css "$DIST_DIR/styles.css"
                mkdir -p "$DIST_DIR/fonts"
                cp src/fonts/*.woff2 "$DIST_DIR/fonts/"
            fi
        else
            echo "  Warning: Admin UI dist directory not found"
        fi
        cd "$PROJECT_ROOT"
    else
        echo "  Warning: admin-ui directory not found, skipping"
    fi
else
    echo "  Skipping admin UI (trunk not installed)"
fi

echo ""
echo "Step 4: Verifying Static Files"

REQUIRED_FILES=(
    "pow.js"
    "pow_fallback.js"
    "pow_nojs.js"
)

OPTIONAL_FILES=(
    "pow.wasm"
    "pow_wasm.js"
    "mesh_pow.js"
    "mesh_pow.wasm"
    "mesh_pow_challenge.js"
)

if [ -d "$STATIC_DIR" ]; then
    echo "  Required files:"
    for file in "${REQUIRED_FILES[@]}"; do
        if [ -f "$STATIC_DIR/$file" ]; then
            echo "    - $file: OK"
        else
            echo "    - $file: MISSING"
        fi
    done

    echo "  Optional files:"
    for file in "${OPTIONAL_FILES[@]}"; do
        if [ -f "$STATIC_DIR/$file" ]; then
            echo "    - $file: OK"
        else
            echo "    - $file: NOT BUILT (fallback will be used)"
        fi
    done
else
    echo "  Warning: static directory not found"
fi

echo ""
echo "Step 5: Building Main Application"

if [ -f "$PROJECT_ROOT/Cargo.toml" ]; then
    echo "  Building synvoid..."

    BUILD_FEATURES=""
    if [ "$1" = "--with-wireguard" ]; then
        BUILD_FEATURES="--features wireguard"
        echo "  (with wireguard support)"
    fi

    cargo build --release $BUILD_FEATURES

    echo "  Main binary built successfully"
else
    echo "  Warning: Cargo.toml not found"
fi

echo ""
echo "Step 6: Generating OpenAPI TypeScript Client"

if command -v npx &> /dev/null; then
    if [ -f "$PROJECT_ROOT/target/release/synvoid" ]; then
        echo "  Generating OpenAPI spec..."
        OPENAPI_JSON="$PROJECT_ROOT/openapi.json"
        "$PROJECT_ROOT/target/release/synvoid" --export-openapi > "$OPENAPI_JSON"

        if [ -f "$OPENAPI_JSON" ]; then
            echo "  Generating TypeScript client..."
            mkdir -p "$ADMIN_UI_DIR/src/api"
            npx --yes @openapitools/openapi-generator-cli generate \
                -i "$OPENAPI_JSON" \
                -g typescript-fetch \
                -o "$ADMIN_UI_DIR/src/api/generated" \
                --additional-properties=modelPropertyNaming=camelCase \
                --additional-properties=typescriptVersion=5.0 \
                --skip-validate 2>/dev/null || echo "  Warning: TypeScript generation failed (may need openapi-generator installed)"

            if [ -d "$ADMIN_UI_DIR/src/api/generated" ]; then
                echo "  TypeScript client generated successfully"
            fi
        else
            echo "  Warning: Failed to generate OpenAPI spec"
        fi
    else
        echo "  Skipping (main binary not built)"
    fi
else
    echo "  Skipping (npx not available)"
fi

echo ""
echo "Build Complete"
echo ""
echo "Output files:"
echo "  - Main binary: target/release/synvoid"
echo "  - Static files: static/"
echo "  - OpenAPI spec: openapi.json"
if [ -d "$DIST_DIR" ]; then
    echo "  - Admin UI: admin-ui/dist/"
fi
echo ""
echo "To run: ./target/release/synvoid --config config/main.toml"
