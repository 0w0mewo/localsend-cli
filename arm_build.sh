#!/bin/bash
set -e

BUILD_DIR="build"
PLUGIN_NAME="localsend.koplugin"
PLUGIN_SRC="lua"

# Clean and create build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/$PLUGIN_NAME"

# Copy plugin source files to build directory
cp "$PLUGIN_SRC/main.lua" "$BUILD_DIR/$PLUGIN_NAME/"
cp "$PLUGIN_SRC/_meta.lua" "$BUILD_DIR/$PLUGIN_NAME/"

# Build for armv7 (32-bit ARM)
echo "Building for armv7..."
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o "$BUILD_DIR/$PLUGIN_NAME/localsend" .
echo "Compressing armv7 with UPX..."
upx --best "$BUILD_DIR/$PLUGIN_NAME/localsend"
echo "armv7: $(ls -lh "$BUILD_DIR/$PLUGIN_NAME/localsend" | awk '{print $5}')"

# Create armv7 zip
echo "Creating armv7 zip..."
(cd "$BUILD_DIR" && zip -r "localsend-koplugin-armv7.zip" "$PLUGIN_NAME")

# Build for arm64 (64-bit ARM)
echo "Building for arm64..."
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$BUILD_DIR/$PLUGIN_NAME/localsend" .
echo "Compressing arm64 with UPX..."
upx --best "$BUILD_DIR/$PLUGIN_NAME/localsend"
echo "arm64: $(ls -lh "$BUILD_DIR/$PLUGIN_NAME/localsend" | awk '{print $5}')"

# Create arm64 zip
echo "Creating arm64 zip..."
(cd "$BUILD_DIR" && zip -r "localsend-koplugin-arm64.zip" "$PLUGIN_NAME")

# Clean up binary from plugin dir (keep only zips)
rm -rf "$BUILD_DIR/$PLUGIN_NAME"

echo ""
echo "Done! Release files:"
ls -lh "$BUILD_DIR"/*.zip
