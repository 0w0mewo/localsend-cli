#!/bin/bash
set -e

BUILD_DIR="build"
BIN_DIR="$BUILD_DIR/bin"
PLUGIN_NAME="localsend.koplugin"
PLUGIN_SRC="lua"

# Clean and create build directories
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR/$PLUGIN_NAME"
mkdir -p "$BIN_DIR"

# Copy plugin source files to build directory
cp "$PLUGIN_SRC/main.lua" "$BUILD_DIR/$PLUGIN_NAME/"
cp "$PLUGIN_SRC/_meta.lua" "$BUILD_DIR/$PLUGIN_NAME/"

# Build for armv7 (32-bit ARM)
echo "Building for armv7..."
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o "$BIN_DIR/localsend-armv7" .
echo "Compressing armv7 with UPX..."
upx --best "$BIN_DIR/localsend-armv7"
echo "armv7: $(ls -lh "$BIN_DIR/localsend-armv7" | awk '{print $5}')"

# Create armv7 zip
echo "Creating armv7 zip..."
cp "$BIN_DIR/localsend-armv7" "$BUILD_DIR/$PLUGIN_NAME/localsend"
(cd "$BUILD_DIR" && zip -r "localsend-koplugin-armv7.zip" "$PLUGIN_NAME")

# Build for arm64 (64-bit ARM)
echo "Building for arm64..."
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$BIN_DIR/localsend-arm64" .
echo "Compressing arm64 with UPX..."
upx --best "$BIN_DIR/localsend-arm64"
echo "arm64: $(ls -lh "$BIN_DIR/localsend-arm64" | awk '{print $5}')"

# Create arm64 zip
echo "Creating arm64 zip..."
cp "$BIN_DIR/localsend-arm64" "$BUILD_DIR/$PLUGIN_NAME/localsend"
(cd "$BUILD_DIR" && zip -r "localsend-koplugin-arm64.zip" "$PLUGIN_NAME")

# Clean up plugin staging dir (keep bins and zips)
rm -rf "$BUILD_DIR/$PLUGIN_NAME"

echo ""
echo "Done! Release files:"
ls -lh "$BUILD_DIR"/*.zip
echo ""
echo "Binaries:"
ls -lh "$BIN_DIR"/*
