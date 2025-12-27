#!/bin/bash
set -e

PLUGIN_DIR="localsend.koplugin"

# Build for armv7 (32-bit ARM)
echo "Building for armv7..."
GOOS=linux GOARCH=arm GOARM=7 go build -ldflags="-s -w" -o "$PLUGIN_DIR/localsend-armv7" .
echo "Compressing armv7 with UPX..."
upx --best "$PLUGIN_DIR/localsend-armv7"
echo "armv7: $(ls -lh "$PLUGIN_DIR/localsend-armv7" | awk '{print $5}')"

# Build for arm64 (64-bit ARM)
echo "Building for arm64..."
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$PLUGIN_DIR/localsend-arm64" .
echo "Compressing arm64 with UPX..."
upx --best "$PLUGIN_DIR/localsend-arm64"
echo "arm64: $(ls -lh "$PLUGIN_DIR/localsend-arm64" | awk '{print $5}')"

# Create separate zip files for each architecture
echo "Creating release zips..."
rm -f localsend-koplugin-armv7.zip localsend-koplugin-arm64.zip

# Clean up any old binaries
rm -f "$PLUGIN_DIR/localsend" "$PLUGIN_DIR/localsend-armhf"

# armv7 zip - temporarily remove arm64, rename armv7 to localsend
rm -f "$PLUGIN_DIR/localsend-arm64"
mv "$PLUGIN_DIR/localsend-armv7" "$PLUGIN_DIR/localsend"
zip -r localsend-koplugin-armv7.zip "$PLUGIN_DIR"
mv "$PLUGIN_DIR/localsend" "$PLUGIN_DIR/localsend-armv7"

# Rebuild arm64 binary
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o "$PLUGIN_DIR/localsend-arm64" .
upx --best "$PLUGIN_DIR/localsend-arm64"

# arm64 zip - temporarily remove armv7, rename arm64 to localsend
rm -f "$PLUGIN_DIR/localsend-armv7"
mv "$PLUGIN_DIR/localsend-arm64" "$PLUGIN_DIR/localsend"
zip -r localsend-koplugin-arm64.zip "$PLUGIN_DIR"
rm "$PLUGIN_DIR/localsend"

echo ""
echo "Done! Release files:"
ls -lh localsend-koplugin-*.zip
