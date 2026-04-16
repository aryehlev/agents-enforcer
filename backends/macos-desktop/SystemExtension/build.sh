#!/bin/bash
# Build script for Agent Gateway Enforcer System Extension
# Requires: Xcode, xcodegen (brew install xcodegen)

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Agent Gateway Enforcer - System Extension Build ==="
echo ""

# Check for xcodegen
if ! command -v xcodegen &> /dev/null; then
    echo "xcodegen not found. Installing..."
    brew install xcodegen
fi

# Check for full Xcode (not just command line tools)
XCODE_PATH=$(mdfind 'kMDItemCFBundleIdentifier == "com.apple.dt.Xcode"' 2>/dev/null | head -1)

if [ -z "$XCODE_PATH" ]; then
    echo "ERROR: Full Xcode not found"
    echo ""
    echo "System Extensions require full Xcode, not just Command Line Tools."
    echo ""
    echo "Install Xcode from:"
    echo "  1. Mac App Store: https://apps.apple.com/app/xcode/id497799835"
    echo "  2. Or download from: https://developer.apple.com/xcode/"
    echo ""
    echo "After installing, run:"
    echo "  sudo xcode-select -s /Applications/Xcode.app/Contents/Developer"
    echo ""
    exit 1
fi

# Select Xcode if not already selected
CURRENT_DEV_DIR=$(xcode-select -p 2>/dev/null)
if [[ "$CURRENT_DEV_DIR" != *"Xcode"* ]]; then
    echo "Switching to Xcode developer directory..."
    sudo xcode-select -s "$XCODE_PATH/Contents/Developer"
fi

# Generate Xcode project
echo "Generating Xcode project..."
xcodegen generate

# Build the project
echo ""
echo "Building project..."
xcodebuild -project AgentGatewayEnforcer.xcodeproj \
    -scheme AgentGatewayEnforcer \
    -configuration Debug \
    -derivedDataPath build \
    CODE_SIGN_IDENTITY="-" \
    CODE_SIGNING_ALLOWED=NO \
    build

echo ""
echo "=== Build Complete ==="
echo ""
echo "App location:"
echo "  $SCRIPT_DIR/build/Build/Products/Debug/Agent Gateway Enforcer.app"
echo ""
echo "=== Installation Instructions ==="
echo ""
echo "1. Disable SIP (if not already done):"
echo "   - Restart Mac and hold Cmd+R (Intel) or Power button (Apple Silicon)"
echo "   - Open Terminal from Utilities menu"
echo "   - Run: csrutil disable"
echo "   - Restart"
echo ""
echo "2. Enable developer mode for system extensions:"
echo "   sudo systemextensionsctl developer on"
echo ""
echo "3. Run the app:"
echo "   open \"$SCRIPT_DIR/build/Build/Products/Debug/Agent Gateway Enforcer.app\""
echo ""
echo "4. Approve in System Preferences > Security & Privacy > General"
echo ""
echo "5. Check extension status:"
echo "   systemextensionsctl list"
echo ""
