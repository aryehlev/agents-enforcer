#!/bin/bash
# Development environment setup script for Agent Gateway Enforcer

set -e

echo "🚀 Setting up Agent Gateway Enforcer development environment..."

# Install Rust if not present
if ! command -v rustup &> /dev/null; then
    echo "📦 Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    echo "✅ Rust is already installed"
fi

# Install required components
echo "📦 Installing Rust components..."
rustup component add clippy rustfmt rust-src

# Platform-specific dependencies
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "🐧 Installing Linux dependencies..."
    
    # Detect package manager
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y \
            clang \
            libelf-dev \
            libbpf-dev \
            pkg-config \
            llvm \
            linux-headers-$(uname -r)
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y \
            clang \
            elfutils-libelf-devel \
            libbpf-devel \
            pkg-config \
            llvm \
            kernel-devel
    else
        echo "⚠️  Warning: Unknown package manager. Please install dependencies manually."
    fi
    
    # Install bpf-linker for eBPF development
    echo "📦 Installing bpf-linker..."
    cargo install bpf-linker || echo "⚠️  bpf-linker installation failed (may require nightly toolchain)"
    
elif [[ "$OSTYPE" == "darwin"* ]]; then
    echo "🍎 Installing macOS dependencies..."
    
    # Install Xcode command line tools
    if ! command -v xcode-select &> /dev/null; then
        echo "📦 Installing Xcode command line tools..."
        xcode-select --install
    else
        echo "✅ Xcode command line tools already installed"
    fi
    
    # Optionally install Homebrew dependencies
    if command -v brew &> /dev/null; then
        echo "📦 Installing Homebrew dependencies..."
        brew install llvm pkg-config
    fi
    
elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
    echo "🪟 Windows detected"
    echo "⚠️  Please ensure Visual Studio Build Tools are installed"
    echo "   Download from: https://visualstudio.microsoft.com/downloads/"
fi

# Install development tools
echo "📦 Installing development tools..."
cargo install cargo-watch || echo "⚠️  cargo-watch installation failed"
cargo install cargo-nextest || echo "⚠️  cargo-nextest installation failed"

# Verify installation
echo ""
echo "🔍 Verifying installation..."
echo "Rust version: $(rustc --version)"
echo "Cargo version: $(cargo --version)"
echo "Platform: $OSTYPE"

# Build workspace to verify everything works
echo ""
echo "🔨 Building workspace to verify setup..."
if cargo build --workspace; then
    echo ""
    echo "✅ Development environment setup complete!"
    echo ""
    echo "📝 Next steps:"
    echo "   1. Run 'cargo build --workspace' to build all components"
    echo "   2. Run 'cargo test --workspace' to run tests"
    echo "   3. Run 'cargo clippy --workspace' to check for lints"
    echo "   4. Run 'cargo fmt --all' to format code"
    echo ""
    echo "   Platform-specific:"
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo "   - Run 'cargo xtask build-ebpf' to build eBPF programs"
        echo "   - Run 'sudo target/debug/agent-gateway-enforcer run --help' for usage"
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        echo "   - Run 'target/debug/agent-gateway-enforcer backends' to list available backends"
    fi
else
    echo ""
    echo "❌ Build failed. Please check the errors above and resolve them."
    exit 1
fi
