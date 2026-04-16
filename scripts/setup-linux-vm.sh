#!/bin/bash
# Setup Linux VM for eBPF development and testing
# Uses Multipass (https://multipass.run)

set -e

VM_NAME="ebpf-enforcer"
VM_CPUS=2
VM_MEMORY="4G"
VM_DISK="20G"

echo "=== Agent Gateway Enforcer - Linux VM Setup ==="
echo ""

# Check if multipass is installed
if ! command -v multipass &> /dev/null; then
    echo "Multipass not found. Installing..."
    if [[ "$OSTYPE" == "darwin"* ]]; then
        brew install multipass
    else
        echo "Please install Multipass manually: https://multipass.run"
        exit 1
    fi
fi

# Check if VM already exists
if multipass list | grep -q "$VM_NAME"; then
    echo "VM '$VM_NAME' already exists."
    read -p "Delete and recreate? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        multipass delete "$VM_NAME"
        multipass purge
    else
        echo "Connecting to existing VM..."
        multipass shell "$VM_NAME"
        exit 0
    fi
fi

echo "Creating Ubuntu VM: $VM_NAME"
echo "  CPUs: $VM_CPUS"
echo "  Memory: $VM_MEMORY"
echo "  Disk: $VM_DISK"
echo ""

# Create VM with Ubuntu 22.04 LTS
multipass launch 22.04 \
    --name "$VM_NAME" \
    --cpus "$VM_CPUS" \
    --memory "$VM_MEMORY" \
    --disk "$VM_DISK"

echo "VM created. Setting up development environment..."

# Create setup script to run inside VM
multipass exec "$VM_NAME" -- bash -c 'cat > /tmp/setup.sh << '\''SETUP_SCRIPT'\''
#!/bin/bash
set -e

echo "=== Installing dependencies ==="

# Update system
sudo apt update && sudo apt upgrade -y

# Install eBPF toolchain
sudo apt install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    build-essential \
    pkg-config \
    libssl-dev \
    curl \
    git \
    bpftool

# Install Rust
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto "=https" --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Add Rust to path for future sessions
echo '\''source "$HOME/.cargo/env"'\'' >> ~/.bashrc

# Install bpf-linker (for aya-based eBPF)
cargo install bpf-linker || echo "bpf-linker install failed (may need nightly)"

echo ""
echo "=== Setup complete! ==="
echo ""
echo "To build the enforcer:"
echo "  cd /path/to/agent-gateway-enforcer"
echo "  cargo build --release"
echo ""
echo "To run with eBPF (requires root):"
echo "  sudo ./target/release/agent-gateway-enforcer run --config config.opencode.yaml"
echo ""
SETUP_SCRIPT
chmod +x /tmp/setup.sh
/tmp/setup.sh'

echo ""
echo "=== VM Setup Complete ==="
echo ""
echo "To connect to VM:"
echo "  multipass shell $VM_NAME"
echo ""
echo "To mount this project in the VM:"
echo "  multipass mount $(pwd) $VM_NAME:/home/ubuntu/agent-gateway-enforcer"
echo ""
echo "To stop VM:"
echo "  multipass stop $VM_NAME"
echo ""
echo "To delete VM:"
echo "  multipass delete $VM_NAME && multipass purge"
echo ""

# Ask if user wants to mount the project
read -p "Mount current project directory in VM? (Y/n) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Nn]$ ]]; then
    CURRENT_DIR=$(pwd)
    multipass mount "$CURRENT_DIR" "$VM_NAME:/home/ubuntu/agent-gateway-enforcer"
    echo "Project mounted at /home/ubuntu/agent-gateway-enforcer"
fi

# Connect to VM
echo ""
echo "Connecting to VM..."
multipass shell "$VM_NAME"
