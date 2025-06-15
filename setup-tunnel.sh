#!/bin/bash

# Raspberry Pi Reverse Tunnel VPN Setup Script
# This script sets up a reverse SSH tunnel with WireGuard VPN
# Compatible with Raspberry Pi OS x64

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
VPN_PORT=51820
SSH_PORT=22
TUNNEL_PORT=2222
VPN_SUBNET="10.0.0.0/24"
SERVER_IP="10.0.0.1"
CLIENT_IP="10.0.0.2"

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        print_error "This script should not be run as root for security reasons"
        print_status "Please run as regular user with sudo privileges"
        exit 1
    fi
}

# Get user input for configuration
get_user_config() {
    echo -e "${BLUE}=== Reverse Tunnel VPN Configuration ===${NC}"
    
    read -p "Enter your remote server IP/hostname: " REMOTE_SERVER
    read -p "Enter remote server SSH port (default 22): " REMOTE_SSH_PORT
    REMOTE_SSH_PORT=${REMOTE_SSH_PORT:-22}
    
    read -p "Enter remote server username: " REMOTE_USER
    
    read -p "Enter VPN port (default 51820): " VPN_PORT_INPUT
    VPN_PORT=${VPN_PORT_INPUT:-51820}
    
    read -p "Enter tunnel port for SSH (default 2222): " TUNNEL_PORT_INPUT
    TUNNEL_PORT=${TUNNEL_PORT_INPUT:-2222}
    
    echo
    print_status "Configuration:"
    print_status "Remote Server: $REMOTE_SERVER:$REMOTE_SSH_PORT"
    print_status "Remote User: $REMOTE_USER"
    print_status "VPN Port: $VPN_PORT"
    print_status "SSH Tunnel Port: $TUNNEL_PORT"
    echo
    
    read -p "Continue with this configuration? (y/N): " CONFIRM
    if [[ ! $CONFIRM =~ ^[Yy]$ ]]; then
        print_status "Setup cancelled"
        exit 0
    fi
}

# Update system
update_system() {
    print_status "Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
}

# Install required packages
install_packages() {
    print_status "Installing required packages..."
    sudo apt install -y \
        wireguard \
        wireguard-tools \
        openssh-server \
        autossh \
        qrencode \
        iptables-persistent \
        ufw \
        fail2ban
}

# Generate SSH key pair if not exists
setup_ssh_keys() {
    print_status "Setting up SSH keys..."
    
    if [[ ! -f ~/.ssh/id_rsa ]]; then
        print_status "Generating SSH key pair..."
        ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa -N ""
        print_success "SSH key pair generated"
    else
        print_status "SSH key pair already exists"
    fi
    
    print_status "Your public key (copy this to your remote server):"
    echo -e "${YELLOW}$(cat ~/.ssh/id_rsa.pub)${NC}"
    echo
    print_warning "You need to add this public key to $REMOTE_USER@$REMOTE_SERVER:~/.ssh/authorized_keys"
    read -p "Press Enter when you've added the public key to the remote server..."
}

# Test SSH connection
test_ssh_connection() {
    print_status "Testing SSH connection to remote server..."
    
    if ssh -o ConnectTimeout=10 -o BatchMode=yes -p $REMOTE_SSH_PORT $REMOTE_USER@$REMOTE_SERVER echo "SSH connection successful" 2>/dev/null; then
        print_success "SSH connection to remote server successful"
    else
        print_error "SSH connection failed. Please check:"
        print_error "1. Remote server is accessible"
        print_error "2. SSH public key is properly added"
        print_error "3. SSH service is running on remote server"
        exit 1
    fi
}

# Generate WireGuard keys
generate_wireguard_keys() {
    print_status "Generating WireGuard keys..."
    
    # Server keys (Pi)
    wg genkey | sudo tee /etc/wireguard/server_private.key | wg pubkey | sudo tee /etc/wireguard/server_public.key
    
    # Client keys
    wg genkey | sudo tee /etc/wireguard/client_private.key | wg pubkey | sudo tee /etc/wireguard/client_public.key
    
    # Set proper permissions
    sudo chmod 600 /etc/wireguard/server_private.key /etc/wireguard/client_private.key
    
    print_success "WireGuard keys generated"
}

# Configure WireGuard server
setup_wireguard_server() {
    print_status "Configuring WireGuard server..."
    
    SERVER_PRIVATE_KEY=$(sudo cat /etc/wireguard/server_private.key)
    CLIENT_PUBLIC_KEY=$(sudo cat /etc/wireguard/client_public.key)
    
    sudo tee /etc/wireguard/wg0.conf > /dev/null <<EOF
[Interface]
PrivateKey = $SERVER_PRIVATE_KEY
Address = $SERVER_IP/24
ListenPort = $VPN_PORT
SaveConfig = true

# Enable IP forwarding
PostUp = echo 1 > /proc/sys/net/ipv4/ip_forward
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
PostUp = iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o eth0 -j MASQUERADE
PostDown = iptables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP/32
EOF

    print_success "WireGuard server configured"
}

# Generate client configuration
generate_client_config() {
    print_status "Generating client configuration..."
    
    SERVER_PUBLIC_KEY=$(sudo cat /etc/wireguard/server_public.key)
    CLIENT_PRIVATE_KEY=$(sudo cat /etc/wireguard/client_private.key)
    
    # Get the Pi's local IP for the endpoint
    LOCAL_IP=$(hostname -I | awk '{print $1}')
    
    tee ~/wireguard-client.conf > /dev/null <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP/24
DNS = 8.8.8.8, 1.1.1.1

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $LOCAL_IP:$VPN_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
EOF

    print_success "Client configuration saved to ~/wireguard-client.conf"
    
    # Generate QR code
    print_status "Generating QR code for mobile devices..."
    qrencode -t ansiutf8 < ~/wireguard-client.conf
    qrencode -o ~/wireguard-qr.png < ~/wireguard-client.conf
    print_success "QR code saved to ~/wireguard-qr.png"
}

# Enable IP forwarding
enable_ip_forwarding() {
    print_status "Enabling IP forwarding..."
    echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
    sudo sysctl -p
    print_success "IP forwarding enabled"
}

# Configure firewall
setup_firewall() {
    print_status "Configuring firewall..."
    
    # Reset UFW
    sudo ufw --force reset
    
    # Default policies
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Allow SSH
    sudo ufw allow $SSH_PORT/tcp
    
    # Allow WireGuard
    sudo ufw allow $VPN_PORT/udp
    
    # Allow forwarding
    sudo sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
    
    # Enable UFW
    sudo ufw --force enable
    
    print_success "Firewall configured"
}

# Setup reverse SSH tunnel service
setup_reverse_tunnel() {
    print_status "Setting up reverse SSH tunnel service..."
    
    sudo tee /etc/systemd/system/reverse-tunnel.service > /dev/null <<EOF
[Unit]
Description=Reverse SSH Tunnel
After=network.target

[Service]
Type=simple
User=$USER
ExecStart=/usr/bin/autossh -M 0 -N -T -o "ServerAliveInterval 60" -o "ServerAliveCountMax 3" -o "ExitOnForwardFailure yes" -R $TUNNEL_PORT:localhost:$SSH_PORT -R $VPN_PORT:localhost:$VPN_PORT -p $REMOTE_SSH_PORT $REMOTE_USER@$REMOTE_SERVER
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable reverse-tunnel.service
    
    print_success "Reverse tunnel service created"
}

# Start services
start_services() {
    print_status "Starting services..."
    
    # Start WireGuard
    sudo systemctl enable wg-quick@wg0
    sudo systemctl start wg-quick@wg0
    
    # Start reverse tunnel
    sudo systemctl start reverse-tunnel.service
    
    print_success "Services started"
}

# Create management scripts
create_management_scripts() {
    print_status "Creating management scripts..."
    
    # Status script
    tee ~/tunnel-status.sh > /dev/null <<'EOF'
#!/bin/bash
echo "=== Reverse Tunnel Status ==="
systemctl status reverse-tunnel.service --no-pager -l
echo
echo "=== WireGuard Status ==="
sudo wg show
echo
echo "=== Active Connections ==="
ss -tulnp | grep -E "(51820|2222|22)"
EOF
    
    # Restart script
    tee ~/tunnel-restart.sh > /dev/null <<'EOF'
#!/bin/bash
echo "Restarting services..."
sudo systemctl restart reverse-tunnel.service
sudo systemctl restart wg-quick@wg0
echo "Services restarted"
EOF
    
    # Stop script
    tee ~/tunnel-stop.sh > /dev/null <<'EOF'
#!/bin/bash
echo "Stopping services..."
sudo systemctl stop reverse-tunnel.service
sudo systemctl stop wg-quick@wg0
echo "Services stopped"
EOF
    
    chmod +x ~/tunnel-*.sh
    
    print_success "Management scripts created in home directory"
}

# Display final instructions
show_final_instructions() {
    echo
    echo -e "${GREEN}=== Setup Complete! ===${NC}"
    echo
    print_success "Your Raspberry Pi reverse tunnel VPN is now configured!"
    echo
    print_status "What was set up:"
    echo "  • WireGuard VPN server on port $VPN_PORT"
    echo "  • Reverse SSH tunnel to $REMOTE_SERVER"
    echo "  • SSH accessible via $REMOTE_SERVER:$TUNNEL_PORT"
    echo "  • VPN accessible via $REMOTE_SERVER:$VPN_PORT"
    echo
    print_status "Client configuration:"
    echo "  • WireGuard config: ~/wireguard-client.conf"
    echo "  • QR code: ~/wireguard-qr.png"
    echo
    print_status "Management commands:"
    echo "  • Check status: ./tunnel-status.sh"
    echo "  • Restart services: ./tunnel-restart.sh"
    echo "  • Stop services: ./tunnel-stop.sh"
    echo
    print_status "To connect:"
    echo "  1. SSH: ssh -p $TUNNEL_PORT $USER@$REMOTE_SERVER"
    echo "  2. VPN: Import ~/wireguard-client.conf to your WireGuard client"
    echo
    print_warning "Remote server requirements:"
    echo "  • Port $TUNNEL_PORT forwarded for SSH access"
    echo "  • Port $VPN_PORT forwarded for VPN access"
    echo "  • GatewayPorts yes in /etc/ssh/sshd_config (for external access)"
    echo
}

# Main execution
main() {
    echo -e "${BLUE}=== Raspberry Pi Reverse Tunnel VPN Setup ===${NC}"
    echo
    
    check_root
    get_user_config
    
    print_status "Starting setup process..."
    
    update_system
    install_packages
    setup_ssh_keys
    test_ssh_connection
    generate_wireguard_keys
    setup_wireguard_server
    generate_client_config
    enable_ip_forwarding
    setup_firewall
    setup_reverse_tunnel
    start_services
    create_management_scripts
    
    show_final_instructions
}

# Run main function
main "$@"
