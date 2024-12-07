
```
#!/bin/bash

echo "Starting Ubuntu 20.04 Quick Hardening Script..."

# Update and Upgrade
echo "Updating and upgrading packages..."
sudo apt update && sudo apt upgrade -y

# Install essential security packages
echo "Installing security tools (UFW, fail2ban)..."
sudo apt install ufw fail2ban unattended-upgrades -y

# Configure Firewall
echo "Configuring UFW firewall..."
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw enable

# Harden SSH
echo "Hardening SSH configuration..."
sudo sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/#X11Forwarding yes/X11Forwarding no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# Enable Unattended Upgrades
echo "Configuring unattended upgrades..."
sudo dpkg-reconfigure --priority=low unattended-upgrades

# Disable Unnecessary Services
echo "Disabling unnecessary services..."
sudo systemctl disable avahi-daemon
sudo systemctl disable cups
sudo systemctl disable bluetooth

# Configure Fail2Ban
echo "Setting up Fail2Ban..."
sudo systemctl enable fail2ban
sudo systemctl start fail2ban

# Remove Unused Packages
echo "Removing unnecessary packages..."
sudo apt autoremove -y
sudo apt autoclean -y

# Ensure Permissions
echo "Securing permissions for critical files..."
sudo chmod 600 /etc/ssh/sshd_config
sudo chmod 700 /root

# Audit System
echo "Installing Lynis for security auditing..."
sudo apt install lynis -y
sudo lynis audit system

# Final Message
echo "Ubuntu 20.04 Quick Hardening Complete. Please review logs and test configurations."
```

# Save to a file, harden_ubuntu.sh
# Make it executable
chmod +x harden_ubuntu.sh
# Run with sudo privilege
sudo ./harden_ubuntu.sh

# Manually triggering a Lynis scan
sudo lynis audit system

sudo lynis audit system --tests 'ACCT-9628'
