#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
# Install Cloudflared
set -e
if [[ -f /root/.cloudflared ]]; then
    printf "%s\n" "Cloudflared has been installed before, skipping..."
    else
printf "%s\n" "Installing Cloudflared"
curl -sSLO https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
apt-get -qqy install ./cloudflared-linux-amd64.deb -y && \
printf "%s\n" "Cloudflared installed" || printf "%s\n" "Failed to install Cloudflared" && \
rm -f cloudflared-linux-amd64.deb
cloudflared -v
useradd -s /usr/sbin/nologin -r -M cloudflared

cat << EOF > /etc/default/cloudflared
# Commandline args for cloudflared, using Cloudflare DNS
CLOUDFLARED_OPTS=--port 5053 --upstream https://1.1.1.1/dns-query --upstream https://1.0.0.1/dns-query
EOF

chown cloudflared:cloudflared /etc/default/cloudflared
chown cloudflared:cloudflared /usr/local/bin/cloudflared

bash -c "cat << EOF > /etc/systemd/system/cloudflared.service
[Unit]
Description=cloudflared DNS over HTTPS proxy
After=syslog.target network-online.target

[Service]
Type=simple
User=cloudflared
EnvironmentFile=/etc/default/cloudflared
ExecStart=/usr/local/bin/cloudflared proxy-dns \\\$CLOUDFLARED_OPTS
Restart=on-failure
RestartSec=10
KillMode=process

[Install]
WantedBy=multi-user.target
EOF
" && \
printf "%s\n" "Cloudflared service file created" || printf "%s\n" "Failed to create Cloudflared service file"

systemctl enable cloudflared
systemctl start cloudflared
systemctl status cloudflared > /dev/null && \
printf "%s\n" "Cloudflared service installed and enabled" || printf "%s\n" "Failed to install Cloudflared service"

bash -c ' cat << EOF > /etc/cron.weekly/cloudflared-updater
#!/usr/bin/env bash
set -e
curl -sSLO https://github.com/cloudflare/cloudflared/releases/download/2024.8.3/cloudflared-linux-amd64
systemctl stop cloudflared
mv cloudflared-linux-amd64 "\$(command -v cloudflared)"
chmod +x "\$(command -v cloudflared)"
systemctl start cloudflared
cloudflared -v
systemctl status cloudflared
EOF
'

chmod +x /etc/cron.weekly/cloudflared-updater
chown root:root /etc/cron.weekly/cloudflared-updater
touch /root/.cloudflared && printf "\n%s\n" "Cloudflared installation completed successfully";
fi