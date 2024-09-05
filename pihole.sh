#!/usr/bin/env bash

# Install Pi-hole and Cloudflared
PI_HOLE_PASSWORD=$1

# cloudflared
set -e
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

# pihole
pass=$(printf "$PI_HOLE_PASSWORD" | sha256sum | awk '{printf $1}'|sha256sum);
bash -c "cat << EOF > /etc/pihole/setupVars.conf
PIHOLE_INTERFACE=ens3
QUERY_LOGGING=true
INSTALL_WEB_SERVER=true
INSTALL_WEB_INTERFACE=true
LIGHTTPD_ENABLED=true
CACHE_SIZE=10000
DNS_FQDN_REQUIRED=true
DNS_BOGUS_PRIV=true
DNSMASQ_LISTENING=all
WEBPASSWORD=$(printf ${pass})
BLOCKING_ENABLED=true
DNSSEC=false
REV_SERVER=false
PIHOLE_DNS_1=127.0.0.1#5053
PIHOLE_DNS_2=::1#5053
EOF
"
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
rule_number=$(sudo iptables -L INPUT --line-numbers | grep -E 'ACCEPT.*dpt:ssh' | awk '{print $1}')
iptables -I INPUT $((++rule_number)) -i tun0 -s 10.50.0.0/24 -d 10.0.0.2 -j ACCEPT
sh -c 'iptables-save > /etc/iptables/rules.v4' && sh -c 'iptables-restore < /etc/iptables/rules.v4' && \
printf "%s\n" "Firewall rules saved and enabled" || printf "%s\n" "Failed to enable saved and Firewall rules"

printf "%s\n" "Pi-hole installed"
