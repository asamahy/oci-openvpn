#!/usr/bin/env bash
# shellcheck disable=SC2059,SC2086

# Install Pi-hole and Cloudflared
PI_HOLE_PASSWORD="$1"
VPN_NET_IP="$2"
VPN_CIDR="$3"
INSTANCE_IPv4="$4"

# cloudflared
set -e
if [ -f /root/.provisioned6 ]; then
    printf "%s\n" "Part 6 has been run before, you are all set"
    else
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

touch /root/.provisioned6 && printf "%s\n" "Part 6 done"
fi


# pihole
if [ -f /root/.provisioned7 ]; then
    printf "%s\n" "Part 7 has been run before, you are all set"
    else
pass=$(printf "$PI_HOLE_PASSWORD" | sha256sum | awk '{printf $1}'|sha256sum);
mkdir -p /etc/pihole
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
rule_number="$(sudo iptables -L INPUT --line-numbers | grep -E 'ACCEPT.*dpt:ssh' | awk '{print $1}')"
iptables -I INPUT $((++rule_number)) -i tun0 -s "${VPN_NET_IP}/${VPN_CIDR}" -d "$INSTANCE_IPv4" -j ACCEPT
sh -c 'iptables-save > /etc/iptables/rules.v4' && sh -c 'iptables-restore < /etc/iptables/rules.v4' && \
printf "%s\n" "Firewall rules saved and enabled" || printf "%s\n" "Failed to enable saved and Firewall rules"

printf "%s\n" "Pi-hole installed"
touch /root/.provisioned7 && printf "%s\n" "Part 7 done"
sleep 5 && reboot

