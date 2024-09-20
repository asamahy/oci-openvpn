#!/usr/bin/env bash
# shellcheck disable=SC2059,SC2086,SC2154

# Install Pi-hole and Cloudflared


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
PIHOLE_DNS_1=127.0.0.1#5335
PIHOLE_DNS_2=::1#5335
EOF
"
curl -sSL https://install.pi-hole.net | bash /dev/stdin --unattended
rule_number="$(sudo iptables -L INPUT --line-numbers | grep -E 'ACCEPT.*dpt:ssh' | awk '{print $1}')"
iptables -I INPUT $((++rule_number)) -i tun0 -s "${VPN_NET_IP}/${VPN_CIDR}" -d "$INSTANCE_IPv4" -j ACCEPT
add_iptables_rule 53 udp "PI-Hole DNS UDP"
add_iptables_rule 53 tcp "PI-Hole DNS TCP"
update-security-list "$SECURITY_LIST_ID" "Pi-Hole DNS" "null" "false" "UDP" "0.0.0.0/0" "CIDR_BLOCK" "" "53" "ingress"
update-security-list "$SECURITY_LIST_ID" "Pi-Hole DNS" "null" "false" "TCP" "0.0.0.0/0" "CIDR_BLOCK" "" "53" "ingress"

printf "%s\n" "Pi-hole installed"
touch /root/.provisioned7 && printf "%s\n" "Part 7 done"
fi

if [ -f /root/.provisioned8 ]; then
    printf "%s\n" "Part 8 has been run before, you are all set"
    else
    # unbound
apt-get -qqy install unbound
mkdir -p /etc/unbound/unbound.conf.d/
cat << EOF > /etc/unbound/unbound.conf.d/pi-hole.conf
server:
# If no logfile is specified, syslog is used
# logfile: "/var/log/unbound/unbound.log"
verbosity: 0

interface: 127.0.0.1
port: 5335
do-ip4: yes
do-udp: yes
do-tcp: yes

# May be set to yes if you have IPv6 connectivity
do-ip6: no

# You want to leave this to no unless you have *native* IPv6. With 6to4 and
# Terredo tunnels your web browser should favor IPv4 for the same reasons
prefer-ip6: no

# Use this only when you downloaded the list of primary root servers!
# If you use the default dns-root-data package, unbound will find it automatically
#root-hints: "/var/lib/unbound/root.hints"

# Trust glue only if it is within the server's authority
harden-glue: yes

# Require DNSSEC data for trust-anchored zones, if such data is absent, the zone becomes BOGUS
harden-dnssec-stripped: yes

# Don't use Capitalization randomization as it known to cause DNSSEC issues sometimes
# see https://discourse.pi-hole.net/t/unbound-stubby-or-dnscrypt-proxy/9378 for further details
use-caps-for-id: no

# Reduce EDNS reassembly buffer size.
# IP fragmentation is unreliable on the Internet today, and can cause
# transmission failures when large DNS messages are sent via UDP. Even
# when fragmentation does work, it may not be secure; it is theoretically
# possible to spoof parts of a fragmented DNS message, without easy
# detection at the receiving end. Recently, there was an excellent study
# >>> Defragmenting DNS - Determining the optimal maximum UDP response size for DNS <<<
# by Axel Koolhaas, and Tjeerd Slokker (https://indico.dns-oarc.net/event/36/contributions/776/)
# in collaboration with NLnet Labs explored DNS using real world data from the
# the RIPE Atlas probes and the researchers suggested different values for
# IPv4 and IPv6 and in different scenarios. They advise that servers should
# be configured to limit DNS messages sent over UDP to a size that will not
# trigger fragmentation on typical network links. DNS servers can switch
# from UDP to TCP when a DNS response is too big to fit in this limited
# buffer size. This value has also been suggested in DNS Flag Day 2020.
edns-buffer-size: 1232

# Perform prefetching of close to expired message cache entries
# This only applies to domains that have been frequently queried
prefetch: yes

# One thread should be sufficient, can be increased on beefy machines. In reality for most users running on small networks or on a single machine, it should be unnecessary to seek performance enhancement by increasing num-threads above 1.
num-threads: 1

# Ensure kernel buffer is large enough to not lose messages in traffic spikes
so-rcvbuf: 1m

# Ensure privacy of local IP ranges
private-address: 192.168.0.0/16
private-address: 169.254.0.0/16
private-address: 172.16.0.0/12
private-address: 10.0.0.0/8
private-address: fd00::/8
private-address: fe80::/10
EOF

echo 'edns-packet-max=1232' > /etc/dnsmasq.d/99-edns.conf
sudo systemctl disable --now unbound-resolvconf.service

touch /root/.provisioned8 && printf "%s\n" "Part 8 done"
fi
sleep 5 && reboot