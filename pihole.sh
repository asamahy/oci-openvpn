#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
# shellcheck disable=SC2059,SC2086,SC2154

# Install Pi-hole
set -e
if [[ -f /root/.pihole ]]; then
    printf "%s\n" "Pi-hole has been installed before, skipping..."
    else
    { [[ "$INSTALL_CLOUDFLARED" != "true" ]] && [[ "$INSTALL_UNBOUND" != "true" ]] && DNS_SERVER="1.1.1.1"; } || DNS_SERVER="127.0.0.1";
    { [[ "$INSTALL_CLOUDFLARED" == "true" ]] && DNS_PORT='5053'; } || { [[ "$INSTALL_UNBOUND" == "true" ]] && DNS_PORT='5335'; } || DNS_PORT='53';
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
PIHOLE_DNS_1=${DNS_SERVER}#${DNS_PORT}
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
    touch /root/.pihole && printf "\n%s\n" "Pi-hole installation completed successfully";
fi
