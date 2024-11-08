#!/usr/bin/env bash
# Install Tailscale
# https://tailscale.com/kb/1293/cloud-init
# required variables:
# - TAILSCALE_AUTH_KEY
# - SUBNET_ID
# - rule_number
# - NETDEV
# - SECURITY_LIST_ID
# - COMPARTMENT_ID
# - VCN_ID
# required functions:
# - get-ipv4-subnet
# - add_iptables_rule
# - update-security-list

set -e
if [[ -f /root/.tailscale ]]; then
    printf "%s\n" "Tailscale has been installed before, skipping..."
    else
printf "%s\n" "Installing Tailscale"
sed -i \
-e 's/^#\(net.ipv4.ip_forward=\)\([0-1]\)/\11/' \
-e 's/^#\(net.ipv6.conf.all.forwarding=\)\([0-1]\)/\11/' /etc/sysctl.conf
sysctl -p > /dev/null
sh -c "$(curl -sSL https://tailscale.com/install.sh)"
[[ -n "${TAILSCALE_AUTH_KEY}" ]] && \
tailscale up --ssh --authkey="${TAILSCALE_AUTH_KEY}" --advertise-routes="$(get-ipv4-subnet "$SUBNET_ID"),169.254.169.254/32" --accept-dns=false;
add_iptables_rule "$NETDEV" 41641 udp "Tailscale IPv4 Direct Connection"
update-security-list "$SECURITY_LIST_ID" "Tailscale IPv4 Direct Connection" "null" "true" "UDP" "0.0.0.0/0" "CIDR_BLOCK" "" "41641" "ingress"
[[ -f /etc/networkd-dispatcher/routable.d/60-openvpn ]] || \
{ printf '#!/bin/sh\n\nethtool -K %s rx-udp-gro-forwarding on rx-gro-list off \n' "$NETDEV" > /etc/networkd-dispatcher/routable.d/50-tailscale && \
chmod 755 /etc/networkd-dispatcher/routable.d/50-tailscale; }
touch /root/.tailscale && printf "\n%s\n" "Tailscale installation completed successfully";
fi
