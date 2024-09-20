#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
# Install Webmin
# Required variables:
# - rule_number
# - SECURITY_LIST_ID
# - COMPARTMENT_ID
# - VCN_ID
# - VPN_SERVER_IP
# required functions:
# - update_openssl_conf
# - add_iptables_rule
# - update-security-list
#
set -e
if [[ -f /root/.webmin ]]; then
    printf "%s\n" "Webmin has been installed before, skipping..."
    else
printf "%s\n" "Installing Webmin"
bash -c "$(curl -sSL  https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh)" -- --force
apt-get install webmin --install-recommends -y
update_openssl_conf "/usr/share/webmin/acl/openssl.cnf"
curl -sSL -o openvpn.wbm.gz https://github.com/asamahy/webmin-openvpn-debian-jessie/raw/master/openvpn.wbm.gz
/usr/share/webmin/install-module.pl openvpn.wbm.gz && rm -f openvpn.wbm.gz
add_iptables_rule 10000 tcp "Webmin"
update-security-list "$SECURITY_LIST_ID" "Webmin Port" "null" "false" "TCP" "0.0.0.0/0" "CIDR_BLOCK" "" "10000" "ingress"
printf "%s\n" "Webmin portal is available @ https://${VPN_SERVER_IP}:10000"
touch /root/.webmin && printf "\n%s\n" "Webmin installation completed successfully";
fi