#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
## Description: This script provisions a new Ubuntu 22.04 LTS server with the necessary tools and configurations 
## for running an OpenVPN server and Webmin for administration.
## the script will update the system, install necessary tools, enable IP forwarding, change openssl.cnf settings,
## install Webmin, install OpenVPN Webmin module, add firewall rules, and save the rules.
## 
## the script is meant to be run as an initialization script for a new Ubuntu 22.04 LTS instance.
## 
##
##
# update the repos and upgrade the system
apt-get update && apt-get upgrade -y && \
printf "%s\n" "System Updated" || printf "%s\n" "Failed to Update System"

# install tools
apt-get install net-tools nano rand apt-utils dialog iputils-ping dnsutils openvpn -y && \
printf "%s\n" "Tools Installed" || printf "%s\n" "Failed to Install Tools"

# generate random seed for openssl and write to /root/.rnd
openssl rand -writerand /root/.rnd -out /dev/null && \
printf "%s\n" "Random Seed Generated" || printf "%s\n" "Failed to Generate Random Seed"

# enable ip forwarding for ipv4 and ipv6
printf "%s\n" "Enabling IP Forwarding for IPv4 and IPv6"
sudo sed -i \
-e 's/^#\(net.ipv4.ip_forward=\)\([0-1]\)/\11/' \
-e 's/^#\(net.ipv6.conf.all.forwarding=\)\([0-1]\)/\11/' /etc/sysctl.conf && \
printf "%s\n" "IP Forwarding Enabled" || printf "%s\n" "Failed to Enable IP Forwarding"

# change default_days = 365 to default_days = 3650 in /etc/ssl/openssl.cnf
# change default_crl_days= 30 to default_crl_days= 3650 in /etc/ssl/openssl.cnf
# change default_md = default to default_md = sha512 in /etc/ssl/openssl.cnf
printf "%s\n" "Changing default_days, default_crl_days, and default_md in /etc/ssl/openssl.cnf"
sudo sed -i \
-e 's/^\(default_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_crl_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' /etc/ssl/openssl.cnf && \
printf "%s\n" "Successfully Modified openssl.cnf" || printf "%s\n" "Failed to Modify openssl.cnf"

# install webmin
printf "%s\n" "Installing Webmin"
curl -o setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
chmod +x setup-repos.sh
sh setup-repos.sh --force && \
printf "%s\n" "Webmin Repositories Installed" || printf "%s\n" "Failed to Install Webmin Repositories"
apt-get install webmin --install-recommends -y && \
printf "%s\n" "Webmin Installed" || printf "%s\n" "Failed to Install Webmin"

sleep 2

# edit webmin openssl.cnf
printf "%s\n" "Changing default_days, default_crl_days, and default_md in /usr/share/webmin/acl/openssl.cnf"
sudo sed -i \
-e 's/^\(default_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_crl_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' /usr/share/webmin/acl/openssl.cnf && \
printf "%s\n" "Successfully Modified Webmin openssl.cnf" || printf "%s\n" "Failed to Modify Webmin openssl.cnf"

# install openvpn webmin module
printf "%s\n" "Installing OpenVPN Webmin Module"
curl -LO https://github.com/nicsure/webmin-openvpn-debian-jessie/raw/master/openvpn.wbm.gz
/usr/share/webmin/install-module.pl openvpn.wbm.gz && \
printf "%s\n" "OpenVPN Webmin Module Installed" || printf "%s\n" "Failed to Install OpenVPN Webmin Module"
# edit webmin openvpn-ssl.cnf
sed -i \
-e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' /usr/share/webmin/openvpn/openvpn-ssl.cnf && \
printf "%s\n" "Successfully Modified openvpn-ssl.cnf" || printf "%s\n" "Failed to Modify openvpn-ssl.cnf"

# add rules to /etc/iptables/rules.v4
printf "%s\n" "Adding rules to /etc/iptables/rules.v4"
# last rule number
rule_number=$(sudo iptables -L INPUT --line-numbers | grep -E 'ACCEPT.*dpt:ssh' | awk '{print $1}')

# inserting firewall rules
# webmin port 10000
printf "%s\n" "Adding Webmin rule"
iptables -I INPUT $((++ rule_number)) -p tcp -m state -m tcp --dport 10000 --state NEW -j ACCEPT && \
printf "%s\n" "Webmin rule added" || printf "%s\n" "Failed to add Webmin rule"

# openvpn port 1194
printf "%s\n" "Adding OpenVPN rule"
iptables -I INPUT $((++ rule_number)) -p udp -m udp --dport 1194 -j ACCEPT && \
printf "%s\n" "OpenVPN rule added" || printf "%s\n" "Failed to add OpenVPN rule"

# temp netcat port 17486
printf "%s\n" "Adding Temp. Netcat rule"
iptables -I INPUT $((++ rule_number)) -p tcp -m state -m tcp --dport 17486 --state NEW -j ACCEPT && \
printf "%s\n" "Temp. Netcat rule added" || printf "%s\n" "Failed to add Temp. Netcat rule"

# delete FORWARD rules with reject-with icmp-host-prohibited rule
printf "%s\n" "Deleting FORWARD rules with reject-with icmp-host-prohibited"
iptables -L FORWARD --line-numbers | \
grep -E 'reject-with.*icmp-host-prohibited' | \
awk '{print $1}' | xargs -I {} iptables -D FORWARD {} && \
printf "%s\n" "Deleted FORWARD rules" || printf "%s\n" "No FORWARD rules found"

# NAT Rules for OpenVPN Server on ens3 interface with IP 10.50.0.0/24
iptables -t nat -A POSTROUTING -s 10.50.0.0/24 -o ens3 -j SNAT --to-source 10.0.0.2 && \
printf "%s\n" "NAT POSTROUTING Rules Added" || printf "%s\n" "Failed to Add NAT POSTROUTING Rules"

sleep 2
# save the rules
printf "%s\n" "Saving the Firewall rules"
sh -c 'iptables-save > /etc/iptables/rules.v4' && \
printf "%s\n" "Firewall rules saved" || printf "%s\n" "Failed to save Firewall rules"

# enable the rules
printf "%s\n" "Enabling the Firewall rules"
sh -c 'iptables-restore < /etc/iptables/rules.v4' && \
printf "%s\n" "Firewall rules enabled" || printf "%s\n" "Failed to enable Firewall rules"

printf "%s\n" "Provisioning completed"