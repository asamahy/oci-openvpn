#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
set -e

# Common Variables
export INSTALL_WEBMIN="false";
export INSTALL_OPENVPN="true";
export INSTALL_PIHOLE="true";
export INSTALL_CLOUDFLARED="false";
export INSTALL_UNBOUND="true";
export INSTALL_TAILSCALE="true";

export INSTANCE_NAME="CHANGE_ME";
export CHANGE_PASSWORDS="true";
export UBUNTU_PASSWORD="CHANGE_ME";
export ROOT_PASSWORD="CHANGE_ME";
export PI_HOLE_PASSWORD="CHANGE_ME";
export TAILSCALE_AUTH_KEY="CHANGE_ME";
export DNS_SERVER_1=""; # change to a DNS Server if you are not using Unbound or Cloudflared
VPN_SERVER_IP="$(curl -s -4 ifconfig.io)"; # change to domain name if you have one
export VPN_SERVER_IP;
export VPN_NET_IP="10.50.0.0";
export VPN_NET_MASK="255.255.255.0";
export VPN_CIDR="24";
export VPN_PORT="1194";
export VPN_PROTOCOL="udp";
export VPN_CIPHER="AES-256-CBC";
export HMAC_ALG="SHA512";


# Required Variables
function configure-oci-cli(){
mkdir -p /root/.oci/sessions/DEFAULT
cat <<EOF > /root/.oci/sessions/DEFAULT/oci_api_key.pem
-----BEGIN PRIVATE KEY-----
# paste the private key here
-----END PRIVATE KEY-----
OCI_API_KEY
EOF
cat <<EOF > /root/.oci/config
[DEFAULT]
user=<>
fingerprint=<>
tenancy=<>
region=<>
key_file=/root/.oci/sessions/DEFAULT/oci_api_key.pem
EOF
chmod 600 /root/.oci/sessions/DEFAULT/oci_api_key.pem
chmod 600 /root/.oci/config
};

export -f configure-oci-cli;

bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/cloudlab.sh)"