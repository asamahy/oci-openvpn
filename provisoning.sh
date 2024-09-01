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
function cleanup(){
printf "%s\n" "Cleaning up temporary files..."
rm -f openvpn.wbm.gz
exit 0
};

# update the repos and upgrade the system
printf "%s\n" "****************************************"
printf "%s\n" "Provisioning Script for Ubuntu 22.04 LTS"
printf "%s\n\n" "****************************************"
printf "%s\n" "Updating System"
apt-get update && apt-get upgrade -y && \
printf "%s\n" "System Updated" || printf "%s\n" "Failed to Update System"
# install tools
printf "%s\n" "Installing Tools"
apt-get install net-tools nano rand apt-utils dialog iputils-ping dnsutils openvpn -y && \
printf "%s\n" "Tools Installed" || printf "%s\n" "Failed to Install Tools"

# generate random seed for openssl and write to /root/.rnd
printf "%s\n" "Generating Random Seed for OpenSSL"openssl rand -writerand /root/.rnd -out /dev/null && \
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
curl -o /tmp/setup-repos.sh https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh
chmod +x /tmp/setup-repos.sh
sh /tmp/setup-repos.sh --force && \
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
curl -L -o /tmp/openvpn.wbm.gz https://github.com/nicsure/webmin-openvpn-debian-jessie/raw/master/openvpn.wbm.gz
/usr/share/webmin/install-module.pl /tmp/openvpn.wbm.gz && \
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
############################################
## OCI-CLI Installation and Configuration ##
###########################################
# install oci-cli
printf "%s\n" "Installing OCI CLI"
curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh -o /tmp/install.sh && \
bash /tmp/install.sh --accept-all-defaults > /dev/null 2>&1
# exec -l $SHELL
oci --version && printf "%s\n" "OCI CLI installed successfully" || printf "%s\n" "OCI CLI installation failed"


## On the Oracle Web UI, go to "Identity" -> "Domains" -> "Default Domain" -> "Users" -> <YOUR-USER-NAME> -> "API Keys" -> "Add API Key"
## Download the Private Key and Public Key
## Open the Private Key in a text editor and copy the contents then paste it here
mkdir -p /root/.oci/sessions/DEFAULT
cat <<EOF > /root/.oci/sessions/DEFAULT/oci_api_key.pem
-----BEGIN PRIVATE KEY-----
# paste the private key here
-----END PRIVATE KEY-----
OCI_API_KEY
EOF

## After saving the private key, click Add and a new window will open with the configuration file content
## fill in the fields below with those info
## The values must not include any "" or '' characters.
## note: the user, fingerprint, tenancy, and region can be found in the OCI web UI under the user profile in case you dismissed the window
## note 2: leave the key_file as is unless you changed the path of the private key
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

###############################################
## Assign IPv6 Address to VNIC using OCI-CLI ##
###############################################
INSTANCE_NAME="CHANGE_ME"
COMPARTMENT_ID=$(oci iam compartment list --all --compartment-id-in-subtree true --access-level ACCESSIBLE \
--include-root --raw-output --query "data[?contains(\"id\",'tenancy')].id | [0]");
INSTANCE_ID=$(oci compute instance list --compartment-id "$COMPARTMENT_ID" --display-name "$INSTANCE_NAME" \
--raw-output --query "data[?contains(\"id\",'instance')].id | [0]");
VNIC_ID=$(oci compute instance list-vnics --instance-id "$INSTANCE_ID" \
--raw-output --query "data[?contains(\"id\",'vnic')].id | [0]");
SUBNET_ID=$(oci network vnic get --vnic-id "$VNIC_ID" --raw-output --query "data.\"subnet-id\"");
VCN_ID=$(oci network subnet get --subnet-id "$SUBNET_ID" --raw-output --query "data.\"vcn-id\"");
IPv6PREFIX="";
ROUTE_TABLE_ID=$(oci network route-table list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[?contains(\"id\",'routetable')].id | [0]");
INTERNET_GATEWAY_ID=$(oci network internet-gateway list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[?contains(\"id\",'internetgateway')].id | [0]");
SECURITY_LIST_ID=$(oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[?contains(\"id\",'securitylist')].id | [0]");
CURRENT_INGRESS_RULES="$(oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[].\"ingress-security-rules\"| [0]")";
CURRENT_EGRESS_RULES="$(oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[].\"egress-security-rules\"| [0]")";


# get ipv6 cidr block from vcn
function get-ipv6-prefix(){
    oci network vcn get --vcn-id "$1" --raw-output --query "data.\"ipv6-cidr-blocks\" | [0]";
};
# add ipv6 cidr block to vcn
function add-ipv6-cidr-block(){
    printf "%s\n" "Adding IPv6 CIDR Block"
    oci network vcn add-ipv6-vcn-cidr --vcn-id "$1" && \
    printf "%s\n" "IPv6 CIDR Block Added" || printf "%s\n" "Failed to Add IPv6 CIDR Block"
};

# loop to check that all ipv6 addresses are assigned successfully
function check-ipv6-ips(){
    VNIC_ID=$1
    i=$2
    Assigned_IPv6=$(oci network vnic get --vnic-id "$VNIC_ID" --raw-output --query "data.\"ipv6-addresses\" | [ $((i-1)) ]");
    if [[ ${Assigned_IPv6##*:} == $(printf "%x\n" $i) ]]; then
    printf "%s\n" "IPv6 Address $Assigned_IPv6 Has Been Assigned Successfully"
    sleep 3 # so we don't hit any rate limit
    else
    printf "%s\n" "IPv6 Address $Assigned_IPv6 Has Not Been Assigned"
    sleep 3 # so we don't hit any rate limit
    fi
}

# assign ipv6 address to the vnic
function assign-ipv6-address-range(){
    printf "%s\n" "Assigning IPv6 addresses to the VNIC"
    for i in {1..15}; do
    IPv6="${IPv6PREFIX%/*}1:$(printf "%x\n" $i)";
    oci network vnic assign-ipv6 --vnic-id "$1" --ip-address "$IPv6" --no-retry > /dev/null 2>&1;
    sleep 3 # so we don't hit any rate limit
    check-ipv6-ips "$1" "$i"
    done && \
    printf "%s\n" "IPv6 Addresses Assigned Successfully" || printf "%s\n" "Failed to Assign IPv6 Addresses to the VNIC"
};

# check if ipv6 address is assigned to the subnet
function check-ipv6-subnet(){
    oci network subnet get --subnet-id "$1" --raw-output --query "data.\"ipv6-cidr-block\""
};

# assign ipv6 to subnet
function assign-ipv6-to-subnet(){
    printf "%s\n" "Assigning IPv6 CIDR Block to the Subnet"
    oci network subnet add-ipv6-subnet-cidr --subnet-id "$1" --ipv6-cidr-block "${2%/*}/64" && \
    printf "%s\n" "IPv6 CIDR Block Assigned to the Subnet" || printf "%s\n" "Failed to Assign IPv6 CIDR Block to the Subnet"
};

# add ipv4 and ipv6 internet routes
function add-ipv4-ipv6-internet-route(){
    printf "%s\n" "Adding IPv4 and IPv6 Internet Routes";
    oci network route-table update --rt-id "$1" --route-rules "[{
        \"cidr-block\": null,
        \"description\": \"IPv4 Internet\",
        \"destination\": \"0.0.0.0/0\",
        \"destination-type\": \"CIDR_BLOCK\",
        \"network-entity-id\": \"$2\",
        \"route-type\": \"STATIC\"
        },
        {
        \"cidr-block\": null,
        \"description\": \"IPv6 Internet\",
        \"destination\": \"::/0\",
        \"destination-type\": \"CIDR_BLOCK\",
        \"network-entity-id\": \"$2\",
        \"route-type\": \"STATIC\"
}]" --force > /dev/null 2>&1 && \
    printf "%s\n" "IPv4 and IPv6 Internet Routes Added" || printf "%s\n" "Failed to Add IPv4 and IPv6 Internet Routes";
};
# get current egress security list rules
# oci network security-list list --compartment-id $COMPARTMENT_ID --vcn-id $VCN_ID --raw-output --query "data[].\"egress-security-rules\" | [0]";

# update egress security list rules
function update-egress-security-list(){
    printf "%s\n" "Updating Egress Security List Rules"
    oci network security-list update --security-list-id "$1" --egress-security-rules "${2%\]*},{
        \"description\": null,
        \"destination\": \"::/0\",
        \"destination-type\": \"CIDR_BLOCK\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"all\",
        \"tcp-options\": null,
        \"udp-options\": null
    }]" --force > /dev/null 2>&1 && \
    printf "%s\n" "Egress Security List Rules Updated" || printf "%s\n" "Failed to Update Egress Security List Rules";
};

# update ingress security list rules
function update-ingress-security-list(){
    printf "%s\n" "Updating Ingress Security List Rules"
    oci network security-list update --security-list-id "$1" --ingress-security-rules "${2%\]*},{
        \"description\": \"Tailscale IPv4 Direct Connection\",
        \"icmp-options\": null,
        \"is-stateless\": true,
        \"protocol\": \"17\",
        \"source\": \"0.0.0.0/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": null,
        \"udp-options\": {
        \"destination-port-range\": {
            \"max\": 41641,
            \"min\": 41641
        },
        \"source-port-range\": null
        }},
        {
        \"description\": \"Webmin Port\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"6\",
        \"source\": \"0.0.0.0/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": {
        \"destination-port-range\": {
            \"max\": 10000,
            \"min\": 10000
        },
        \"source-port-range\": null
        },
        \"udp-options\": null
        },
        {
        \"description\": \"OpenVPN IPv4 UDP Port\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"6\",
        \"source\": \"0.0.0.0/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": {
        \"destination-port-range\": {
            \"max\": 1194,
            \"min\": 1194
        },
        \"source-port-range\": null
        },
        \"udp-options\": null
        },
        {
        \"description\": \"OpenVPN IPv6 UDP Port\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"6\",
        \"source\": \"::/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": {
        \"destination-port-range\": {
            \"max\": 1194,
            \"min\": 1194
        },
        \"source-port-range\": null
        },
        \"udp-options\": null
        },
        {
        \"description\": \"Temp Netcat TCP Port\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"6\",
        \"source\": \"::/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": {
        \"destination-port-range\": {
            \"max\": 17486,
            \"min\": 17486
        },
        \"source-port-range\": null
        },
        \"udp-options\": null
    }]" --force > /dev/null 2>&1 && \
    printf "%s\n" "Ingress Security List Rules Updated" || printf "%s\n" "Failed to Update Ingress Security List Rules";
};


# -------------------------------------------
# Main Script
# -------------------------------------------
IPv6PREFIX=$(get-ipv6-prefix "$VCN_ID")

# if IPv6PREFIX is empty, then add a new ipv6 cidr block, assign to subnet, and then assign addresses to the vnic
if [[ -z "${IPv6PREFIX}" ]]; then
    printf "%s\n" "IPv6 CIDR Block does not exist"
    add-ipv6-cidr-block "$VCN_ID"
    assign-ipv6-to-subnet "$SUBNET_ID" "$(get-ipv6-prefix "$VCN_ID")"
    assign-ipv6-address-range "$VNIC_ID"
    else
    printf "%s\n" "IPv6 CIDR Block already exists"
    echo "checking if the IPv6 CIDR Block is assigned to the subnet"
    if [ -z "$(check-ipv6-subnet "$SUBNET_ID")" ]; then
        assign-ipv6-to-subnet "$SUBNET_ID" "$(get-ipv6-prefix "$VCN_ID")" && \
        assign-ipv6-address-range "$VNIC_ID";
    else
        printf "%s\n" "IPv6 CIDR Block Already Assigned to the Subnet"
        printf "%s\n" "Assigning IPv6 addresses to the VNIC"
        assign-ipv6-address-range "$VNIC_ID";
    fi
fi

# add ipv4 and ipv6 internet routes
add-ipv4-ipv6-internet-route "$ROUTE_TABLE_ID" "$INTERNET_GATEWAY_ID";

# update egress security list rules
update-egress-security-list "$SECURITY_LIST_ID" "$CURRENT_EGRESS_RULES";

# update ingress security list rules
update-ingress-security-list "$SECURITY_LIST_ID" "$CURRENT_INGRESS_RULES";
cleanup