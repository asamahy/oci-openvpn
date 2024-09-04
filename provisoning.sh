#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
export DEBIAN_FRONTEND=noninteractive
timedatectl set-timezone Universal

INSTANCE_NAME="CHANGE_ME";
NC_PORT="17486";
NC_PROTOCOL="tcp"; # changes to this will not reflect in OCI security list rules
CHANGE_PASSWORDS="true";
UBUNTU_PASSWORD="CHANGE_ME";
ROOT_PASSWORD="CHANGE_ME";
INSTANCE_IPv4="10.0.0.2";
VPN_SERVER_IP="$(curl -s -4 ifconfig.io)"; # change to domain name if you have one
DNS_SERVER_1="1.1.1.1"
DNS_SERVER_2="8.8.8.8"
VPN_NET_IP="10.50.0.0";
VPN_NET_MASK="255.255.255.0";
VPN_CIDR="24";
VPN_PORT="1194";
VPN_PROTOCOL="udp"; # changes to this will not reflect in OCI security list rules
VPN_CIPHER="AES-256-CBC";
HMAC_ALG="SHA512";

function cleanup(){
printf "%s\n" "Cleaning up temporary files..."
rm -f openvpn.wbm.gz
};

if [ -f /root/.provisioned1 ]; then
    printf "%s\n" "Part 1 has been run before, skipping..."
    else
    printf "%s\n" "Part 1 has not been run before, executing Part 1"

printf "%s\n" "****************************************"
printf "%s\n" "Provisioning Script for Ubuntu 22.04 LTS"
printf "%s\n\n" "****************************************"
printf "%s\n" "Part 1: System Update and Tools Installation"
printf "%s\n" "Updating System"
apt-get update && apt-get upgrade -y && \
printf "%s\n" "System Updated" || printf "%s\n" "Failed to Update System"

printf "%s\n" "Installing Tools"
apt-get install net-tools nano rand apt-utils dialog iputils-ping dnsutils openvpn -y && \
printf "%s\n" "Tools Installed" || printf "%s\n" "Failed to Install Tools"

printf "%s\n" "Generating Random Seed for OpenSSL"
openssl rand -writerand /root/.rnd -out /dev/null && \
printf "%s\n" "Random Seed Generated" || printf "%s\n" "Failed to Generate Random Seed"

printf "%s\n" "Enabling IP Forwarding for IPv4 and IPv6"
sudo sed -i \
-e 's/^#\(net.ipv4.ip_forward=\)\([0-1]\)/\11/' \
-e 's/^#\(net.ipv6.conf.all.forwarding=\)\([0-1]\)/\11/' /etc/sysctl.conf && \
printf "%s\n" "IP Forwarding Enabled" || printf "%s\n" "Failed to Enable IP Forwarding"

printf "%s\n" "Changing default_days, default_crl_days, and default_md in /etc/ssl/openssl.cnf"
sudo sed -i \
-e 's/^\(default_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_crl_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' /etc/ssl/openssl.cnf && \
printf "%s\n" "Successfully Modified openssl.cnf" || printf "%s\n" "Failed to Modify openssl.cnf"

printf "%s\n" "Installing Webmin"
bash -c "$(curl -L  https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh)" -- --force && \
printf "%s\n" "Webmin Repositories Installed" || printf "%s\n" "Failed to Install Webmin Repositories"
apt-get install webmin --install-recommends -y && \
printf "%s\n" "Webmin Installed" || printf "%s\n" "Failed to Install Webmin"

sleep 2

printf "%s\n" "Changing default_days, default_crl_days, and default_md in /usr/share/webmin/acl/openssl.cnf"
sudo sed -i \
-e 's/^\(default_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_crl_days\s*=\s*\)[^#[:space:]]*/\13650/' \
-e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' /usr/share/webmin/acl/openssl.cnf && \
printf "%s\n" "Successfully Modified Webmin openssl.cnf" || printf "%s\n" "Failed to Modify Webmin openssl.cnf"

printf "%s\n" "Installing OpenVPN Webmin Module"
curl -L -o openvpn.wbm.gz https://github.com/nicsure/webmin-openvpn-debian-jessie/raw/master/openvpn.wbm.gz
/usr/share/webmin/install-module.pl openvpn.wbm.gz && \
printf "%s\n" "OpenVPN Webmin Module Installed" || printf "%s\n" "Failed to Install OpenVPN Webmin Module"

sed -i \
-e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' /usr/share/webmin/openvpn/openvpn-ssl.cnf && \
printf "%s\n" "Successfully Modified openvpn-ssl.cnf" || printf "%s\n" "Failed to Modify openvpn-ssl.cnf"

printf "%s\n" "Adding rules to /etc/iptables/rules.v4"
rule_number=$(sudo iptables -L INPUT --line-numbers | grep -E 'ACCEPT.*dpt:ssh' | awk '{print $1}')

printf "%s\n" "Adding Webmin rule"
iptables -I INPUT $((++ rule_number)) -p tcp -m state -m tcp --dport 10000 --state NEW -j ACCEPT && \
printf "%s\n" "Webmin rule added" || printf "%s\n" "Failed to add Webmin rule"

printf "%s\n" "Adding OpenVPN rule"
iptables -I INPUT $((++ rule_number)) -p $VPN_PROTOCOL -m $VPN_PROTOCOL --dport $VPN_PORT -j ACCEPT && \
printf "%s\n" "OpenVPN rule added" || printf "%s\n" "Failed to add OpenVPN rule"

printf "%s\n" "Adding Temp. Netcat rule"
iptables -I INPUT $((++ rule_number)) -p $NC_PROTOCOL -m state -m $NC_PROTOCOL --dport $NC_PORT --state NEW -j ACCEPT && \
printf "%s\n" "Temp. Netcat rule added" || printf "%s\n" "Failed to add Temp. Netcat rule"

printf "%s\n" "Deleting FORWARD rules with reject-with icmp-host-prohibited"
iptables -L FORWARD --line-numbers | \
grep -E 'reject-with.*icmp-host-prohibited' | \
awk '{print $1}' | xargs -I {} iptables -D FORWARD {} && \
printf "%s\n" "Deleted FORWARD rules" || printf "%s\n" "No FORWARD rules found"

iptables -t nat -A POSTROUTING -s "${VPN_NET_IP}/${VPN_CIDR}" -o ens3 -j SNAT --to-source "$INSTANCE_IPv4" && \
printf "%s\n" "NAT POSTROUTING Rules Added" || printf "%s\n" "Failed to Add NAT POSTROUTING Rules"

printf "%s\n" "Saving the Firewall rules"
sh -c 'iptables-save > /etc/iptables/rules.v4' && sh -c 'iptables-restore < /etc/iptables/rules.v4' && \
printf "%s\n" "Firewall rules saved and enabled" || printf "%s\n" "Failed to enable saved and Firewall rules"

touch /root/.provisioned1 && printf "\n%s\n" "Part 1 completed successfully";
fi

if [ -f /root/.provisioned2 ]; then
    printf "%s\n" "Part 2 has been run before, skipping..."
    else
    printf "%s\n" "Part 2 has not been run before, executing Part 2"

printf "%s\n" "****************************************"
printf "%s\n" "Part 2: OCI-CLI Installation and Configuration"
printf "%s\n" "****************************************"

printf "%s\n" "Installing OCI CLI"
bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)" -- --accept-all-defaults
/root/bin/oci --version && printf "%s\n" "OCI CLI installed successfully" || printf "%s\n" "OCI CLI installation failed"

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

touch /root/.provisioned2 && printf "\n%s\n" "Part 2 completed successfully";
fi

if [ -f /root/.provisioned3 ]; then
    printf "%s\n" "Part 3 has been run before, skipping..."
    else
    printf "%s\n" "Part 3 has not been run before, executing Part 3"

printf "%s\n" "****************************************"
printf "%s\n" "Part 3: Assigning IPv6 Address to VNIC"
printf "%s\n" "****************************************"

if [ "$(command -v /root/bin/oci)" ]; then
printf "%s\n" "OCI CLI is Found"
printf "%s\n" "Initializing OCI CLI Environment Variables"
printf "%s\n" "Checking if INSTANCE_NAME have been set or left to default"
    if [ "$INSTANCE_NAME" == "CHANGE_ME" ]; then
        printf "%s\n" "INSTANCE_NAME is set to default, please change it to the actual instance name"
        printf "%s\n" "Exiting..."
        exit 1
        else
        printf "%s\n" "INSTANCE_NAME is set to $INSTANCE_NAME"
        printf "%s\n" "Continuing..."
    fi

COMPARTMENT_ID=$(/root/bin/oci iam compartment list --all --compartment-id-in-subtree true --access-level ACCESSIBLE \
--include-root --raw-output --query "data[?contains(\"id\",'tenancy')].id | [0]");
INSTANCE_ID=$(/root/bin/oci compute instance list --compartment-id "$COMPARTMENT_ID" --display-name "$INSTANCE_NAME" \
--raw-output --query "data[?contains(\"id\",'instance')].id | [0]");
VNIC_ID=$(/root/bin/oci compute instance list-vnics --instance-id "$INSTANCE_ID" \
--raw-output --query "data[?contains(\"id\",'vnic')].id | [0]");
SUBNET_ID=$(/root/bin/oci network vnic get --vnic-id "$VNIC_ID" --raw-output --query "data.\"subnet-id\"");
VCN_ID=$(/root/bin/oci network subnet get --subnet-id "$SUBNET_ID" --raw-output --query "data.\"vcn-id\"");
ROUTE_TABLE_ID=$(/root/bin/oci network route-table list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[?contains(\"id\",'routetable')].id | [0]");
INTERNET_GATEWAY_ID=$(/root/bin/oci network internet-gateway list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[?contains(\"id\",'internetgateway')].id | [0]");
SECURITY_LIST_ID=$(/root/bin/oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[?contains(\"id\",'securitylist')].id | [0]");
CURRENT_INGRESS_RULES="$(/root/bin/oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[].\"ingress-security-rules\"| [0]")";
CURRENT_EGRESS_RULES="$(/root/bin/oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[].\"egress-security-rules\"| [0]")";

function get-ipv6-prefix(){
    /root/bin/oci network vcn get --vcn-id "$1" --raw-output --query "data.\"ipv6-cidr-blocks\" | [0]";
};

function add-ipv6-cidr-block(){
    printf "%s\n" "Adding IPv6 CIDR Block"
    /root/bin/oci network vcn add-ipv6-vcn-cidr --vcn-id "$1" > /dev/null && \
    printf "%s\n" "IPv6 CIDR Block Added" || printf "%s\n" "Failed to Add IPv6 CIDR Block"
};

function check-ipv6-ips(){
    VNIC_ID=$1
    i=$2
    Assigned_IPv6=$(/root/bin/oci network vnic get --vnic-id "$VNIC_ID" --raw-output --query "data.\"ipv6-addresses\" | [ $((i-1)) ]");
    if [[ ${Assigned_IPv6##*:} == $(printf "%x\n" $i) ]]; then
    printf "%s\n" "IPv6 Address $Assigned_IPv6 Has Been Assigned Successfully"
    sleep 3
    else
    printf "%s\n" "IPv6 Address $Assigned_IPv6 Has Not Been Assigned"
    sleep 3
    fi
}

function assign-ipv6-address-range(){
    IPv6PREFIX=$(get-ipv6-prefix "$VCN_ID");
    printf "%s\n" "Assigning IPv6 addresses to the VNIC"
    for i in {1..15}; do
    IPv6="${IPv6PREFIX%/*}1:$(printf "%x\n" $i)";
    /root/bin/oci network vnic assign-ipv6 --vnic-id "$1" --ip-address "$IPv6" --no-retry > /dev/null;
    sleep 3
    check-ipv6-ips "$1" "$i"
    done && \
    printf "%s\n" "IPv6 Addresses Assigned Successfully" || printf "%s\n" "Failed to Assign IPv6 Addresses to the VNIC"
};

function check-ipv6-subnet(){
    /root/bin/oci network subnet get --subnet-id "$1" --raw-output --query "data.\"ipv6-cidr-block\""
};

function assign-ipv6-to-subnet(){
    printf "%s\n" "Assigning IPv6 CIDR Block to the Subnet"
    /root/bin/oci network subnet add-ipv6-subnet-cidr --subnet-id "$1" --ipv6-cidr-block "${2%/*}/64" > /dev/null && \
    printf "%s\n" "IPv6 CIDR Block Assigned to the Subnet" || printf "%s\n" "Failed to Assign IPv6 CIDR Block to the Subnet"
};

function add-ipv4-ipv6-internet-route(){
    printf "%s\n" "Adding IPv4 and IPv6 Internet Routes";
    /root/bin/oci network route-table update --rt-id "$1" --route-rules "[{
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
    }]" --force > /dev/null && \
    printf "%s\n" "IPv4 and IPv6 Internet Routes Added" || printf "%s\n" "Failed to Add IPv4 and IPv6 Internet Routes";
};

function update-egress-security-list(){
    printf "%s\n" "Updating Egress Security List Rules"
    /root/bin/oci network security-list update --security-list-id "$1" --egress-security-rules "${2%\]*},{
        \"description\": null,
        \"destination\": \"::/0\",
        \"destination-type\": \"CIDR_BLOCK\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"all\",
        \"tcp-options\": null,
        \"udp-options\": null
    }]" --force > /dev/null && \
    printf "%s\n" "Egress Security List Rules Updated" || printf "%s\n" "Failed to Update Egress Security List Rules";
};

function update-ingress-security-list(){
    printf "%s\n" "Updating Ingress Security List Rules"
    /root/bin/oci network security-list update --security-list-id "$1" --ingress-security-rules "${2%\]*},{
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
        \"protocol\": \"17\",
        \"source\": \"0.0.0.0/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": null,
        \"udp-options\": {
        \"destination-port-range\": {
            \"max\": \"${VPN_PORT}\",
            \"min\": \"${VPN_PORT}\"
        },
        \"source-port-range\": null
        }
        },
        {
        \"description\": \"OpenVPN IPv4 UDP Port\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"17\",
        \"source\": \"::/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": null,
        \"udp-options\": {
        \"destination-port-range\": {
            \"max\": \"${VPN_PORT}\",
            \"min\": \"${VPN_PORT}\"
        },
        \"source-port-range\": null
        }
        },
        {
        \"description\": \"Temp Netcat TCP Port\",
        \"icmp-options\": null,
        \"is-stateless\": false,
        \"protocol\": \"6\",
        \"source\": \"0.0.0.0/0\",
        \"source-type\": \"CIDR_BLOCK\",
        \"tcp-options\": {
        \"destination-port-range\": {
            \"max\": \"${NC_PORT}\",
            \"min\": \"${NC_PORT}\"
        },
        \"source-port-range\": null
        },
        \"udp-options\": null
    }]" --force > /dev/null && \
    printf "%s\n" "Ingress Security List Rules Updated" || printf "%s\n" "Failed to Update Ingress Security List Rules";
};

function check-and-assign(){
    if [ -z "$(check-ipv6-subnet "$SUBNET_ID")" ]; then
        assign-ipv6-to-subnet "$SUBNET_ID" "$(get-ipv6-prefix "$VCN_ID")" && \
        sleep 5 && \
        assign-ipv6-address-range "$VNIC_ID";
    else
        printf "%s\n" "IPv6 CIDR Block Already Assigned to the Subnet"
        assign-ipv6-address-range "$VNIC_ID";
    fi
}

IPv6PREFIX=$(get-ipv6-prefix "$VCN_ID")

if [[ -z "${IPv6PREFIX}" ]]; then
    printf "%s\n" "IPv6 CIDR Block does not exist"
    add-ipv6-cidr-block "$VCN_ID"
    sleep 5
    check-and-assign
    else
    printf "%s\n" "IPv6 CIDR Block already exists"
    echo "checking if the IPv6 CIDR Block is assigned to the subnet"
    check-and-assign
fi

add-ipv4-ipv6-internet-route "$ROUTE_TABLE_ID" "$INTERNET_GATEWAY_ID";

update-egress-security-list "$SECURITY_LIST_ID" "$CURRENT_EGRESS_RULES";

update-ingress-security-list "$SECURITY_LIST_ID" "$CURRENT_INGRESS_RULES";

dhclient -6 && printf "%s\n" "IPv6 Address Assigned Successfully to VNIC" || printf "%s\n" "Failed to Assign IPv6 Address to VNIC"
ping6 -c 1 google.com > /dev/null && \
printf "%s\n" "IPv6 Connectivity Established" || printf "%s\n" "Failed to Establish IPv6 Connectivity"
fi # oci-cli check

cleanup

touch /root/.provisioned3 && printf "\n%s\n" "Part 3 completed successfully";
fi

if [ -f /root/.provisioned4 ]; then
    printf "%s\n" "Part 4 has been run before, skipping..."
    else
    printf "%s\n" "Part 4 has not been run before, executing Part 4"

printf "%s\n" "****************************************"
printf "%s\n" "Part 4: OpenVPN Server Configuration"
printf "%s\n" "****************************************"

printf "%s\n" "Setting up CA Vars";

export CA_NAME='CloudLabCA'
export KEY_SIZE='2048'
export CA_EXPIRE='3650'
export KEY_CN='CloudLabVPN'
export KEY_CONFIG='/etc/openvpn/openvpn-ssl.cnf'
export KEY_DIR='/etc/openvpn/keys'
export KEY_COUNTRY='FR'
export KEY_PROVINCE='13'
export KEY_CITY='Marseille'
export KEY_ORG='My Org'
export KEY_EMAIL='me@my.org'
export KEY_OU='Cloud Lab'

printf "%s\n" "creating a modified openvpn-ssl.cnf file"
cp /usr/share/webmin/openvpn/openvpn-ssl.cnf /etc/openvpn/
bash -c "sed \
-e 's/^\(database\s*=\s*\)[^#[:space:]]*/\1\$dir\/\$ENV::CA_NAME\/index.txt/' \
-e 's/^\(serial\s*=\s*\)[^#[:space:]]*/\1\$dir\/\$ENV::CA_NAME\/serial/' \
/etc/openvpn/openvpn-ssl.cnf > /etc/openvpn/openvpn-ssl-mod.cnf" > /dev/null && \
printf "%s\n" "Modified openvpn-ssl.cnf file created" || { printf "%s\n" "Failed to create Modified openvpn-ssl.cnf file" && exit 1; }

mkdir -p ${KEY_DIR}/${CA_NAME} > /dev/null && \
printf "%s\n" "CA Directory Created" || { printf "%s\n" "Failed to Create CA Directory" && exit 1; }

bash -c "cat << EOF > ${KEY_DIR}/${CA_NAME}/ca.config
\\\$info_ca = {
CA_NAME=>'${CA_NAME}',
CA_EXPIRE=>'${CA_EXPIRE}',
KEY_SIZE=>'${KEY_SIZE}',
KEY_CONFIG=>'${KEY_CONFIG}',
KEY_DIR=>'${KEY_DIR}',
KEY_COUNTRY=>'${KEY_COUNTRY}',
KEY_PROVINCE=>'${KEY_PROVINCE}',
KEY_CITY=>'${KEY_CITY}',
KEY_ORG=>'${KEY_ORG}',
KEY_EMAIL=>'${KEY_EMAIL}',
KEY_OU=>'${KEY_OU}',
KEY_CN=>'${KEY_CN}',
}
EOF
" > /dev/null && \
printf "%s\n" "CA Webmin Config Created" || { printf "%s\n" "Failed to Create CA Webmin Config" && exit 1; }

printf "%s\n" "Creating the Deffie-Hellman key"
openssl dhparam -out "${KEY_DIR}/${CA_NAME}/dh${KEY_SIZE}.pem" "$KEY_SIZE" > /dev/null 2>&1 && \
printf "%s\n" "Deffie-Hellman key created" || { printf "%s\n" "Failed to create Deffie-Hellman key" && exit 1; }

printf "%s\n" "Creating the Database and Serial files"
bash -c "touch "${KEY_DIR}/${CA_NAME}/index.txt"" && \
printf "%s\n" "Database file created" || { printf "%s\n" "Failed to create Database file" && exit 1; }
bash -c "echo 01 > "${KEY_DIR}/${CA_NAME}/serial"" && \
printf "%s\n" "Serial file created" || { printf "%s\n" "Failed to create Serial file" && exit 1; }

printf "%s\n" "Creating the CA key and certificate"
/usr/bin/openssl req -batch -days 3650 -nodes -new -x509 \
-keyout "${KEY_DIR}/${CA_NAME}/ca.key" \
-out "${KEY_DIR}/${CA_NAME}/ca.crt" \
-config /etc/openvpn/openvpn-ssl.cnf > /dev/null 2>&1 && \
printf "%s\n" "CA key and certificate created" || { printf "%s\n" "Failed to create CA key and certificate" && exit 1; }

printf "%s\n" "Creating the CRL"
/usr/bin/openssl ca -gencrl \
-keyfile "${KEY_DIR}/${CA_NAME}/ca.key" \
-cert "${KEY_DIR}/${CA_NAME}/ca.crt" \
-out "${KEY_DIR}/${CA_NAME}/crl.pem" \
-config /etc/openvpn/openvpn-ssl-mod.cnf > /dev/null && \
printf "%s\n" "CRL created" || { printf "%s\n" "Failed to create CRL" && exit 1; }

printf "%s\n" "Creating the PEM file"
bash -c "cat ${KEY_DIR}/${CA_NAME}/ca.crt ${KEY_DIR}/${CA_NAME}/ca.key \
> ${KEY_DIR}/${CA_NAME}/ca.pem" > /dev/null && \
printf "%s\n" "PEM file created" || { printf "%s\n" "Failed to create PEM file" && exit 1; }

export KEY_CN="${KEY_CN}_server"

printf "%s\n" "Creating the server key and certificate"
openssl req -newkey rsa:"${KEY_SIZE}" -days 3650 -batch -nodes \
-keyout "$KEY_DIR/${CA_NAME}/${KEY_CN}.key" \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-extensions server \
-config /etc/openvpn/openvpn-ssl.cnf > /dev/null 2>&1 && \
printf "%s\n" "Server key and certificate created" || { printf "%s\n" "Failed to create Server key and certificate" && exit 1; }

printf "%s\n" "Signing the server certificate"
openssl ca -days 3650 -batch \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.crt" \
-in "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-keyfile "$KEY_DIR/${CA_NAME}/ca.key" \
-cert "$KEY_DIR/${CA_NAME}/ca.crt" \
-extensions server \
-config /etc/openvpn/openvpn-ssl-mod.cnf && \
printf "%s\n" "Server certificate signed" || { printf "%s\n" "Failed to sign Server certificate" && exit 1; }

mv "$KEY_DIR"/*.pem "$KEY_DIR/${CA_NAME}"/ > /dev/null && \
printf "%s\n" "PEM file moved to CA directory" || { printf "%s\n" "Failed to move PEM file to CA directory" && exit 1; }

bash -c "echo -e 'Do not remove this file. It will be used from webmin OpenVPN Administration interface.' \
> "$KEY_DIR/${CA_NAME}/${KEY_CN}".server" > /dev/null && \
printf "%s\n" "Server key file created" || { printf "%s\n" "Failed to create Server key file" && exit 1; }

export KEY_CN="${KEY_CN%_server}_client"

printf "%s\n" "Creating the client key and certificate"
openssl req -newkey rsa:"${KEY_SIZE}" -days 3650 -batch -nodes \
-keyout "$KEY_DIR/${CA_NAME}/${KEY_CN}.key" \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-config /etc/openvpn/openvpn-ssl.cnf > /dev/null 2>&1 && \
printf "%s\n" "Client key and certificate created" || { printf "%s\n" "Failed to create Client key and certificate" && exit 1; }

printf "%s\n" "Signing the client certificate"
openssl ca -days 3650 -batch \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.crt" \
-in "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-keyfile "$KEY_DIR/${CA_NAME}/ca.key" \
-cert "$KEY_DIR/${CA_NAME}/ca.crt" \
-config /etc/openvpn/openvpn-ssl-mod.cnf > /dev/null && \
printf "%s\n" "Client certificate signed" || { printf "%s\n" "Failed to sign Client certificate" && exit 1; }

mv "$KEY_DIR"/*.pem "$KEY_DIR/${CA_NAME}"/ > /dev/null && \
printf "%s\n" "PEM file moved to CA directory" || { printf "%s\n" "Failed to move PEM file to CA directory" && exit 1; }

export KEY_CN="${KEY_CN%_client}"

IPv6PREFIX=$(get-ipv6-prefix "$VCN_ID");

printf "%s\n" "Creating the server config file"
bash -c "cat << EOF > /etc/openvpn/${KEY_CN}.conf
port ${VPN_PORT}
proto ${VPN_PROTOCOL}
dev tun0
ca keys/${CA_NAME}/ca.crt
cert keys/${CA_NAME}/${KEY_CN}_server.crt
key keys/${CA_NAME}/${KEY_CN}_server.key
dh keys/${CA_NAME}/dh${KEY_SIZE}.pem
topology subnet
server ${VPN_NET_IP} ${VPN_NET_MASK}
crl-verify keys/${CA_NAME}/crl.pem
ifconfig-pool-persist servers/${KEY_CN}/logs/ipp.txt
cipher ${VPN_CIPHER}
user root
group root
status servers/${KEY_CN}/logs/openvpn-status.log
log-append servers/${KEY_CN}/logs/openvpn.log
verb 2
mute 20
max-clients 100
keepalive 10 120
client-config-dir /etc/openvpn/servers/${KEY_CN}/ccd
duplicate-cn
persist-key
persist-tun
float
ccd-exclusive
ifconfig-ipv6 ${IPv6PREFIX%/*}1:1/124 ::
ifconfig-ipv6-pool ${IPv6PREFIX%/*}1:2/124
auth ${HMAC_ALG}
tls-crypt-v2 tls-crypt-v2.key
push \"dhcp-option DNS ${DNS_SERVER_1}\"
push \"dhcp-option DNS ${DNS_SERVER_2}\"
push \"redirect-gateway def1 bypass-dhcp\"
push \"route-ipv6 2000::/3\"
EOF
" > /dev/null && \
printf "%s\n" "Server config file created" || { printf "%s\n" "Failed to create Server config file" && exit 1; }

printf "%s\n" "Creating the servers directories"
mkdir -p /etc/openvpn/servers/"${KEY_CN}"/{bin,ccd,logs} > /dev/null && \
printf "%s\n" "Servers directories created" || { printf "%s\n" "Failed to create Servers directories" && exit 1; }

touch "/etc/openvpn/servers/${KEY_CN}/ccd/${KEY_CN}_client" > /dev/null && \
printf "%s\n" "Client file created" || { printf "%s\n" "Failed to create Client file" && exit 1; }

touch "/etc/openvpn/servers/${KEY_CN}/logs/openvpn-status.log" > /dev/null && \
printf "%s\n" "status file created" || { printf "%s\n" "Failed to create status file" && exit 1; }

touch "/etc/openvpn/servers/${KEY_CN}/logs/openvpn.log" > /dev/null && \
printf "%s\n" "log-append file created" || { printf "%s\n" "Failed to create log-append file" && exit 1; }

printf "%s\n" "Creating the clients directories"
mkdir -p "/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client" > /dev/null && \
printf "%s\n" "Clients directories created" || { printf "%s\n" "Failed to create Clients directories" && exit 1; }

cp "$KEY_DIR/$CA_NAME"/{ca.crt,"${KEY_CN}"_client.crt,"${KEY_CN}"_client.key} \
"/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/" > /dev/null && \
printf "%s\n" "Client files copied" || { printf "%s\n" "Failed to copy Client files" && exit 1; }

printf "%s\n" "Creating the tls-crypt-v2 key"
/usr/sbin/openvpn --genkey tls-crypt-v2-server /etc/openvpn/tls-crypt-v2.key > /dev/null && \
printf "%s\n" "tls-crypt-v2 key created" || { printf "%s\n" "Failed to create tls-crypt-v2 key" && exit 1; }

printf "%s\n" "Creating the tls-crypt-v2 key for the client"
/usr/sbin/openvpn --tls-crypt-v2 /etc/openvpn/tls-crypt-v2.key \
--genkey tls-crypt-v2-client /etc/openvpn/tls-crypt-v2-client.key > /dev/null && \
printf "%s\n" "tls-crypt-v2 key for the client created" || { printf "%s\n" "Failed to create tls-crypt-v2 key for the client" && exit 1; }

TLS_CRYPT_V2_CLIENT_KEY=$(</etc/openvpn/tls-crypt-v2-client.key)

printf "%s\n" "Creating the client config file"
bash -c "cat << EOF > /etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/${KEY_CN}_client.conf
client
proto ${VPN_PROTOCOL}
dev tun
ca ca.crt
cert ${KEY_CN}_client.crt
key ${KEY_CN}_client.key
remote ${VPN_SERVER_IP} ${VPN_PORT}
cipher ${VPN_CIPHER}
user root
group root
verb 2
mute 20
keepalive 10 120
persist-key
persist-tun
float
resolv-retry infinite
nobind
mtu-test
auth ${HMAC_ALG}
<tls-crypt-v2>
${TLS_CRYPT_V2_CLIENT_KEY}
</tls-crypt-v2>
EOF
" > /dev/null && \
printf "%s\n" "Client config file created" || { printf "%s\n" "Failed to create Client config file" && exit 1; }

printf "%s\n" "Creating the ovpn file"
bash -c "sed \
-e '/^\(user root\)/d' \
-e '/^\(group root\)/d' \
/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/${KEY_CN}_client.conf \
> /etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/${KEY_CN}_client.ovpn" > /dev/null && \
printf "%s\n" "ovpn file created" || { printf "%s\n" "Failed to create ovpn file" && exit 1; }

touch /root/.provisioned4 && printf "\n%s\n" "Part 4 Done. OpenVPN Server Configuration Completed successfully";
fi

if [ -f /root/.provisioned5 ]; then
    printf "%s\n" "Part 5 has been run before, you are all set"
    else
    printf "%s\n" "Part 5 has not been run before, executing Part 5"

if [ "$CHANGE_PASSWORDS" == "true" ]; then
    printf "%s\n" "CHANGE_PASSWORDS is set to true, continuing..."
    
printf "%s\n" "****************************************"
printf "%s\n" "Part 5: Changing User Passwords"
printf "%s\n" "****************************************"

    if [ "$UBUNTU_PASSWORD" == "CHANGE_ME" ]; then
            printf "%s\n" "UBUNTU_PASSWORD is set to the script default, please change it to an actual password"
            echo -e "${UBUNTU_PASSWORD}\n${UBUNTU_PASSWORD}" | sudo passwd ubuntu > /dev/null && \
            printf "%s\n" "UBUNTU_PASSWORD is set to for use on Webmin" || printf "%s\n" "Failed to set UBUNTU_PASSWORD"
        else
            printf "%s\n" "Seting the password for the ubuntu"
            echo -e "${UBUNTU_PASSWORD}\n${UBUNTU_PASSWORD}" | sudo passwd ubuntu > /dev/null && \
            printf "%s\n" "UBUNTU_PASSWORD is set to for use on Webmin" || printf "%s\n" "Failed to set UBUNTU_PASSWORD"
    fi

    if [ "$ROOT_PASSWORD" == "CHANGE_ME" ]; then
            printf "%s\n" "ROOT_PASSWORD is set to the script default, please change it to an actual password"
            echo -e "${ROOT_PASSWORD}\n${ROOT_PASSWORD}" | sudo passwd root > /dev/null && \
            printf "%s\n" "ROOT_PASSWORD is set" || printf "%s\n" "Failed to set ROOT_PASSWORD"
        else
            printf "%s\n" "Seting the password for the root"
            echo -e "${ROOT_PASSWORD}\n${ROOT_PASSWORD}" | sudo passwd root > /dev/null && \
            printf "%s\n" "ROOT_PASSWORD is set" || printf "%s\n" "Failed to set ROOT_PASSWORD"
    fi
else
    printf "%s\n" "CHANGE_PASSWORDS is set to false, skipping..."
fi

    touch /root/.provisioned5 && printf "\n%s\n" "Part 5 Done. Passwords Has been successfully (un)changed";

    if [ -f /root/.provisioned1 ] && [ -f /root/.provisioned2 ] && [ -f /root/.provisioned3 ] && [ -f /root/.provisioned4 ] && [ -f /root/.provisioned5 ]; then
        printf "%s\n" "All parts have been completed successfully"
        printf "%s\n" "Webmin portal is available @ https://${VPN_SERVER_IP}:10000"
    fi
fi
