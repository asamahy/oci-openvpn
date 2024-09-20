#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
# shellcheck disable=SC2086,SC2059,SC2016,SC2001
set -e
timedatectl set-timezone Universal

INSTALL_WEBMIN="false";
INSTANCE_NAME="CHANGE_ME";
CHANGE_PASSWORDS="true";
UBUNTU_PASSWORD="CHANGE_ME";
ROOT_PASSWORD="CHANGE_ME";
export PI_HOLE_PASSWORD="CHANGE_ME";
route=$(ip route get 8.8.8.8)
INSTANCE_IPv4="$(printf ${route#*src })";
export INSTANCE_IPv4
VPN_SERVER_IP="$(curl -s -4 ifconfig.io)"; # change to domain name if you have one
DNS_SERVER_1="$INSTANCE_IPv4"
export VPN_NET_IP="10.50.0.0";
VPN_NET_MASK="255.255.255.0";
export VPN_CIDR="24";
VPN_PORT="1194";
VPN_PROTOCOL="udp";
VPN_CIPHER="AES-256-CBC";
HMAC_ALG="SHA512";

if [ -f /root/.provisioned1 ]; then
    printf "%s\n" "Part 1 has been run before, skipping..."
    else
update_openssl_conf() {
    local conf_file=$1
    sed -i \
    -e 's/^\(default_days\s*=\s*\)[^#[:space:]]*/\13650/' \
    -e 's/^\(default_crl_days\s*=\s*\)[^#[:space:]]*/\13650/' \
    -e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' "$conf_file"
};
add_iptables_rule() {
    local port=$1
    local protocol=$2
    local description=$3
    iptables -I INPUT $((++rule_number)) -p "$protocol" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT && \
    printf "%s\n" "$description rule added" || printf "%s\n" "Failed to add $description rule"
    sh -c 'iptables-save > /etc/iptables/rules.v4' && sh -c 'iptables-restore < /etc/iptables/rules.v4' && \
    printf "%s\n" "Firewall rules saved and enabled" || printf "%s\n" "Failed to enable saved and Firewall rules"
};
printf "%s\n" "Part 1: System Update and Tools Installation"
apt-get update -qq && apt-get upgrade -qqy 
apt-get install net-tools nano rand apt-utils dialog iputils-ping dnsutils openvpn cron -qqy
openssl rand -writerand /root/.rnd -out /dev/null
sed -i \
-e 's/^#\(net.ipv4.ip_forward=\)\([0-1]\)/\11/' \
-e 's/^#\(net.ipv6.conf.all.forwarding=\)\([0-1]\)/\11/' /etc/sysctl.conf
update_openssl_conf "/etc/ssl/openssl.cnf"
if [ "$INSTALL_WEBMIN" == "true" ]; then
    bash -c "$(curl -sSL  https://raw.githubusercontent.com/webmin/webmin/master/setup-repos.sh)" -- --force
    apt-get install webmin --install-recommends -y
    update_openssl_conf "/usr/share/webmin/acl/openssl.cnf"
    curl -sSL -o openvpn.wbm.gz https://github.com/asamahy/webmin-openvpn-debian-jessie/raw/master/openvpn.wbm.gz
    /usr/share/webmin/install-module.pl openvpn.wbm.gz && rm -f openvpn.wbm.gz
    add_iptables_rule 10000 tcp "Webmin"
fi
rule_number=$(iptables -L INPUT --line-numbers | grep -E 'ACCEPT.*dpt:ssh' | awk '{print $1}')
iptables -L FORWARD --line-numbers | \
grep -E 'reject-with.*icmp-host-prohibited' | \
awk '{print $1}' | xargs -I {} iptables -D FORWARD {}
iptables -t nat -A POSTROUTING -s "${VPN_NET_IP}/${VPN_CIDR}" -o ens3 -j SNAT --to-source "$INSTANCE_IPv4"
add_iptables_rule $VPN_PORT $VPN_PROTOCOL "OpenVPN"
touch /root/.provisioned1 && printf "\n%s\n" "Part 1 completed successfully";
fi

if [ -f /root/.provisioned2 ]; then
    printf "%s\n" "Part 2 has been run before, skipping..."
    else
printf "%s\n" "Part 2: OCI-CLI Installation and Configuration"

bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)" -- --accept-all-defaults
/root/bin/oci --version

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
printf "%s\n" "Part 3: Assigning IPv6 Address to VNIC"

if [ "$(command -v /root/bin/oci)" ]; then
    if [ "$INSTANCE_NAME" == "CHANGE_ME" ]; then
        printf "%s\n" "INSTANCE_NAME is set to script default, Exiting..."
        exit 1
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

function get-ipv6-prefix(){
    /root/bin/oci network vcn get --vcn-id "$1" --raw-output --query "data.\"ipv6-cidr-blocks\" | [0]";
};
function add-ipv6-cidr-block(){
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
    /root/bin/oci network subnet add-ipv6-subnet-cidr --subnet-id "$1" --ipv6-cidr-block "${2%/*}/64" > /dev/null 2>&1 && \
    printf "%s\n" "IPv6 CIDR Block Assigned to the Subnet" || printf "%s\n" "Failed to Assign IPv6 CIDR Block to the Subnet"
};
function add-ipv4-ipv6-internet-route(){
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
function update-security-list() {
    CURRENT_INGRESS_RULES='/root/bin/oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[].\"ingress-security-rules\"| [0]"';
    CURRENT_EGRESS_RULES='/root/bin/oci network security-list list --compartment-id "$COMPARTMENT_ID" --vcn-id "$VCN_ID" --raw-output --query "data[].\"egress-security-rules\"| [0]"';

    local security_list_id="$1"
    local description="$2"
    local icmp_options="$3"
    local is_stateless="$4"
    local protocol="$5"
    local source_or_dest="$6"
    local source_or_dest_type="$7"
    local sport="$8"
    local dport="$9"
    local rule_type="${10}"
    local proto=""
    local sport_range=""
    local BASE_RULES=""
    local JSON_REQUEST=""
    local tcp_port_options=""
    local udp_port_options=""
    local port_options=""

    { [[ -n "$sport" ]] && sport_range="{\"max\": ${sport//\"/}, \"min\": ${sport//\"/}}" && \
    JSON_REQUEST="$(echo "$JSON_REQUEST" | sed -e "s/\(\"source-port-range\":\s*\)\([^\",}]*\)/\1$sport_range/")"; } || \
    { [[ -z "$sport" ]] && sport_range="null" && \
    JSON_REQUEST="$(echo "$JSON_REQUEST" | sed -e "s/\(\"source-port-range\":\s*\)\([^\",}]*\)/\1$sport_range/")"; }

    { [[ -n "$dport" ]] && dport_range="{\"max\": ${dport//\"/}, \"min\": ${dport//\"/}}" && \
    JSON_REQUEST="$(echo "$JSON_REQUEST" | sed -e "s/\(\"source-port-range\":\s*\)\([^\",}]*\)/\1$dport_range/")"; } || \
    { [[ -z "$dport" ]] && dport_range="null" && \
    JSON_REQUEST="$(echo "$JSON_REQUEST" | sed -e "s/\(\"source-port-range\":\s*\)\([^\",}]*\)/\1$dport_range/")"; }

    local port_options="{\"destination-port-range\": ${dport_range}, \"source-port-range\": ${sport_range}}"

    { [[ "${protocol,,}" == "tcp" ]] && \
    { [[ -n $dport ]] || [[ -n $sport ]];} && \
    udp_port_options="null" && proto="6" && tcp_port_options=${port_options}; } || \
    { [[ "${protocol,,}" == "all" ]] && proto="all" && udp_port_options="null" && tcp_port_options="null"; } || \
    { [[ "${protocol,,}" == "udp" ]] && \
    { [[ -n $dport ]] || [[ -n $sport ]];} && \
    tcp_port_options="null" && proto="17" && udp_port_options=${port_options}; } || \
    { printf "%s\n" "Check your Request, Something is wrong."; return 1; }

    local JSON_REQUEST="{\"description\": \"$description\", \"destination\": \"$source_or_dest\", \"destination-type\": \"${source_or_dest_type:=CIDR_BLOCK}\", \"icmp-options\": ${icmp_options:="null"}, \"is-stateless\": $is_stateless, \"protocol\": \"$proto\", \"tcp-options\": $tcp_port_options, \"udp-options\": $udp_port_options}"
    { [[ "${rule_type,,}" == "ingress" ]] && BASE_RULES="$(eval "${CURRENT_INGRESS_RULES}")" && JSON_REQUEST="${JSON_REQUEST/destination/source}" && JSON_REQUEST="${JSON_REQUEST/destination-type/source-type}"; } || \
    { [[ "${rule_type,,}" == "egress" ]] && BASE_RULES="$(eval "${CURRENT_EGRESS_RULES}")"; } || \
    { printf "%s\n" "Invalid Rule Type"; return 1; }

    /root/bin/oci network security-list update --security-list-id "$security_list_id" --"${rule_type}"-security-rules "${BASE_RULES%\]},${JSON_REQUEST}]" > /dev/null --force && \
    printf "%s: %s\n" "Security List Updated Successfully for ${rule_type^^}" "$description" || \
    printf "%s: %s\n" "Failed to Update Security List for ${rule_type^^}" "$description"
}

function check-and-assign(){
    if [ -z "$(check-ipv6-subnet "$SUBNET_ID")" ]; then
        assign-ipv6-to-subnet "$SUBNET_ID" "$(get-ipv6-prefix "$VCN_ID")" && \
        sleep 5 && \
        assign-ipv6-address-range "$VNIC_ID";
    else
        printf "%s\n" "IPv6 CIDR Block Already Assigned to the Subnet"
        assign-ipv6-address-range "$VNIC_ID";
    fi
};
IPv6PREFIX=$(get-ipv6-prefix "$VCN_ID")
if [[ -z "${IPv6PREFIX}" ]]; then
    printf "%s\n" "IPv6 CIDR Block does not exist"
    add-ipv6-cidr-block "$VCN_ID"
    sleep 5
    check-and-assign
    else
    printf "%s\n" "IPv6 CIDR Block already exists"
    check-and-assign
fi
add-ipv4-ipv6-internet-route "$ROUTE_TABLE_ID" "$INTERNET_GATEWAY_ID";
update-security-list "$SECURITY_LIST_ID" "Allow Traffic for IPv6 ports" "null" "false" "all" "::/0" "CIDR_BLOCK" "" "" "egress"
[[ "$INSTALL_WEBMIN" == "true" ]] && update-security-list "$SECURITY_LIST_ID" "Webmin Port" "null" "false" "TCP" "0.0.0.0/0" "CIDR_BLOCK" "" "10000" "ingress"
update-security-list "$SECURITY_LIST_ID" "OpenVPN UDP IPv4 Port" "null" "false" "UDP" "0.0.0.0/0" "CIDR_BLOCK" "" "1194" "ingress"
update-security-list "$SECURITY_LIST_ID" "OpenVPN UDP IPv6 Port" "null" "false" "UDP" "::/0" "CIDR_BLOCK" "" "1194" "ingress"
update-security-list "$SECURITY_LIST_ID" "Tailscale IPv4 Direct Connection" "null" "true" "UDP" "0.0.0.0/0" "CIDR_BLOCK" "" "1194" "ingress"
dhclient -6 && ping6 -c 1 google.com
fi # oci-cli check
touch /root/.provisioned3 && printf "\n%s\n" "Part 3 completed successfully";
fi

if [ -f /root/.provisioned4 ]; then
    printf "%s\n" "Part 4 has been run before, skipping..."
    else
printf "%s\n" "Part 4: OpenVPN Server Configuration"
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
[[ "$INSTALL_WEBMIN" == "true" ]] && cp /usr/share/webmin/openvpn/openvpn-ssl.cnf /etc/openvpn/ || \
curl -sSL https://github.com/asamahy/webmin-openvpn-debian-jessie/raw/master/openvpn.wbm.gz | tar zxvf - "openvpn/openvpn-ssl.cnf" -O > /etc/openvpn/openvpn-ssl.cnf 2> /dev/null
sed \
-e 's/^\(database\s*=\s*\)[^#[:space:]]*/\1\$dir\/\$ENV::CA_NAME\/index.txt/' \
-e 's/^\(serial\s*=\s*\)[^#[:space:]]*/\1\$dir\/\$ENV::CA_NAME\/serial/' \
/etc/openvpn/openvpn-ssl.cnf > /etc/openvpn/openvpn-ssl-mod.cnf

mkdir -p ${KEY_DIR}/${CA_NAME} > /dev/null
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
" > /dev/null

openssl dhparam -out "${KEY_DIR}/${CA_NAME}/dh${KEY_SIZE}.pem" "$KEY_SIZE" > /dev/null 2>&1 && \
printf "%s\n" "Deffie-Hellman key created" || { printf "%s\n" "Failed to create Deffie-Hellman key" && exit 1; }
touch "${KEY_DIR}/${CA_NAME}/index.txt"
echo 01 > "${KEY_DIR}/${CA_NAME}/serial"

/usr/bin/openssl req -batch -days 3650 -nodes -new -x509 \
-keyout "${KEY_DIR}/${CA_NAME}/ca.key" \
-out "${KEY_DIR}/${CA_NAME}/ca.crt" \
-config /etc/openvpn/openvpn-ssl.cnf > /dev/null 2>&1
/usr/bin/openssl ca -gencrl \
-keyfile "${KEY_DIR}/${CA_NAME}/ca.key" \
-cert "${KEY_DIR}/${CA_NAME}/ca.crt" \
-out "${KEY_DIR}/${CA_NAME}/crl.pem" \
-config /etc/openvpn/openvpn-ssl-mod.cnf > /dev/null

cat "${KEY_DIR}/${CA_NAME}"/ca.crt "${KEY_DIR}/${CA_NAME}"/ca.key \
> "${KEY_DIR}/${CA_NAME}"/ca.pem

export KEY_CN="${KEY_CN}_server"

openssl req -newkey rsa:"${KEY_SIZE}" -days 3650 -batch -nodes \
-keyout "$KEY_DIR/${CA_NAME}/${KEY_CN}.key" \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-extensions server \
-config /etc/openvpn/openvpn-ssl.cnf > /dev/null 2>&1
openssl ca -days 3650 -batch \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.crt" \
-in "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-keyfile "$KEY_DIR/${CA_NAME}/ca.key" \
-cert "$KEY_DIR/${CA_NAME}/ca.crt" \
-extensions server \
-config /etc/openvpn/openvpn-ssl-mod.cnf > /dev/null

mv "$KEY_DIR"/*.pem "$KEY_DIR/${CA_NAME}"/ > /dev/null 
bash -c "echo -e 'Do not remove this file. It will be used from webmin OpenVPN Administration interface.' \
> "$KEY_DIR/${CA_NAME}/${KEY_CN}".server" > /dev/null

export KEY_CN="${KEY_CN%_server}_client"

openssl req -newkey rsa:"${KEY_SIZE}" -days 3650 -batch -nodes \
-keyout "$KEY_DIR/${CA_NAME}/${KEY_CN}.key" \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-config /etc/openvpn/openvpn-ssl.cnf > /dev/null
openssl ca -days 3650 -batch \
-out "$KEY_DIR/${CA_NAME}/${KEY_CN}.crt" \
-in "$KEY_DIR/${CA_NAME}/${KEY_CN}.csr" \
-keyfile "$KEY_DIR/${CA_NAME}/ca.key" \
-cert "$KEY_DIR/${CA_NAME}/ca.crt" \
-config /etc/openvpn/openvpn-ssl-mod.cnf > /dev/null 2>&1

mv "$KEY_DIR"/*.pem "$KEY_DIR/${CA_NAME}"/

export KEY_CN="${KEY_CN%_client}"

IPv6PREFIX=$(get-ipv6-prefix "$VCN_ID");
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
push \"redirect-gateway def1 bypass-dhcp\"
push \"route-ipv6 2000::/3\"
EOF
"

printf "%s\n" "Creating the clients & servers directories"
mkdir -p /etc/openvpn/servers/${KEY_CN}/{bin,ccd,logs} "/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client"
touch "/etc/openvpn/servers/${KEY_CN}/ccd/${KEY_CN}_client" \
"/etc/openvpn/servers/${KEY_CN}/logs/openvpn-status.log" \
"/etc/openvpn/servers/${KEY_CN}/logs/openvpn.log"

cp "$KEY_DIR/$CA_NAME"/{ca.crt,"${KEY_CN}"_client.crt,"${KEY_CN}"_client.key} \
"/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/"
printf "%s\n" "Creating the tls-crypt-v2 key"
/usr/sbin/openvpn --genkey tls-crypt-v2-server /etc/openvpn/tls-crypt-v2.key > /dev/null
printf "%s\n" "Creating the tls-crypt-v2 key for the client"
/usr/sbin/openvpn --tls-crypt-v2 /etc/openvpn/tls-crypt-v2.key \
--genkey tls-crypt-v2-client /etc/openvpn/tls-crypt-v2-client.key > /dev/null
TLS_CRYPT_V2_CLIENT_KEY=$(</etc/openvpn/tls-crypt-v2-client.key)
CA=$(<"/etc/openvpn/keys/${CA_NAME}/ca.crt")
CLIENT_CERT=$(<"/etc/openvpn/keys/${CA_NAME}/${KEY_CN}_client.crt")
CLIENT_KEY=$(<"/etc/openvpn/keys/${CA_NAME}/${KEY_CN}_client.key")

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
"
sed \
-e '/^\(user root\)/d' \
-e '/^\(group root\)/d' \
"/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/${KEY_CN}_client.conf" \
> "/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/${KEY_CN}_client.ovpn"
# either remove the indentation or use the sed 's/^[ \t]*//' to remove the leading whitespace from the here-doc input (<<<)
if [[ "$INSTALL_WEBMIN" != "true" ]];then
    sed -e '/^\(ca ca.crt\)/ {
    r /dev/stdin
    d
    }' \
    -e '/^\(cert\)/d' \
    -e '/^\(key\)/d' \
    "/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client/${KEY_CN}_client.ovpn" <<< "$(echo "<ca>
    ${CA}
    </ca>
    <cert>
    ${CLIENT_CERT}
    </cert>
    <key>
    ${CLIENT_KEY}
    </key>" | sed 's/^[ \t]*//')" > /home/ubuntu/Client_CloudVPN.ovpn
    chown ubuntu:ubuntu /home/ubuntu/Client_CloudVPN.ovpn
    systemctl enable openvpn@${KEY_CN}.service
    systemctl start openvpn@${KEY_CN}.service
    systemctl status openvpn@${KEY_CN}.service > /dev/null
    printf "%s\n" "OpenVPN Server Started Successfully" || printf "%s\n" "Failed to start OpenVPN Server";
fi

touch /root/.provisioned4 && printf "\n%s\n" "Part 4 Done. OpenVPN Server Configuration Completed successfully";
fi

if [ -f /root/.provisioned5 ]; then
    printf "%s\n" "Part 5 has been run before, you are all set"
    else
    printf "%s\n" "Part 5 has not been run before, executing Part 5"
if [ "$CHANGE_PASSWORDS" == "true" ]; then    
printf "%s\n" "Part 5: Changing User Passwords"
            echo -e "${UBUNTU_PASSWORD}\n${UBUNTU_PASSWORD}" | passwd ubuntu > /dev/null
            echo -e "${ROOT_PASSWORD}\n${ROOT_PASSWORD}" | passwd root > /dev/null
else
    printf "%s\n" "CHANGE_PASSWORDS is set to false, skipping..."
fi
    touch /root/.provisioned5
fi
    if [ -f /root/.provisioned1 ] && [ -f /root/.provisioned2 ] && [ -f /root/.provisioned3 ] && [ -f /root/.provisioned4 ] && [ -f /root/.provisioned5 ]; then
        printf "%s\n" "All parts have been completed successfully"
        [[ "$INSTALL_WEBMIN" == "true" ]] && printf "%s\n" "Webmin portal is available @ https://${VPN_SERVER_IP}:10000"
    fi
export rule_number
export -f add_iptables_rule
export -f update-security-list
export SECURITY_LIST_ID
export COMPARTMENT_ID
export VCN_ID
export INSTANCE_IPv4
bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/pihole.sh)"
