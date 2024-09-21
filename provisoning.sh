#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
# shellcheck disable=SC2086,SC2059,SC2016,SC2001
set -e
timedatectl set-timezone Universal

# Common Variables
export INSTALL_WEBMIN="false";
export INSTALL_OPENVPN="true";
export INSTALL_PIHOLE="true";
export INSTALL_CLOUDFLARED="false";
export INSTALL_UNBOUND="true";
export INSTALL_TAILSCALE="true";

INSTANCE_NAME="CHANGE_ME";
CHANGE_PASSWORDS="true";
UBUNTU_PASSWORD="CHANGE_ME";
ROOT_PASSWORD="CHANGE_ME";
export PI_HOLE_PASSWORD="CHANGE_ME";
route=$(ip route get 8.8.8.8)
NETDEV=$(echo $route | cut -f 5 -d " ")
INSTANCE_IPv4="$(printf ${route#*src })";
VPN_SERVER_IP="$(curl -s -4 ifconfig.io)"; # change to domain name if you have one
export DNS_SERVER_1="$INSTANCE_IPv4"
export VPN_NET_IP="10.50.0.0";
export VPN_NET_MASK="255.255.255.0";
export VPN_CIDR="24";
export VPN_PORT="1194";
export VPN_PROTOCOL="udp";
export VPN_CIPHER="AES-256-CBC";
export HMAC_ALG="SHA512";
export TAILSCALE_AUTH_KEY="CHANGE_ME";
rule_number=$(iptables -L INPUT --line-numbers | grep -E 'ACCEPT.*dpt:ssh' | awk '{print $1}')

# Common Functions
function update_openssl_conf() {
    local conf_file=$1
    sed -i \
    -e 's/^\(default_days\s*=\s*\)[^#[:space:]]*/\13650/' \
    -e 's/^\(default_crl_days\s*=\s*\)[^#[:space:]]*/\13650/' \
    -e 's/^\(default_md\s*=\s*\)[^#[:space:]]*/\1sha512/' "$conf_file"
};
function add_iptables_rule() {
    local interface=$1
    local port=$2
    local protocol=$3
    local description=$4
    iptables -I INPUT $((++rule_number)) -i "$interface" -p "$protocol" -m conntrack --ctstate NEW --dport "$port" -j ACCEPT && \
    printf "%s\n" "$description rule added" || printf "%s\n" "Failed to add $description rule"
    sh -c 'iptables-save > /etc/iptables/rules.v4' && sh -c 'iptables-restore < /etc/iptables/rules.v4' && \
    printf "%s\n" "Firewall rules saved and enabled" || printf "%s\n" "Failed to enable saved and Firewall rules"
};
function get-ipv4-subnet(){
    /root/bin/oci network subnet get --subnet-id "$1" --raw-output --query "data.\"cidr-block\""
};
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
};
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
};
function initialize-ipv6(){
    if [[ -z "$(get-ipv6-prefix "$VCN_ID")" ]]; then
        printf "%s\n" "IPv6 CIDR Block does not exist"
        add-ipv6-cidr-block "$VCN_ID"
        sleep 5
        check-and-assign
        else
        printf "%s\n" "IPv6 CIDR Block already exists"
        check-and-assign
    fi
};
function install-oci-cli(){
    bash -c "$(curl -L https://raw.githubusercontent.com/oracle/oci-cli/master/scripts/install/install.sh)" -- --accept-all-defaults
    /root/bin/oci --version
};
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
[[ "$INSTANCE_NAME" == "CHANGE_ME" ]] && printf "%s\n" "INSTANCE_NAME is set to script default, Exiting..." && exit 1

printf "%s\n" "Part 1: System Update and Tools Installation"
apt-get update -qq && apt-get dist-upgrade -qqy 
apt-get install net-tools nano apt-utils dialog iputils-ping dnsutils cron -qqy
if [[ -f /root/.oci_installed ]]; then
    printf "%s\n" "OCI CLI has been installed before, skipping..."
    else
    install-oci-cli && configure-oci-cli
    touch /root/.oci_installed && printf "%s\n" "OCI CLI Installation Completed Successfully";
fi
printf "%s\n" "IPv6 Initialization"
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

if [[ -f /root/.ipv6 ]]; then
    printf "%s\n" "IPv6 is already initialized, skipping..."
    else
    initialize-ipv6;
    add-ipv4-ipv6-internet-route "$ROUTE_TABLE_ID" "$INTERNET_GATEWAY_ID";
    update-security-list "$SECURITY_LIST_ID" "Allow Traffic for IPv6 ports" "null" "false" "all" "::/0" "CIDR_BLOCK" "" "" "egress"
    dhclient -6 && ping6 -c 1 google.com
    touch /root/.ipv6 && printf "%s\n" "IPv6 Initialization Completed Successfully";
fi

##############
export rule_number;
export SECURITY_LIST_ID;
export COMPARTMENT_ID;
export VCN_ID;
export VPN_SERVER_IP;
export INSTANCE_IPv4
export SUBNET_ID;
export NETDEV;
export -f add_iptables_rule;
export -f update-security-list;
export -f update_openssl_conf;
export -f get-ipv4-subnet;
export -f get-ipv6-prefix;
###############
[[ "$INSTALL_WEBMIN" == "true" ]] && bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/webmin.sh)"
[[ "$INSTALL_OPENVPN" == "true" ]] && bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/openvpn.sh)"
[[ "$INSTALL_PIHOLE" == "true" ]] && bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/pihole.sh)"
[[ "$INSTALL_CLOUDFLARED" == "true" ]] && bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/cloudflared.sh)"
[[ "$INSTALL_UNBOUND" == "true" ]] && bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/unbound.sh)"
[[ "$INSTALL_TAILSCALE" == "true" ]] && bash -c "$(curl -sSL https://github.com/asamahy/oci-openvpn/raw/main/tailscale.sh)"
###############

if [[ "$CHANGE_PASSWORDS" == "true" ]]; then    
printf "%s\n" "Part 5: Changing User Passwords"
            echo -e "${UBUNTU_PASSWORD}\n${UBUNTU_PASSWORD}" | passwd ubuntu > /dev/null
            echo -e "${ROOT_PASSWORD}\n${ROOT_PASSWORD}" | passwd root > /dev/null
else
    printf "%s\n" "CHANGE_PASSWORDS is set to false, skipping..."
fi
printf "%s\n" "Part 6: Rebooting Instance in 5 seconds"
sleep 5 && reboot