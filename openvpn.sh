#!/usr/bin/env bash
## Provisioning Script for Ubuntu 22.04 LTS
## Author: Amr AlSamahy
## Date: 2024-08-24
## Version: 1.0
## License: GPL-3.0
# shellcheck disable=SC2016,SC2154

# Install OpenVPN
# Required variables:
# - VPN_NET_IP
# - VPN_CIDR
# - INSTANCE_IPv4
# - rule_number
# - VPN_PORT
# - VPN_PROTOCOL
# - SECURITY_LIST_ID
# - COMPARTMENT_ID
# - VCN_ID
# - INSTALL_WEBMIN
# - VPN_CIPHER
# - HMAC_ALG
# - DNS_SERVER_1
# required functions:
# - update_openssl_conf
# - add_iptables_rule
# - update-security-list
# - get-ipv6-prefix
#
set -e
if [[ -f /root/.openvpn ]]; then
    printf "%s\n" "OpenVPN has been installed before, skipping..."
    else
printf "%s\n" "Installing OpenVPN and Server Configuration"
apt-get install rand openvpn -qqy
openssl rand -writerand /root/.rnd -out /dev/null

sed -i \
-e 's/^#\(net.ipv4.ip_forward=\)\([0-1]\)/\11/' \
-e 's/^#\(net.ipv6.conf.all.forwarding=\)\([0-1]\)/\11/' /etc/sysctl.conf

update_openssl_conf "/etc/ssl/openssl.cnf"

iptables -L FORWARD --line-numbers | \
grep -E 'reject-with.*icmp-host-prohibited' | \
awk '{print $1}' | xargs -I {} iptables -D FORWARD {} && \
printf "%s\n" "Removed the default FORWARD rule" || printf "%s\n" "No default FORWARD rule found"
iptables -t nat -A POSTROUTING -s "${VPN_NET_IP}/${VPN_CIDR}" -o ens3 -j SNAT --to-source "$INSTANCE_IPv4" && \
printf "%s\n" "Added the SNAT rule" || printf "%s\n" "Failed to add the SNAT rule"
add_iptables_rule "$VPN_PORT" "$VPN_PROTOCOL" "OpenVPN"


update-security-list "$SECURITY_LIST_ID" "OpenVPN UDP IPv4 Port" "null" "false" "$VPN_PROTOCOL" "0.0.0.0/0" "CIDR_BLOCK" "" "$VPN_PORT" "ingress"
update-security-list "$SECURITY_LIST_ID" "OpenVPN UDP IPv6 Port" "null" "false" "$VPN_PROTOCOL" "::/0" "CIDR_BLOCK" "" "$VPN_PORT" "ingress"

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

curl -sSL https://github.com/asamahy/webmin-openvpn-debian-jessie/raw/master/openvpn.wbm.gz | tar zxvf - "openvpn/openvpn-ssl.cnf" -O > /etc/openvpn/openvpn-ssl.cnf 2> /dev/null
sed \
-e 's/^\(database\s*=\s*\)[^#[:space:]]*/\1\$dir\/\$ENV::CA_NAME\/index.txt/' \
-e 's/^\(serial\s*=\s*\)[^#[:space:]]*/\1\$dir\/\$ENV::CA_NAME\/serial/' \
/etc/openvpn/openvpn-ssl.cnf > /etc/openvpn/openvpn-ssl-mod.cnf

mkdir -p "${KEY_DIR}/${CA_NAME}" > /dev/null
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
printf "%s\n" "Creating the Deffie-Hellman key"
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
mkdir -p /etc/openvpn/servers/"${KEY_CN}"/{bin,ccd,logs} "/etc/openvpn/clients/${KEY_CN}/${KEY_CN}_client"
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
fi
systemctl enable openvpn@"${KEY_CN}".service
systemctl start openvpn@"${KEY_CN}".service > /dev/null && \
printf "%s\n" "OpenVPN Server Started Successfully" || printf "%s\n" "Failed to start OpenVPN Server";
touch /root/.openvpn && printf "\n%s\n" "OpenVPN installation completed successfully";
fi