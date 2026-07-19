#!/bin/bash
set -e

: "${IP_VPN:=100.64.0.0}"
: "${MASCARA_VPN:=255.255.255.0}"
: "${VPN_PORT:=1194}"
: "${VPN_PROTO:=tcp}"

CCD_DIR=/etc/openvpn/UptimeKuma
SERVER_DIR=/etc/openvpn/server
PLUGIN_PATH=/usr/lib/x86_64-linux-gnu/openvpn/plugins/openvpn-plugin-auth-pam.so

mkdir -p "$CCD_DIR" /etc/openvpn/tmp "$SERVER_DIR"
chmod 777 /etc/openvpn/tmp

# Persistencia de usuarios PAM: restaurar /etc/{passwd,shadow,group,gshadow}
# desde el volumen para que sobrevivan recreaciones del contenedor.
AUTH_DIR=/etc/openvpn/auth
mkdir -p "$AUTH_DIR"
for f in passwd shadow group gshadow; do
    if [ -s "$AUTH_DIR/$f" ]; then
        cp "$AUTH_DIR/$f" "/etc/$f"
    fi
done
chmod 644 /etc/passwd /etc/group 2>/dev/null || true
chmod 640 /etc/shadow /etc/gshadow 2>/dev/null || true

if [ ! -s "$CCD_DIR/rutas.sh" ]; then
    echo "#!/bin/sh" > "$CCD_DIR/rutas.sh"
    chmod 0755 "$CCD_DIR/rutas.sh"
fi

if [ ! -f "$SERVER_DIR/server.conf" ]; then
    echo "[init] First run: generating PKI and server config..."

    EASY_RSA_DIR=/etc/openvpn/easy-rsa
    rm -rf "$EASY_RSA_DIR"
    mkdir -p "$EASY_RSA_DIR"
    cp -r /usr/share/easy-rsa/* "$EASY_RSA_DIR/"
    cd "$EASY_RSA_DIR"
    echo "set_var EASYRSA_KEY_SIZE 2048" > vars

    SERVER_CN="cn_$(head /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1)"
    SERVER_NAME="server"

    ./easyrsa init-pki
    EASYRSA_CA_EXPIRE=3650 ./easyrsa --batch --req-cn="$SERVER_CN" build-ca nopass
    EASYRSA_CERT_EXPIRE=3650 ./easyrsa --batch build-server-full "$SERVER_NAME" nopass
    EASYRSA_CRL_DAYS=3650 ./easyrsa gen-crl
    openssl dhparam -out dh.pem 2048

    cp pki/ca.crt pki/private/ca.key \
       "pki/issued/$SERVER_NAME.crt" "pki/private/$SERVER_NAME.key" \
       pki/crl.pem dh.pem "$SERVER_DIR/"
    chmod 644 "$SERVER_DIR/crl.pem"
    chmod o+x "$SERVER_DIR"

    openvpn --genkey secret "$SERVER_DIR/tc.key"

    cat > "$SERVER_DIR/server.conf" <<EOF
port ${VPN_PORT}
proto ${VPN_PROTO}
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
auth SHA1
verify-client-cert none
username-as-common-name
tmp-dir /etc/openvpn/tmp
plugin ${PLUGIN_PATH} openvpn
script-security 2
up /etc/openvpn/UptimeKuma/rutas.sh
explicit-exit-notify 0
client-config-dir /etc/openvpn/UptimeKuma
topology subnet
server ${IP_VPN} ${MASCARA_VPN}
keepalive 10 120
data-ciphers AES-256-CBC
data-ciphers-fallback AES-256-CBC
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
crl-verify crl.pem
EOF

    echo "[init] Done."
fi

echo "[setup] IP forwarding + NAT on tun0..."
echo 1 > /proc/sys/net/ipv4/ip_forward || true

iptables -t nat -C POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE

# --- Aislamiento de red del tenant ---
# Los clientes VPN SOLO pueden hablar entre sí dentro del túnel (hub: cliente↔cliente
# y LAN Mikrotik del mismo tenant). Se BLOQUEA cualquier salida del túnel hacia el
# host, internet, otros tenants o la red del servidor → evita pivoteo y accesos
# SSH/Telnet/SNMP/etc. contra el server. NO afecta a Uptime Kuma: comparte el netns
# del contenedor y su tráfico de monitoreo es local (OUTPUT/INPUT), no FORWARD.
# Idempotente (-C || -A).
echo "[setup] Aislamiento de red (FORWARD/INPUT desde tun0)..."
# retorno de conexiones ya establecidas (necesario para el hub y para Kuma)
iptables -C FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# tráfico intra-túnel permitido (cliente↔cliente, LAN Mikrotik)
iptables -C FORWARD -i tun0 -o tun0 -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i tun0 -o tun0 -j ACCEPT
# todo lo demás que entre por el túnel y quiera SALIR del túnel → DROP
iptables -C FORWARD -i tun0 -j DROP 2>/dev/null || \
    iptables -A FORWARD -i tun0 -j DROP
# proteger el propio contenedor desde el túnel: solo established + ICMP (ping gw)
iptables -C INPUT -i tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -i tun0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C INPUT -i tun0 -p icmp -j ACCEPT 2>/dev/null || \
    iptables -A INPUT -i tun0 -p icmp -j ACCEPT
iptables -C INPUT -i tun0 -j DROP 2>/dev/null || \
    iptables -A INPUT -i tun0 -j DROP

echo "[run] Starting OpenVPN on ${VPN_PROTO}/${VPN_PORT} with tunnel ${IP_VPN}/${MASCARA_VPN}..."
cd "$SERVER_DIR"
exec openvpn --config server.conf --suppress-timestamps
