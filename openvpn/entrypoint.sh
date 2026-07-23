#!/bin/bash
set -e

: "${IP_VPN:=100.64.0.0}"
: "${MASCARA_VPN:=255.255.255.0}"
: "${VPN_PORT:=1194}"
: "${VPN_PROTO:=tcp}"
: "${WG_PORT:=51820}"
: "${WG_SUBNET:=100.65.0.0}"

CCD_DIR=/etc/openvpn/UptimeKuma
SERVER_DIR=/etc/openvpn/server
WG_DIR=/etc/openvpn/wg
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

# Los clientes OpenVPN necesitan saber que la subred WireGuard se alcanza por el
# túnel; sin esto salen por su ruta default y el hub queda asimétrico (WG llega a
# OVPN pero no al revés). Idempotente y fuera del bloque de primer arranque, para
# que los tenants creados antes de WireGuard también lo reciban.
if ! grep -q "^push \"route ${WG_SUBNET} " "$SERVER_DIR/server.conf"; then
    # Borra solo la línea que puso este script antes (marcada con su comentario),
    # nunca otras directivas push que pueda tener el server.conf.
    sed -i '/^# maat-wg-route$/,+1d' "$SERVER_DIR/server.conf"
    printf '# maat-wg-route\npush "route %s 255.255.255.0"\n' "$WG_SUBNET" >> "$SERVER_DIR/server.conf"
    echo "[setup] push route ${WG_SUBNET}/24 agregado a server.conf"
fi

# --- WireGuard (segundo protocolo, mismo netns que OpenVPN y Uptime Kuma) ---
# Los peers WG conviven con los clientes OpenVPN en el mismo hub: Kuma alcanza a
# ambos igual. La config de wg0 (wg0.conf, formato `wg setconf`) la genera el panel
# desde la DB; acá solo se crea la interfaz y se aplica lo que haya.
mkdir -p "$WG_DIR"
chmod 700 "$WG_DIR"

if [ ! -s "$WG_DIR/server.key" ]; then
    echo "[init-wg] Generando keypair del servidor WireGuard..."
    umask 077
    wg genkey > "$WG_DIR/server.key"
    wg pubkey < "$WG_DIR/server.key" > "$WG_DIR/server.pub"
    umask 022
fi
chmod 600 "$WG_DIR/server.key"
chmod 644 "$WG_DIR/server.pub"

if [ ! -s "$WG_DIR/wg0.conf" ]; then
    # Config mínima sin peers: la interfaz queda arriba y escuchando para que el
    # panel pueda dar de alta usuarios en caliente sin recrear el contenedor.
    umask 077
    printf '[Interface]\nPrivateKey = %s\nListenPort = %s\n' \
        "$(cat "$WG_DIR/server.key")" "$WG_PORT" > "$WG_DIR/wg0.conf"
    umask 022
fi

WG_SERVER_IP="$(echo "$WG_SUBNET" | awk -F. '{print $1"."$2"."$3".1"}')"
WG_OK=0

if ip link add dev wg0 type wireguard 2>/dev/null; then
    echo "[setup-wg] Interfaz wg0 creada con el módulo del kernel."
    WG_OK=1
elif ip link show wg0 >/dev/null 2>&1; then
    echo "[setup-wg] wg0 ya existe (reinicio sin recrear netns)."
    WG_OK=1
elif command -v wireguard-go >/dev/null 2>&1; then
    # El host no tiene el módulo `wireguard` cargado → fallback userspace.
    # Funciona igual pero con menos rendimiento; queda en el log para diagnóstico.
    echo "[setup-wg] AVISO: kernel sin módulo wireguard, usando wireguard-go (userspace)."
    if WG_PROCESS_FOREGROUND=0 wireguard-go wg0 >/dev/null 2>&1 && ip link show wg0 >/dev/null 2>&1; then
        WG_OK=1
    else
        echo "[setup-wg] ERROR: no se pudo levantar wg0 ni en userspace. WireGuard deshabilitado."
    fi
else
    echo "[setup-wg] ERROR: sin módulo kernel ni wireguard-go. WireGuard deshabilitado."
fi

if [ "$WG_OK" = "1" ]; then
    wg setconf wg0 "$WG_DIR/wg0.conf"
    ip addr replace "$WG_SERVER_IP/24" dev wg0
    ip link set wg0 up
    # Rutas de las LAN de cliente: se derivan de los AllowedIPs ya cargados, así
    # sobreviven al reinicio sin depender de otro archivo de estado. Las /32 de los
    # propios peers ya las cubre la ruta de la subred de la interfaz.
    wg show wg0 allowed-ips 2>/dev/null | tr '\t' ' ' | while read -r _ cidrs; do
        for c in $cidrs; do
            case "$c" in
                */32|\(none\)|"") continue ;;
            esac
            ip route replace "$c" dev wg0 2>/dev/null || true
        done
    done
    echo "[setup-wg] wg0 arriba en ${WG_SERVER_IP}/24, escuchando udp/${WG_PORT}."
fi

echo "[setup] IP forwarding + NAT on tun0..."
echo 1 > /proc/sys/net/ipv4/ip_forward || true

iptables -t nat -C POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE
iptables -t nat -C POSTROUTING -o wg0 -j MASQUERADE 2>/dev/null || \
    iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE

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

# Mismo aislamiento para wg0 + hub cruzado tun0<->wg0 (un Mikrotik en OpenVPN debe
# poder alcanzar la LAN detrás de un peer WireGuard del mismo tenant y viceversa).
# Los ACCEPT se INSERTAN al tope (-I) para que queden por delante de los DROP que ya
# se agregaron arriba, sin depender del orden histórico de la cadena.
echo "[setup] Aislamiento de red (FORWARD/INPUT desde wg0)..."
iptables -C FORWARD -i wg0 -j DROP 2>/dev/null || \
    iptables -A FORWARD -i wg0 -j DROP
iptables -C INPUT -i wg0 -j DROP 2>/dev/null || \
    iptables -A INPUT -i wg0 -j DROP
for pair in "wg0 wg0" "wg0 tun0" "tun0 wg0"; do
    set -- $pair
    iptables -C FORWARD -i "$1" -o "$2" -j ACCEPT 2>/dev/null || \
        iptables -I FORWARD -i "$1" -o "$2" -j ACCEPT
done
iptables -C INPUT -i wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -i wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -C INPUT -i wg0 -p icmp -j ACCEPT 2>/dev/null || \
    iptables -I INPUT -i wg0 -p icmp -j ACCEPT

# Aislamiento de EGRESS del contenedor. Uptime Kuma comparte este netns
# (network_mode: service:openvpn), así que hereda el uplink (eth0) y su ruta por
# defecto hacia el gateway de Docker → host → redes internas del host. Sin filtrar,
# Kuma alcanza redes privadas del host (p.ej. 10.0.3.x) que NO debe ver.
# Bloqueamos lo que el contenedor ORIGINA hacia rangos privados por el uplink:
# - las redes de CLIENTE van por tun0/wg0 (no el uplink) → NO se ven afectadas;
# - internet (destino público) tampoco se ve afectado;
# - se permite el retorno de conexiones ya establecidas (respuestas a clientes VPN
#   que entran por el uplink), para no romper el propio VPN.
# Defensa en profundidad: SSH (y la gestión de estos contenedores) NUNCA accesible
# desde un cliente VPN. El aislamiento INPUT/FORWARD de arriba ya DROPea todo acceso
# de un cliente al contenedor y al host; esto lo hace EXPLÍCITO para tcp/22 por si a
# futuro se afloja alguna regla, y protege ante un MikroTik/cliente comprometido que
# quiera pivotar a donde corre todo. NO afecta el SSH cliente↔cliente entre sitios
# (eso pasa por el hub en FORWARD, no por INPUT).
echo "[setup] Bloqueo explícito de SSH al contenedor desde clientes VPN (tun0/wg0)..."
for IFACE in tun0 wg0; do
    iptables -C INPUT -i "$IFACE" -p tcp --dport 22 -j DROP 2>/dev/null || \
        iptables -I INPUT -i "$IFACE" -p tcp --dport 22 -j DROP
done

echo "[setup] Aislamiento de egress (OUTPUT del contenedor hacia redes privadas del host)..."
UPLINK="$(ip route show default 2>/dev/null | awk '{print $5; exit}')"
UPLINK="${UPLINK:-eth0}"
iptables -C OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
    iptables -I OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -C OUTPUT -o "$UPLINK" -d "$net" -j DROP 2>/dev/null || \
        iptables -A OUTPUT -o "$UPLINK" -d "$net" -j DROP
done

echo "[run] Starting OpenVPN on ${VPN_PROTO}/${VPN_PORT} with tunnel ${IP_VPN}/${MASCARA_VPN}..."
cd "$SERVER_DIR"
exec openvpn --config server.conf --suppress-timestamps
