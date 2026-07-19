#!/bin/bash
# KumaVPN one-shot installer
# Uso:
#   sudo ./install.sh                        # instalación normal (preserva .env si existe)
#   sudo RESET=1 ./install.sh                # regenera credenciales admin
#   sudo ADMIN_PASS=miclave ./install.sh     # password admin específico
#   sudo PUBLIC_IP=1.2.3.4 ./install.sh      # forzar IP pública (sin auto-detect)

set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="/opt/kumavpn"

c_red()   { printf "\033[31m%s\033[0m\n" "$*"; }
c_green() { printf "\033[32m%s\033[0m\n" "$*"; }
c_blue()  { printf "\033[34m%s\033[0m\n" "$*"; }
c_step()  { printf "\n\033[1;36m▸ %s\033[0m\n" "$*"; }

# --- Pre-checks ---

if [ "$EUID" -ne 0 ]; then
    c_red "ERROR: ejecutar con sudo o como root"
    exit 1
fi

if ! grep -qiE "debian|ubuntu" /etc/os-release; then
    c_red "ERROR: solo soportado Debian/Ubuntu (detectado: $(grep ^PRETTY_NAME /etc/os-release | cut -d= -f2))"
    exit 1
fi

if [ ! -f "$INSTALL_DIR/docker-compose.yml" ] || [ ! -d "$INSTALL_DIR/openvpn" ] || [ ! -d "$INSTALL_DIR/web" ]; then
    c_red "ERROR: corré desde dentro de la carpeta kumavpn-docker"
    c_red "       (faltan docker-compose.yml / openvpn/ / web/)"
    exit 1
fi

if [ ! -e /dev/net/tun ]; then
    c_red "ERROR: /dev/net/tun no existe — kernel sin TUN/TAP"
    c_red "       en Proxmox: agregar 'features: nesting=1' al LXC y habilitar TUN"
    exit 1
fi

c_blue "════════════════════════════════════════════"
c_blue "  KumaVPN installer"
c_blue "════════════════════════════════════════════"
echo "  Install dir: $INSTALL_DIR"
echo "  Data dir:    $DATA_DIR"

# --- 1. Docker ---

c_step "[1/6] Docker"
if ! command -v docker >/dev/null 2>&1; then
    echo "  Instalando Docker via get.docker.com..."
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh >/dev/null 2>&1
    rm -f /tmp/get-docker.sh
    c_green "  ✓ Docker instalado: $(docker --version)"
else
    c_green "  ✓ Docker presente: $(docker --version)"
fi

if ! docker compose version >/dev/null 2>&1; then
    c_red "  ERROR: 'docker compose' plugin no disponible"
    c_red "  Instalar: apt-get install -y docker-compose-plugin"
    exit 1
fi
c_green "  ✓ Compose: $(docker compose version | head -1)"

# --- 2. Dependencias del script ---

c_step "[2/6] Dependencias"
need_install=()
for pkg in curl openssl; do
    if ! command -v $pkg >/dev/null 2>&1; then
        need_install+=("$pkg")
    fi
done
if [ ${#need_install[@]} -gt 0 ]; then
    echo "  Instalando: ${need_install[*]}"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need_install[@]}"
fi
c_green "  ✓ curl, openssl OK"

# --- 3. Estructura de datos ---

c_step "[3/6] Preparar $DATA_DIR"
mkdir -p "$DATA_DIR/data" "$DATA_DIR/tenants"
c_green "  ✓ Directorios creados"

# --- 4. Build imágenes ---

c_step "[4/6] Build imágenes Docker"
echo "  Building kumavpn/openvpn:latest..."
docker build -t kumavpn/openvpn:latest "$INSTALL_DIR/openvpn" >/dev/null
c_green "  ✓ kumavpn/openvpn:latest"

echo "  Building kumavpn/web:latest..."
docker build -t kumavpn/web:latest "$INSTALL_DIR/web" >/dev/null
c_green "  ✓ kumavpn/web:latest"

echo "  Pre-pull louislam/uptime-kuma:1 (en background)..."
docker pull louislam/uptime-kuma:1 >/dev/null 2>&1 &

# --- 5. Configuración (.env) ---

c_step "[5/6] Configuración (.env)"
ENV_FILE="$INSTALL_DIR/.env"
SHOW_PASS=""

if [ -f "$ENV_FILE" ] && grep -q "^ADMIN_PASSWORD_HASH=." "$ENV_FILE" && [ -z "$RESET" ]; then
    c_green "  ✓ .env existente preservado (RESET=1 ./install.sh para regenerar)"
    PUB=$(grep '^PUBLIC_IP=' "$ENV_FILE" | cut -d= -f2)
    SHOW_PASS="(sin cambios)"
else
    [ -n "$RESET" ] && echo "  RESET activo → regenerando credenciales"
    ADMIN_PASS="${ADMIN_PASS:-$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 20)}"
    # Password por STDIN (no por argv) para que no aparezca en `ps aux`/proc del host.
    HASH=$(printf '%s' "$ADMIN_PASS" | docker run --rm -i kumavpn/web:latest \
        python -c "import bcrypt,sys; print(bcrypt.hashpw(sys.stdin.buffer.read(), bcrypt.gensalt()).decode())")
    HASH_ESC=$(echo "$HASH" | sed 's/\$/\$\$/g')
    SECRET=$(openssl rand -hex 32)
    PUB="${PUBLIC_IP:-$(curl -s -4 --max-time 5 https://ip1.dynupdate.no-ip.com/ 2>/dev/null || hostname -I | awk '{print $1}')}"

    cat > "$ENV_FILE" <<EOF
ADMIN_USER=admin
ADMIN_PASSWORD_HASH=$HASH_ESC
SESSION_SECRET=$SECRET
ADMIN_PORT=8000
# Exposicion del panel. Dev default 127.0.0.1; 0.0.0.0 para acceso directo por IP.
ADMIN_BIND=${ADMIN_BIND:-127.0.0.1}
# Cookie de sesion Secure. 1 cuando el panel se sirve por HTTPS (proxy con TLS).
SECURE_COOKIES=0
# Exposicion de los Uptime Kuma de cada tenant. 127.0.0.1 cierra el wizard sin-auth.
KUMA_BIND=${KUMA_BIND:-0.0.0.0}
PUBLIC_IP=$PUB
VPN_PORT_BASE=1193
KUMA_PORT_BASE=3000
VPN_SUBNET_PREFIX=100.64
DOCKER_SUBNET_PREFIX=172.30
EOF
    chmod 600 "$ENV_FILE"
    SHOW_PASS="$ADMIN_PASS"
    c_green "  ✓ .env generado con credenciales nuevas"
fi

# --- 6. Levantar el panel ---

c_step "[6/6] Levantando panel"
cd "$INSTALL_DIR"
docker compose up -d --remove-orphans 2>&1 | grep -E "Created|Started|Recreated" || true

# Esperar a que responda
for _ in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8000/login" 2>/dev/null | grep -q "200"; then
        c_green "  ✓ Panel respondiendo en http://127.0.0.1:8000"
        break
    fi
done

# --- Resumen final ---

echo ""
c_blue "════════════════════════════════════════════════════════════════"
c_green "  ✓ MonitorMaat instalado correctamente"
c_blue "════════════════════════════════════════════════════════════════"
echo ""
echo "  Panel:    http://$PUB:8000"
echo "  Usuario:  admin"
echo "  Password: $SHOW_PASS"
echo ""
if [ -n "$ADMIN_PASS" ] && [ "$SHOW_PASS" != "(sin cambios)" ]; then
  c_red "  ⚠  IMPORTANTE: Esta password aleatoria NO se vuelve a mostrar."
  c_red "     Guardala ahora. Al primer login el panel te va a OBLIGAR a cambiarla"
  c_red "     por una propia (mínimo 8 caracteres + mayús + minús + número + símbolo)."
fi
echo ""
c_blue "  Comandos útiles:"
echo "    docker logs -f kumavpn-web                              # logs del panel"
echo "    docker compose -f $INSTALL_DIR/docker-compose.yml ps    # estado"
echo "    docker compose -f $INSTALL_DIR/docker-compose.yml down  # detener"
echo "    sudo RESET=1 $INSTALL_DIR/install.sh                    # regenerar password admin"
echo ""
