#!/bin/bash
# MonitorMaat one-line installer.
# Pulla imágenes pre-builteadas desde GHCR — no necesita clonar el repo ni buildear.
#
# Uso (desde un Debian/Ubuntu limpio, como root):
#   curl -fsSL https://raw.githubusercontent.com/mtandazo35/monitor-maat/main/get.sh | sudo bash
#
# Variables opcionales:
#   ADMIN_PASS=miclave  curl ... | sudo bash      # password admin específica (default: aleatoria)
#   PUBLIC_IP=1.2.3.4   curl ... | sudo bash      # IP pública forzada (default: auto-detect)
#   RESET=1             curl ... | sudo bash      # regenerar credenciales aunque ya exista .env
#   VERSION=v1.0.0      curl ... | sudo bash      # tag específico (default: latest)

set -e

INSTALL_DIR="/opt/monitor-maat"
DATA_DIR="/opt/kumavpn"
RAW_BASE="https://raw.githubusercontent.com/mtandazo35/monitor-maat/main"
REGISTRY="ghcr.io/mtandazo35"
TAG="${VERSION:-latest}"

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
    c_red "ERROR: solo Debian/Ubuntu soportado"
    exit 1
fi
if [ ! -e /dev/net/tun ]; then
    c_red "ERROR: /dev/net/tun no existe — kernel sin TUN/TAP"
    exit 1
fi

c_blue "════════════════════════════════════════════════════════════════"
c_blue "  MonitorMaat installer (desde imágenes pre-builteadas)"
c_blue "════════════════════════════════════════════════════════════════"
echo "  Install dir: $INSTALL_DIR"
echo "  Data dir:    $DATA_DIR"
echo "  Tag:         $TAG"

# --- 1. Docker ---
c_step "[1/5] Docker"
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
    exit 1
fi

# --- 2. Dependencias del script ---
c_step "[2/5] Dependencias (curl, openssl)"
need=()
for pkg in curl openssl; do
    command -v $pkg >/dev/null 2>&1 || need+=($pkg)
done
if [ ${#need[@]} -gt 0 ]; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${need[@]}"
fi
c_green "  ✓ OK"

# --- 3. Estructura ---
c_step "[3/5] Preparar $INSTALL_DIR y $DATA_DIR"
mkdir -p "$INSTALL_DIR" "$DATA_DIR/data" "$DATA_DIR/tenants"
c_green "  ✓ Directorios creados"

# --- 4. Pull de imágenes desde GHCR + tag local ---
c_step "[4/5] Pull de imágenes desde $REGISTRY (tag: $TAG)"
docker pull "$REGISTRY/monitor-maat-web:$TAG" 2>&1 | tail -2
docker tag "$REGISTRY/monitor-maat-web:$TAG" kumavpn/web:latest
c_green "  ✓ kumavpn/web:latest"

docker pull "$REGISTRY/monitor-maat-openvpn:$TAG" 2>&1 | tail -2
docker tag "$REGISTRY/monitor-maat-openvpn:$TAG" kumavpn/openvpn:latest
c_green "  ✓ kumavpn/openvpn:latest"

# Pre-pull de Kuma para que primer tenant arranque rápido
echo "  Pre-pull louislam/uptime-kuma:1 (en background)..."
docker pull louislam/uptime-kuma:1 >/dev/null 2>&1 &

# --- 5. .env + docker-compose.yml + up ---
c_step "[5/5] Config .env + levantar panel"

# docker-compose.yml: descargo el de runtime y reemplazo image refs por kumavpn/web (que ya tagueé)
cat > "$INSTALL_DIR/docker-compose.yml" <<'EOF'
name: kumavpn-admin
services:
  web:
    image: kumavpn/web:latest
    container_name: kumavpn-web
    restart: unless-stopped
    env_file:
      - .env
    environment:
      KUMAVPN_BASE_PATH: /opt/kumavpn
    ports:
      - "${ADMIN_PORT:-8000}:8000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /opt/kumavpn:/opt/kumavpn
EOF

ENV_FILE="$INSTALL_DIR/.env"
SHOW_PASS=""

if [ -f "$ENV_FILE" ] && grep -q "^ADMIN_PASSWORD_HASH=." "$ENV_FILE" && [ -z "$RESET" ]; then
    c_green "  ✓ .env existente preservado (RESET=1 para regenerar)"
    PUB=$(grep '^PUBLIC_IP=' "$ENV_FILE" | cut -d= -f2)
    SHOW_PASS="(sin cambios)"
else
    [ -n "$RESET" ] && echo "  RESET activo → regenerando credenciales"
    ADMIN_PASS="${ADMIN_PASS:-$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 20)}"
    HASH=$(docker run --rm kumavpn/web:latest python -c "import bcrypt,sys; print(bcrypt.hashpw(sys.argv[1].encode(), bcrypt.gensalt()).decode())" "$ADMIN_PASS")
    HASH_ESC=$(echo "$HASH" | sed 's/\$/\$\$/g')
    SECRET=$(openssl rand -hex 32)
    PUB="${PUBLIC_IP:-$(curl -s -4 --max-time 5 https://ip1.dynupdate.no-ip.com/ 2>/dev/null || hostname -I | awk '{print $1}')}"

    cat > "$ENV_FILE" <<EOF
ADMIN_USER=admin
ADMIN_PASSWORD_HASH=$HASH_ESC
SESSION_SECRET=$SECRET
ADMIN_PORT=8000
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

cd "$INSTALL_DIR"
docker compose up -d --remove-orphans 2>&1 | grep -E "Created|Started|Recreated" || true

# Esperar a que el panel responda
for i in 1 2 3 4 5 6 7 8 9 10; do
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
echo "    docker logs -f kumavpn-web                                # logs"
echo "    docker compose -f $INSTALL_DIR/docker-compose.yml ps      # estado"
echo "    docker compose -f $INSTALL_DIR/docker-compose.yml down    # detener"
echo ""
c_blue "  Actualizar (pulla imágenes nuevas y recrea):"
echo "    curl -fsSL $RAW_BASE/get.sh | sudo bash       # mismo comando = idempotente"
echo ""
