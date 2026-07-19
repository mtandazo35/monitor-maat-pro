#!/bin/bash
# update.sh — actualiza el panel y todos los tenants existentes.
# Detecta automáticamente:
#   - Modo dev (hay Dockerfiles locales)  → git pull + build local
#   - Modo prod (sin Dockerfiles)         → docker pull desde GHCR
#
# Uso:
#   sudo ./update.sh                    # update completo (panel + todos los tenants)
#   sudo ./update.sh --no-tenants       # solo panel
#   sudo ./update.sh --no-pull          # solo rebuild/recreate (sin git pull / docker pull)

set -e

INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
DATA_DIR="${KUMAVPN_BASE_PATH:-/opt/kumavpn}"
TENANTS_DIR="$DATA_DIR/tenants"
REGISTRY="ghcr.io/mtandazo35"

DO_PULL=1
DO_TENANTS=1
for arg in "$@"; do
    case "$arg" in
        --no-pull)    DO_PULL=0    ;;
        --no-tenants) DO_TENANTS=0 ;;
        -h|--help)
            grep '^#' "$0" | head -10
            exit 0
            ;;
    esac
done

c_red()   { printf "\033[31m%s\033[0m\n" "$*"; }
c_green() { printf "\033[32m%s\033[0m\n" "$*"; }
c_blue()  { printf "\033[34m%s\033[0m\n" "$*"; }
c_step()  { printf "\n\033[1;36m▸ %s\033[0m\n" "$*"; }

if [ "$EUID" -ne 0 ]; then
    c_red "ERROR: ejecutar con sudo o como root"
    exit 1
fi
if [ ! -f "$INSTALL_DIR/docker-compose.yml" ]; then
    c_red "ERROR: corré desde dentro de la carpeta del proyecto"
    exit 1
fi

# Detectar modo
MODE="prod"
if [ -f "$INSTALL_DIR/web/Dockerfile" ] && [ -f "$INSTALL_DIR/openvpn/Dockerfile" ]; then
    MODE="dev"
fi
echo "Modo detectado: $MODE"

cd "$INSTALL_DIR"

# --- 1. Pull (git o docker) ---
if [ "$DO_PULL" = "1" ]; then
    if [ "$MODE" = "dev" ]; then
        c_step "[1/4] git pull"
        if [ ! -d ".git" ]; then
            c_red "  No es un repo git — saltando"
        else
            BEFORE=$(git rev-parse HEAD 2>/dev/null || echo "none")
            git fetch origin 2>&1 | tail -3
            REMOTE=$(git rev-parse '@{u}' 2>/dev/null || echo "$BEFORE")
            if [ "$BEFORE" = "$REMOTE" ]; then
                c_green "  ✓ ya estás al día"
            else
                git pull --ff-only 2>&1 | tail -8
                AFTER=$(git rev-parse HEAD)
                c_green "  ✓ actualizado: $BEFORE → $AFTER"
                git --no-pager log --oneline "$BEFORE..$AFTER" | sed 's/^/    /'
            fi
        fi
    else
        c_step "[1/4] docker pull desde GHCR"
        docker pull "$REGISTRY/monitor-maat-web:latest" 2>&1 | tail -2
        [ "${PIPESTATUS[0]}" -eq 0 ] || { c_red "  ERROR: falló el pull de monitor-maat-web"; exit 1; }
        docker tag "$REGISTRY/monitor-maat-web:latest" kumavpn/web:latest
        docker pull "$REGISTRY/monitor-maat-openvpn:latest" 2>&1 | tail -2
        [ "${PIPESTATUS[0]}" -eq 0 ] || { c_red "  ERROR: falló el pull de monitor-maat-openvpn"; exit 1; }
        docker tag "$REGISTRY/monitor-maat-openvpn:latest" kumavpn/openvpn:latest
        c_green "  ✓ imágenes actualizadas"
    fi
else
    c_step "[1/4] Pull (saltado --no-pull)"
fi

# --- 2. Build (solo modo dev) ---
if [ "$MODE" = "dev" ]; then
    c_step "[2/4] Build kumavpn/openvpn"
    docker build -t kumavpn/openvpn:latest "$INSTALL_DIR/openvpn" 2>&1 | tail -3
    c_green "  ✓ kumavpn/openvpn:latest"
else
    c_step "[2/4] Build (saltado en modo prod)"
fi

# --- 3. Build web + recreate panel ---
c_step "[3/4] Recreate panel"
if [ "$MODE" = "dev" ]; then
    docker build -t kumavpn/web:latest "$INSTALL_DIR/web" 2>&1 | tail -3
fi
docker compose -f "$INSTALL_DIR/docker-compose.yml" up -d --force-recreate 2>&1 | tail -5
c_green "  ✓ panel recreado"

# --- 4. Recreate tenants ---
if [ "$DO_TENANTS" = "1" ]; then
    c_step "[4/4] Recreate stacks de tenants"
    if [ -d "$TENANTS_DIR" ]; then
        any=0
        for d in "$TENANTS_DIR"/*/; do
            [ -f "$d/docker-compose.yml" ] || continue
            name=$(basename "$d")
            printf "  recreating %-25s " "$name..."
            docker compose -f "$d/docker-compose.yml" up -d --force-recreate >/dev/null 2>&1 \
                && c_green "OK" || c_red "FAIL"
            any=1
        done
        [ "$any" = "0" ] && echo "  (no hay tenants)"
    else
        echo "  (directorio $TENANTS_DIR inexistente)"
    fi
else
    c_step "[4/4] Recreate tenants (saltado --no-tenants)"
fi

echo ""
c_blue "════════════════════════════════════════════════════════════════"
c_green "  ✓ Update completo (modo $MODE)"
c_blue "════════════════════════════════════════════════════════════════"
echo ""
docker ps --format "  {{.Names}}\t{{.Status}}"
echo ""
