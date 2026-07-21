# MonitorMaat

Plataforma multi-tenant para correr **OpenVPN + WireGuard + Uptime Kuma** aislados por cliente en un solo servidor Debian/Ubuntu.

Cada tenant tiene sus propios puertos OpenVPN y WireGuard, rangos VPN, instancia de Uptime Kuma y URL separada. El protocolo se elige **por usuario VPN**: un mismo tenant puede tener MikroTiks v6 en OpenVPN y equipos v7/Linux en WireGuard, todos en el mismo hub. El panel web (FastAPI) lo gestiona todo: usuarios, roles, quotas, notificaciones por Telegram y Email, logs.

---

## Arquitectura

```
┌────────────────────── host Debian/Ubuntu ──────────────────────┐
│                                                                │
│   kumavpn-web (panel FastAPI, :8000)                           │
│       │  docker.sock                                           │
│       ▼                                                        │
│   ┌─── tenant "maat" ──────────┐  ┌─── tenant "foo" ───────┐   │
│   │ openvpn-maat  :1194/tcp    │  │ openvpn-foo :1195/tcp  │   │
│   │ kuma-maat     :3001        │  │ kuma-foo    :3002      │   │
│   │ VPN net 100.64.1.0/24      │  │ VPN net 100.64.2.0/24  │   │
│   └────────────────────────────┘  └────────────────────────┘   │
│                                                                │
└────────────────────────────────────────────────────────────────┘
```

- Kuma comparte el network namespace de su openvpn (`network_mode: service:openvpn`) → ve directamente las rutas iroute de la VPN, puede pingear LAN del Mikrotik sin NAT extra.
- Cada tenant es su propio `docker-compose.yml` en `/opt/kumavpn/tenants/<nombre>/`.
- `kumavpn-web` administra todo via docker socket.

---

## Requisitos del host

- Debian 11/12/13 o Ubuntu 20.04+
- Kernel con `/dev/net/tun` (LXC en Proxmox: `features: nesting=1`)
- Acceso a internet (para pull de imágenes)
- Puerto a abrir en firewall: el puerto VPN de cada tenant (1194, 1195, …) y el del panel (8000 por default, o detrás de NPM)

---

## Instalación

### Opción 1 — One-liner (recomendada)

Pulla imágenes pre-builteadas desde GitHub Container Registry. **No necesita clonar el repo**.

```bash
curl -fsSL https://raw.githubusercontent.com/mtandazo35/monitor-maat/main/get.sh | sudo bash
```

Variables opcionales:

```bash
# Password admin específica (default: aleatoria de 20 chars)
ADMIN_PASS="MiClaveSegura123!" curl -fsSL .../get.sh | sudo bash

# Forzar IP pública (default: auto-detect)
PUBLIC_IP="1.2.3.4" curl -fsSL .../get.sh | sudo bash

# Tag específico (default: latest)
VERSION="v1.0.0" curl -fsSL .../get.sh | sudo bash

# Regenerar credenciales aunque ya exista .env
RESET=1 curl -fsSL .../get.sh | sudo bash
```

Al terminar te imprime URL + usuario + password. **El primer login obliga a cambiar la password** por una propia.

### Opción 2 — Clone + build local (para desarrollo)

```bash
git clone https://github.com/mtandazo35/monitor-maat.git /opt/monitor-maat
cd /opt/monitor-maat
sudo ./install.sh
```

Igual que la opción 1 pero buildeando las imágenes localmente desde los Dockerfiles. Útil si vas a modificar el código.

---

## Actualizar

```bash
cd /opt/monitor-maat
sudo ./update.sh
```

Detecta automáticamente el modo:
- **Modo prod** (sin Dockerfiles locales): `docker pull` desde GHCR + retag + recreate
- **Modo dev** (con Dockerfiles): `git pull` + build local + recreate

Flags:
- `--no-pull`: solo recreate (sin descargar nada nuevo)
- `--no-tenants`: solo el panel (no toca los tenants existentes)

---

## Uso

### 1. Crear un cliente (admin)

Usuarios → **+ Nuevo usuario**:
- Username login (ej. `cliente1`)
- Email (opcional, para enviar credenciales por SMTP)
- Empresa
- Quota (cuántos tenants puede crear)
- Password en blanco → autogenera fuerte y fuerza cambio en primer login

### 2. Crear un tenant

Tenants → **+ Nuevo tenant** → asigna automáticamente:
- Slot (1..254)
- Puerto OpenVPN (`1193 + slot`)
- Puerto WireGuard (`51820 + slot`, UDP)
- Puerto Kuma (`3000 + slot`)
- Subred VPN OpenVPN (`100.64.<slot>.0/24`) y WireGuard (`100.65.<slot>.0/24`)

Levanta openvpn + kuma en ~5s (primer tenant más lento por pull de Kuma).

### 3. Crear usuario VPN para un Mikrotik

Tenant → **+ OpenVPN** o **+ WireGuard**, según el equipo del cliente. Los dos protocolos conviven en el mismo tenant (mismo contenedor y netns), así Uptime Kuma alcanza por igual a todos.

- **OpenVPN**: genera username/password aleatorios + IP VPN. Snippets para RouterOS v6 y v7+ y para Debian/Ubuntu.
- **WireGuard**: genera par de claves + preshared key + IP. Snippets: `.conf` de `wg-quick` (Linux/Windows/móvil), instalador Debian/Ubuntu y RouterOS **v7** — *RouterOS v6 no soporta WireGuard, esos equipos van por OpenVPN*.

### 4. Agregar redes detrás del Mikrotik

Tenant → usuario VPN → form `+ Red` → CIDR de la LAN del cliente (ej. `192.168.88.0/24`). Se agrega:

En OpenVPN:
- `iroute` al CCD del usuario
- `ip route replace` al `rutas.sh`
- SIGHUP a openvpn → la ruta queda activa **sin afectar Kuma** (no recrea el contenedor)

En WireGuard:
- el CIDR entra en los `AllowedIPs` del peer en `wg0.conf`
- `wg syncconf` + `ip route replace ... dev wg0` → activo en caliente, sin cortar a los demás peers

> ⚠ El Mikrotik del cliente debe tener una regla NAT (masquerade) sobre la interfaz LAN para que los devices de la LAN respondan al openvpn server. Ver troubleshooting al final.

---

## Integración con NPM externo

Apuntá los proxy hosts a la IP pública del server con los puertos correspondientes:

```
kumavpn.tudominio.com    → http://204.168.x.x:8000      (panel)
kuma-maat.tudominio.com  → http://204.168.x.x:3001      (kuma del tenant — ✓ Websockets)
kuma-foo.tudominio.com   → http://204.168.x.x:3002
```

---

## Notificaciones

### Email (SMTP) — admin
Settings → SMTP → cargar host, puerto, user, password, modo (SSL/TLS/none) → guardar → test.

Se usa para mandar credenciales nuevas a clientes que tengan email, y notificaciones administrativas.

### Telegram — bot por usuario
Cada usuario crea su propio bot con `@BotFather` y carga token + chat_id en **Mi Telegram**. Recibe notificaciones de **sus** tenants (start/stop/restart/delete) según las preferencias que marque.

El admin tiene su propio bot global en Settings → **Bot Telegram** para notificaciones administrativas (creación de usuarios, fallos, etc.).

---

## Logs / Auditoría

- **Admin** → `/logs` con filtros por origen (sistema/admin/clientes), categoría, búsqueda por texto
- **Cliente** → `/me/logs` con sus propios eventos (sesiones, acciones sobre sus tenants)

Se registra: login_success/fail, logout, password_changed, user_created/updated/deleted, tenant_*, vpn_user_*, network_*, smtp/telegram tests.

---

## Estructura en disco

```
/opt/monitor-maat/             ← este repo (modo dev) o solo docker-compose.yml + .env (modo prod)
/opt/kumavpn/
├── data/
│   └── kumavpn.db             ← SQLite con users, tenants, vpn_users, networks, events, settings
└── tenants/
    └── maat/
        ├── docker-compose.yml ← generado al crear tenant
        ├── openvpn/           ← PKI, server.conf, /auth (passwd persistido), UptimeKuma/ (ccd + rutas.sh)
        └── kuma/              ← data de Uptime Kuma
```

---

## Troubleshooting

```bash
# Logs panel
docker logs -f kumavpn-web

# Logs tenant
docker logs -f openvpn-<tenant>
docker logs -f kuma-<tenant>

# Estado
docker ps

# Entrar a un openvpn
docker exec -it openvpn-<tenant> bash
docker exec openvpn-<tenant> cat /var/log/openvpn-status.log

# Regenerar credenciales admin
sudo RESET=1 /opt/monitor-maat/get.sh
# o (modo dev)
sudo RESET=1 /opt/monitor-maat/install.sh

# Si Kuma no llega a la LAN del Mikrotik:
# en RouterOS:
/ip firewall nat
add chain=srcnat action=masquerade src-address=100.64.<slot>.0/24 out-interface=<TU_INTERFAZ_LAN>
```

---

## Desarrollo

CI/CD via GitHub Actions: cada push a `main` builds + pushea las imágenes a GHCR como `ghcr.io/mtandazo35/monitor-maat-web:latest` y `monitor-maat-openvpn:latest` (más tags `sha-XXX` por commit y `vX.Y.Z` por tag).

Para que get.sh funcione contra GHCR sin auth, las imágenes deben ser **públicas**. Después del primer push, en GitHub:
- Settings del repo → Packages → ver `monitor-maat-web` y `monitor-maat-openvpn`
- Cada uno → Settings (al final) → "Change visibility" → **Public**

Si querés que sigan privadas, usá `docker login ghcr.io` con un PAT antes de correr `get.sh`.

---

## Licencia

Privado — solo uso interno.
