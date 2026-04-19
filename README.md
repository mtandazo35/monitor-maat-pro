# KumaVPN — multi-tenant Uptime Kuma + OpenVPN en Docker

Panel web que genera, levanta y administra stacks aislados de **OpenVPN + Uptime Kuma**, uno por cliente (tenant), en un solo servidor Debian/Ubuntu. Cada tenant tiene su propio puerto OpenVPN, rango VPN, red Docker privada y URL de Kuma separada.

Replica el flujo del script original `kumavpn-pro` (PAM auth por usuario, `client-config-dir`, `iroute`, `rutas.sh`) dentro de contenedores, y lo expone detrás de un panel web.

---

## Arquitectura

```
┌───────────────── host Debian/Ubuntu ──────────────────┐
│                                                       │
│   kumavpn-web (panel, FastAPI, puerto 127.0.0.1:8000) │
│       │  docker.sock                                  │
│       ▼                                               │
│   ┌─── tenant "acme" ──────┐  ┌─── tenant "foo" ───┐  │
│   │ openvpn-acme  :1194/tcp│  │ openvpn-foo :1195  │  │
│   │ kuma-acme     :3001    │  │ kuma-foo    :3002  │  │
│   │ net 172.30.1.0/24      │  │ net 172.30.2.0/24  │  │
│   │ VPN 100.64.1.0/24      │  │ VPN 100.64.2.0/24  │  │
│   └────────────────────────┘  └────────────────────┘  │
│                                                       │
│   Nginx Proxy Manager (tuyo) → 127.0.0.1:3001, 3002   │
└───────────────────────────────────────────────────────┘
```

- El panel y los contenedores Kuma bindean solo a `127.0.0.1`. NPM (que ya gestionás) expone los dominios con TLS.
- OpenVPN bindea al host en TCP para que los Mikrotik conecten desde afuera.
- Cada tenant es un `docker-compose.yml` independiente en `/opt/kumavpn/tenants/<nombre>/`.

---

## Requisitos del host

- Debian 11/12 o Ubuntu 20.04+
- Docker Engine + plugin `docker compose` v2
- `/dev/net/tun` disponible (ya lo tenés en Proxmox/Hetzner con kernel estándar)
- Puertos abiertos en el firewall: el `VPN_PORT` de cada tenant (1194, 1195, …)

---

## Instalación

1. Cloná/copia esta carpeta al servidor, por ejemplo en `/opt/kumavpn-docker/`:

   ```bash
   sudo mkdir -p /opt/kumavpn-docker /opt/kumavpn
   sudo rsync -a kumavpn-docker/ /opt/kumavpn-docker/
   cd /opt/kumavpn-docker
   ```

2. Compilá la imagen OpenVPN (la web la usa para cada tenant):

   ```bash
   docker build -t kumavpn/openvpn:latest ./openvpn
   ```

3. Generá hash de contraseña admin y secret de sesión:

   ```bash
   # Hash bcrypt de la clave admin
   docker run --rm python:3.12-slim sh -c "pip install -q bcrypt && python -c 'import bcrypt; print(bcrypt.hashpw(b\"MI_CLAVE_FUERTE\", bcrypt.gensalt()).decode())'"

   # Secret de sesión
   openssl rand -hex 32
   ```

4. Copiá `.env.example` → `.env` y completá:

   ```bash
   cp .env.example .env
   nano .env      # ADMIN_PASSWORD_HASH, SESSION_SECRET, PUBLIC_IP
   ```

5. Levantá el panel:

   ```bash
   docker compose up -d --build
   ```

6. En **Nginx Proxy Manager**, creá un proxy host:
   - Domain: `kumavpn.tudominio.com`
   - Scheme: `http`, Forward hostname: `127.0.0.1`, Port: `8000`
   - Activá SSL con Let's Encrypt.

   El panel queda accesible en `https://kumavpn.tudominio.com`.

---

## Uso

1. Entrá al panel y creá un tenant nuevo (ej. `acme`). El sistema:
   - Asigna slot (1..254), puerto VPN (`1193+slot`), puerto Kuma (`3000+slot`).
   - Crea `/opt/kumavpn/tenants/acme/{openvpn,kuma}`.
   - Renderiza `docker-compose.yml` del tenant y lo levanta.
   - OpenVPN inicializa su PKI en el primer arranque (easy-rsa, DH 2048, tc.key).

2. En la pantalla del tenant, **+ Nuevo usuario VPN** crea un usuario Linux en el contenedor OpenVPN y te muestra:
   - Usuario / contraseña aleatorios.
   - IP VPN fija (`100.64.<slot>.<n>`).
   - Snippet listo para pegar en consola Mikrotik (`/interface ovpn-client add ...`).

3. **+ Red** en cada usuario agrega un `iroute` + `ip route add` para que Kuma (y el resto de la red del tenant) pueda llegar a la LAN detrás del Mikrotik (ej. `192.168.1.0/24`). Reinicia el contenedor OpenVPN automáticamente.

4. Exponé Kuma por NPM: creá un proxy host por tenant apuntando a `127.0.0.1:<KUMA_PORT>` (lo ves en el dashboard).

---

## Integración con Nginx Proxy Manager

Para cada tenant, un proxy host en NPM:

| Campo              | Valor                         |
|--------------------|-------------------------------|
| Domain Names       | `kuma-acme.tudominio.com`     |
| Scheme             | `http`                        |
| Forward Hostname   | `127.0.0.1`                   |
| Forward Port       | `3001` (ver dashboard)        |
| Websockets Support | ✅ (Kuma lo necesita)          |
| SSL                | Let's Encrypt + Force SSL     |

---

## Estructura en disco

```
/opt/kumavpn-docker/          <- este repo (panel + imágenes)
/opt/kumavpn/
├── data/
│   └── kumavpn.db             <- registro de tenants / usuarios VPN / redes
└── tenants/
    └── acme/
        ├── docker-compose.yml <- generado
        ├── openvpn/           <- PKI, server.conf, UptimeKuma/ (ccd + rutas.sh)
        └── kuma/              <- data de Uptime Kuma
```

Podés entrar a la carpeta del tenant y correr `docker compose` a mano si hace falta debuggear.

---

## Caveats y notas

- **Passwords en claro**: el panel guarda las contraseñas VPN para poder mostrarlas luego (igual que el script original). La DB está en `/opt/kumavpn/data/kumavpn.db`, protegela a nivel filesystem.
- **Reinicio al agregar red**: igual que el script original, agregar una red reinicia el contenedor OpenVPN del tenant (corta conexiones activas unos segundos).
- **Máx. 254 tenants** por el plan de IPs (`100.64.<1..254>.0/24`). Para más, extender el mapeo.
- **Eliminar tenant** borra completamente PKI, Kuma data y el registro. No hay undo.
- **Firewall**: hay que abrir manualmente cada `VPN_PORT` hacia afuera.
- **IP pública**: si el server tiene NAT, poné `PUBLIC_IP=` en `.env` con la IP que ve el Mikrotik; si no, el panel la detecta por `ip1.dynupdate.no-ip.com`.
- **Kuma → Mikrotik LAN**: el contenedor OpenVPN hace MASQUERADE sobre `tun0`. Kuma ve la LAN del cliente a través del openvpn, y los dispositivos reciben el tráfico con source-IP del openvpn (no importa para ping/HTTP monitoring).

---

## Troubleshooting

```bash
# Logs del panel
docker logs -f kumavpn-web

# Logs de un tenant
docker logs -f openvpn-acme
docker logs -f kuma-acme

# Entrar al OpenVPN de un tenant
docker exec -it openvpn-acme bash

# Ver usuarios VPN registrados en el sistema del contenedor
docker exec openvpn-acme getent passwd | tail

# Ver estado de conexiones OpenVPN
docker exec openvpn-acme cat /var/log/openvpn-status.log

# Regenerar stack de un tenant (conserva datos)
cd /opt/kumavpn/tenants/acme && docker compose up -d --force-recreate
```
