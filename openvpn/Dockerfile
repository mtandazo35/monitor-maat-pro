FROM debian:12-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openvpn \
        openssl \
        ca-certificates \
        easy-rsa \
        iproute2 \
        iptables \
        libpam-modules \
        passwd \
        adduser \
        procps \
        tini \
        wireguard-tools \
        wireguard-go \
    && rm -rf /var/lib/apt/lists/*

COPY pam-openvpn /etc/pam.d/openvpn
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 1194/tcp
EXPOSE 1194/udp
EXPOSE 51820/udp

ENTRYPOINT ["/usr/bin/tini", "--", "/entrypoint.sh"]
