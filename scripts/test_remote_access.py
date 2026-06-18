#!/usr/bin/env python3
"""Prueba de acceso al contenedor atacante (acceso directo y/o vía netbird).

Levanta un entorno publicando el SSH del atacante SOLO en las IPs indicadas
(la de LAN/DCC para acceso directo, y/o la overlay netbird wt0 para remotos),
nunca en todas las interfaces. Deja el run vivo para conectarte desde otro
dispositivo:

    ssh attacker@<IP> -p <PUERTO>      # password: attacker

Correr en una máquina Linux con Docker rootless (igual que el server). En
Docker Desktop (macOS) el port-forwarding es distinto y no valida el caso real.

Uso:
    uv run python scripts/test_remote_access.py 192.168.0.200
    uv run python scripts/test_remote_access.py 192.168.0.200 100.72.209.48
"""
from __future__ import annotations

import sys

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider

VULN_IMAGE = "flexipwn/vuln-command-injection"
ATTACKER_IMAGE = "flexipwn/attacker"
SSH_PORT = 2222


def main() -> None:
    if len(sys.argv) < 2:
        print("Uso: test_remote_access.py <IP_DE_BIND> [IP_DE_BIND ...]")
        print("  Una o más IPs: la de LAN/DCC (directo) y/o la de netbird (wt0).")
        sys.exit(1)
    bind_ips = sys.argv[1:]
    ips_str = ", ".join(f"{ip}:{SSH_PORT}" for ip in bind_ips)

    config = FlexiPwnConfig(
        volumes_base_path="/tmp/flexipwn-remote-test",
        attacker_bind_ips=bind_ips,
    )
    provider = DockerRootlessProvider(config=config)

    print(f"[*] Levantando entorno; SSH del atacante en {ips_str}")
    env = provider.create(
        scenario_id="remote-access-test",
        participant_id="dylan",
        image=VULN_IMAGE,
        attacker_image=ATTACKER_IMAGE,
        attacker_ports=[f"{SSH_PORT}:22"],
    )
    print(f"    env_id:   {env.env_id}")
    print(f"    atacante: {env.container_attacker_name}")
    print()
    print("[*] Verifica el bind en el host (debe mostrar las IPs, NO 0.0.0.0):")
    print(f"      ss -tlnp | grep {SSH_PORT}      # esperado: {ips_str}")
    print("[*] Conéctate (misma red o vía netbird):")
    for ip in bind_ips:
        print(f"      ssh attacker@{ip} -p {SSH_PORT}      # password: attacker")
    print()
    try:
        input("[Enter] para destruir el entorno...")
    finally:
        provider.destroy(env.env_id)
        print("[*] Entorno destruido.")


if __name__ == "__main__":
    main()
