#!/usr/bin/env python3
"""Prueba de acceso remoto al contenedor atacante (simula la red del DCC).

Levanta un entorno publicando el SSH del atacante SOLO en la IP indicada
(la LAN del DCC, o más adelante la overlay netbird), nunca en todas las
interfaces. Deja el run vivo para que te conectes desde OTRO dispositivo de
la misma red:

    ssh attacker@<IP> -p <PUERTO>      # password: attacker

Importante: correr en una máquina Linux con Docker rootless (igual que el
server). En Docker Desktop (macOS) el port-forwarding es distinto y NO valida
el caso rootless.

Uso:
    uv run python scripts/test_remote_access.py 192.168.1.50
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
        print("Uso: test_remote_access.py <IP_DE_BIND>   (IP de LAN o de netbird)")
        sys.exit(1)
    bind_ip = sys.argv[1]

    config = FlexiPwnConfig(
        volumes_base_path="/tmp/flexipwn-remote-test",
        attacker_bind_ip=bind_ip,
    )
    provider = DockerRootlessProvider(config=config)

    print(f"[*] Levantando entorno; SSH del atacante solo en {bind_ip}:{SSH_PORT}")
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
    print("[*] Verifica el bind en el host (debe mostrar la IP, NO 0.0.0.0):")
    print(f"      ss -tlnp | grep {SSH_PORT}      # esperado: {bind_ip}:{SSH_PORT}")
    print("[*] Desde otro dispositivo de la misma red:")
    print(f"      ssh attacker@{bind_ip} -p {SSH_PORT}      # password: attacker")
    print()
    try:
        input("[Enter] para destruir el entorno...")
    finally:
        provider.destroy(env.env_id)
        print("[*] Entorno destruido.")


if __name__ == "__main__":
    main()
