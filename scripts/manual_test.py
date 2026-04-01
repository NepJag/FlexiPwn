#!/usr/bin/env python3
"""Script de prueba manual para Layer 1 — DockerRootlessProvider.

Uso:
    uv run python scripts/manual_test.py
"""

from flexipwn.config import FlexiPwnConfig
from flexipwn.layer1.docker_rootless import DockerRootlessProvider

IMAGE = "flexipwn/vulnerable-sudo:latest"
SCENARIO = "sudo-vim-privesc"
PARTICIPANT = "dylan"


def main():
    config = FlexiPwnConfig(volumes_base_path="/tmp/flexipwn-manual")
    provider = DockerRootlessProvider(config=config)

    print("=== FlexiPwn Layer 1 — Prueba manual ===\n")

    # 1. Crear entorno
    print(f"[1] Creando entorno con imagen {IMAGE}...")
    env = provider.create(
        scenario_id=SCENARIO,
        participant_id=PARTICIPANT,
        image=IMAGE,
    )
    print(f"    env_id:     {env.env_id}")
    print(f"    vulnerable: {env.container_vulnerable_name}")
    print(f"    red:        {env.network_name}")
    print(f"    volúmenes:  {env.volume_base_path}")
    print(f"    status:     {env.status}")
    print()

    # 2. Ejecutar comandos
    print("[2] Ejecutando comandos en el contenedor vulnerable...")
    for cmd in ["whoami", "hostname", "cat /etc/os-release | head -2", "ls /home"]:
        result = provider.exec_run(env.env_id, f"bash -c '{cmd}'", "ctfuser")
        print(f"    $ {cmd}")
        print(f"      exit={result.exit_code} stdout={result.stdout.strip()!r}")
        if result.stderr.strip():
            print(f"      stderr={result.stderr.strip()!r}")
    print()

    # 3. Procesos
    print("[3] Listando procesos (container.top())...")
    processes = provider.get_processes(env.env_id)
    for p in processes:
        print(f"    PID={p.pid} PPID={p.ppid} EUID={p.euid} CMD={p.cmd}")
    print()

    # 4. Filesystem diff via container.diff()
    print("[4] Filesystem diff (antes de crear archivos)...")
    diff_before = provider.get_filesystem_diff(env.env_id)
    print(f"    {len(diff_before)} cambios respecto a la imagen base")

    print("    Creando /root/pwned.txt en el contenedor...")
    provider.exec_run(env.env_id, "bash -c 'echo pwned > /root/pwned.txt'")

    diff_after = provider.get_filesystem_diff(env.env_id)
    created = [e for e in diff_after if e["path"] == "/root/pwned.txt"]
    print(f"    /root/pwned.txt detectado en diff: {bool(created)}")
    if created:
        print(f"    kind={created[0]['kind']}  (1 = creado)")
    print()

    # 5. Get status
    print("[5] Estado del entorno...")
    status = provider.get_status(env.env_id)
    print(f"    status: {status.status}")
    print(f"    created_at: {status.created_at}")
    print()

    # 6. Reset
    print("[6] Reseteando entorno (mismo env_id, contenedor nuevo)...")
    provider.reset(env.env_id)
    status = provider.get_status(env.env_id)
    print(f"    env_id post-reset: {status.env_id}")
    print(f"    status: {status.status}")
    print()

    # 7. Aislamiento de red
    print("[7] Probando aislamiento de red...")
    env2 = provider.create(
        scenario_id=SCENARIO,
        participant_id="dylan-2",
        image=IMAGE,
    )
    print(f"    Segundo entorno: {env2.env_id}")

    # IP del contenedor del segundo entorno
    ip_result = provider.exec_run(env2.env_id, "hostname -I")
    ip_env2 = ip_result.stdout.strip().split()[0]
    print(f"    IP de env2: {ip_env2}")

    # Intentar alcanzar env2 desde env1 (debe fallar)
    cross = provider.exec_run(
        env.env_id,
        f"bash -c 'timeout 2 bash -c \"echo > /dev/tcp/{ip_env2}/80\" && echo REACHABLE || echo BLOCKED'",
    )
    print(f"    env1 → env2: {cross.stdout.strip()}")

    # Intentar alcanzar internet desde env1 (debe fallar por internal=True)
    internet = provider.exec_run(
        env.env_id,
        "bash -c 'timeout 2 bash -c \"echo > /dev/tcp/1.1.1.1/80\" && echo REACHABLE || echo BLOCKED'",
    )
    print(f"    env1 → internet: {internet.stdout.strip()}")

    provider.destroy(env2.env_id)
    print()

    # 8. Destruir
    print("[8] Destruyendo entorno...")
    provider.destroy(env.env_id)
    print("    Entorno destruido.")
    print()

    print("=== Prueba completada exitosamente ===")


if __name__ == "__main__":
    main()
