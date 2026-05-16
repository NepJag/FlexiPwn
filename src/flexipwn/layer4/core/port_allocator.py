from __future__ import annotations

import socket


def find_free_port(start: int, end: int) -> int:
    """Devuelve el primer puerto libre en [start, end] vía bind probe en 127.0.0.1.

    Limitación conocida: si dos invocaciones de find_free_port ocurren
    concurrentemente antes de que Docker ocupe el puerto, pueden obtener
    el mismo resultado. Esta función es segura solo si los provider.create()
    se ejecutan en secuencia. batch-start garantiza esto. run start desde
    múltiples terminales simultáneas puede causar colisión; el error de
    Docker en provider.create() se propagará con mensaje claro al usuario.
    """
    for port in range(start, end + 1):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"Sin puertos libres en {start}-{end}")
