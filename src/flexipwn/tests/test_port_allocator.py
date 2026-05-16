from __future__ import annotations

import socket

import pytest

from flexipwn.layer4.core.port_allocator import find_free_port


def _bind_blocker(port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
    s.bind(("127.0.0.1", port))
    return s


def test_find_free_port_returns_port_in_range():
    port = find_free_port(40000, 40100)
    assert 40000 <= port <= 40100


def test_find_free_port_skips_occupied_port():
    blocker = _bind_blocker(40500)
    try:
        port = find_free_port(40500, 40510)
        assert port != 40500
        assert 40500 <= port <= 40510
    finally:
        blocker.close()


def test_find_free_port_raises_when_range_exhausted():
    blockers: list[socket.socket] = []
    try:
        for p in range(41000, 41003):
            blockers.append(_bind_blocker(p))
        with pytest.raises(RuntimeError, match="Sin puertos libres"):
            find_free_port(41000, 41002)
    finally:
        for s in blockers:
            s.close()
