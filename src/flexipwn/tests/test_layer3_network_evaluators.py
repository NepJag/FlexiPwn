"""
Tests de NetworkPayloadEvaluator y NetworkConnectionEvaluator (Capa 3) — sin Docker.
"""
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from flexipwn.layer2.events import MonitorEvent
from flexipwn.layer3.schema import TargetConfig
from flexipwn.layer3.targets.network import NetworkConnectionEvaluator, NetworkPayloadEvaluator


def _make_event(event_type: str, details: dict) -> MonitorEvent:
    return MonitorEvent(
        timestamp=datetime.now(timezone.utc),
        monitor_type="network",
        event_type=event_type,
        env_id="env-test",
        participant_id="test-player",
        scenario_id="test-scenario",
        details=details,
    )


def _make_payload_config(field_matches: dict) -> TargetConfig:
    return TargetConfig(
        type="network_payload",
        description="test",
        field_matches=field_matches,
    )


def _make_connection_config(dst_port: int, dst_ip: str | None = None) -> TargetConfig:
    return TargetConfig(
        type="network_connection",
        description="test",
        dst_port=dst_port,
        dst_ip=dst_ip,
    )


class TestNetworkPayloadEvaluator:

    def test_matches_payload_with_field_matches_regex(self):
        """field_matches regex 'SELECT.*users' matchea data 'SELECT * FROM users'."""
        config = _make_payload_config({"data": "SELECT.*users"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("network_payload", {"data": "SELECT * FROM users WHERE id=1"})

        assert evaluator.matches(event) is True

    def test_no_match_wrong_event_type(self):
        """Evento que no es network_payload → no matchea."""
        config = _make_payload_config({"data": "SELECT.*users"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("log_entry", {"raw_line": "SELECT * FROM users"})

        assert evaluator.matches(event) is False

    def test_no_match_data_does_not_satisfy_pattern(self):
        """Data que no satisface la regex → no matchea."""
        config = _make_payload_config({"data": "SELECT.*sensitive_data"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("network_payload", {"data": "SELECT * FROM users"})

        assert evaluator.matches(event) is False

    def test_no_match_when_field_matches_is_none(self):
        """Si field_matches es None → no matchea (guard)."""
        config = TargetConfig.model_construct(
            type="network_payload",
            description="test",
            field_matches=None,
        )
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("network_payload", {"data": "SELECT * FROM users"})

        assert evaluator.matches(event) is False

    def test_invalid_regex_returns_false_without_crash(self):
        """Regex inválida en field_matches → retorna False sin lanzar excepción."""
        config = _make_payload_config({"data": "[invalid_regex"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("network_payload", {"data": "SELECT * FROM users"})

        assert evaluator.matches(event) is False

    def test_multiple_field_matches_all_must_pass(self):
        """Todas las condiciones en field_matches deben cumplirse (AND implícito)."""
        config = _make_payload_config({"data": "SELECT.*users", "other": "FROM"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("network_payload", {"data": "SELECT * FROM users"})

        assert evaluator.matches(event) is True

    def test_sqli_pattern_matches_injection_query(self):
        """Patrón de SQLi detecta query con OR 1=1."""
        config = _make_payload_config({"data": r"OR.*1.*=.*1|UNION.*SELECT|--"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event(
            "network_payload",
            {"data": "SELECT * FROM users WHERE user='admin' OR 1=1 --"}
        )

        assert evaluator.matches(event) is True

    def test_matches_flag_in_response_payload(self):
        """Patrón sobre flags en data."""
        config = _make_payload_config({"data": r"FLAG\{sql_injection_detected\}"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("network_payload", {"data": "...FLAG{sql_injection_detected}..."})

        assert evaluator.matches(event) is True

    def test_matches_case_insensitive_without_explicit_flag(self):
        """Pattern en mayúsculas matchea data en minúsculas sin (?i) explícito —
        el evaluator aplica re.IGNORECASE por defecto para alinearse con cómo
        un estudiante tipea la inyección."""
        config = _make_payload_config({"data": "OR.*1.*=.*1"})
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event(
            "network_payload",
            {"data": "select * from users where username='admin' or '1'='1' --"},
        )

        assert evaluator.matches(event) is True

    def test_matches_alternation_pattern(self):
        """Patrón con alternación OR matchea cualquiera de los valores sensibles."""
        config = _make_payload_config(
            {"data": r"FLAG\{sql_injection_detected\}|internal-api-key-xyz"}
        )
        evaluator = NetworkPayloadEvaluator(config)
        event = _make_event("network_payload", {"data": "row: internal-api-key-xyz"})

        assert evaluator.matches(event) is True


class TestNetworkConnectionEvaluator:

    def test_matches_correct_dst_port(self):
        config = _make_connection_config(dst_port=4444)
        evaluator = NetworkConnectionEvaluator(config)
        event = _make_event(
            "network_connection",
            {"src_ip": "172.20.0.2", "dst_ip": "192.168.1.10", "dst_port": 4444}
        )

        assert evaluator.matches(event) is True

    def test_no_match_wrong_dst_port(self):
        config = _make_connection_config(dst_port=4444)
        evaluator = NetworkConnectionEvaluator(config)
        event = _make_event(
            "network_connection",
            {"src_ip": "172.20.0.2", "dst_ip": "192.168.1.10", "dst_port": 80}
        )

        assert evaluator.matches(event) is False

    def test_no_match_wrong_event_type(self):
        config = _make_connection_config(dst_port=4444)
        evaluator = NetworkConnectionEvaluator(config)
        event = _make_event("network_payload", {"data": "x", "dst_port": 4444})

        assert evaluator.matches(event) is False

    def test_optional_dst_ip_filter_matches_when_correct(self):
        config = _make_connection_config(dst_port=4444, dst_ip="192.168.1.10")
        evaluator = NetworkConnectionEvaluator(config)
        event = _make_event(
            "network_connection",
            {"src_ip": "172.20.0.2", "dst_ip": "192.168.1.10", "dst_port": 4444}
        )

        assert evaluator.matches(event) is True

    def test_optional_dst_ip_filter_no_match_wrong_ip(self):
        config = _make_connection_config(dst_port=4444, dst_ip="192.168.1.10")
        evaluator = NetworkConnectionEvaluator(config)
        event = _make_event(
            "network_connection",
            {"src_ip": "172.20.0.2", "dst_ip": "10.0.0.99", "dst_port": 4444}
        )

        assert evaluator.matches(event) is False

    def test_without_dst_ip_matches_any_ip(self):
        config = _make_connection_config(dst_port=4444)
        evaluator = NetworkConnectionEvaluator(config)
        event = _make_event(
            "network_connection",
            {"src_ip": "172.20.0.2", "dst_ip": "any.random.ip.here", "dst_port": 4444}
        )

        assert evaluator.matches(event) is True


class TestEnableNetworkCaptureFlag:

    def test_create_without_flag_does_not_call_create_sniffer(self):
        """create(enable_network_capture=False) no debe llamar _create_sniffer."""
        from flexipwn.config import FlexiPwnConfig
        from flexipwn.layer1.docker_rootless import DockerRootlessProvider

        mock_client = MagicMock()
        mock_network = MagicMock()
        mock_container = MagicMock()
        mock_container.attrs = {"State": {"Health": None}}
        mock_container.diff.return_value = []

        mock_client.networks.create.return_value = mock_network
        mock_client.containers.run.return_value = mock_container
        mock_client.containers.get.return_value = mock_container

        config = MagicMock(spec=FlexiPwnConfig)
        config.volumes_base_path = "/tmp/test-flexipwn"
        config.startup_delay_seconds = 0.0
        config.healthcheck_timeout = 0.1
        config.healthcheck_poll_interval = 0.05
        config.container_stop_timeout = 1
        # attacker_bind_ips usa field(default_factory=...), así que no es atributo
        # de clase y MagicMock(spec=...) no lo expone: hay que stubearlo o create()
        # lanza AttributeError (en _parse_port_bindings) antes de llegar al sniffer.
        config.attacker_bind_ips = None

        provider = DockerRootlessProvider(config=config, client=mock_client)

        with patch.object(provider, "_create_sniffer") as mock_sniffer:
            with patch("time.sleep"):
                try:
                    provider.create(
                        scenario_id="test",
                        participant_id="player",
                        image="test-image",
                        enable_network_capture=False,
                    )
                except Exception:
                    pass
            mock_sniffer.assert_not_called()

    def test_create_with_flag_calls_create_sniffer(self):
        """create(enable_network_capture=True) debe llamar _create_sniffer."""
        from flexipwn.config import FlexiPwnConfig
        from flexipwn.layer1.docker_rootless import DockerRootlessProvider

        mock_client = MagicMock()
        mock_network = MagicMock()
        mock_container = MagicMock()
        mock_container.attrs = {"State": {"Health": None}}
        mock_container.diff.return_value = []

        mock_client.networks.create.return_value = mock_network
        mock_client.containers.run.return_value = mock_container
        mock_client.containers.get.return_value = mock_container

        config = MagicMock(spec=FlexiPwnConfig)
        config.volumes_base_path = "/tmp/test-flexipwn"
        config.startup_delay_seconds = 0.0
        config.healthcheck_timeout = 0.1
        config.healthcheck_poll_interval = 0.05
        config.container_stop_timeout = 1
        # attacker_bind_ips usa field(default_factory=...), así que no es atributo
        # de clase y MagicMock(spec=...) no lo expone: hay que stubearlo o create()
        # lanza AttributeError (en _parse_port_bindings) antes de llegar al sniffer.
        config.attacker_bind_ips = None

        provider = DockerRootlessProvider(config=config, client=mock_client)

        with patch.object(provider, "_create_sniffer") as mock_sniffer:
            with patch("time.sleep"):
                try:
                    provider.create(
                        scenario_id="test",
                        participant_id="player",
                        image="test-image",
                        enable_network_capture=True,
                    )
                except Exception:
                    pass
            mock_sniffer.assert_called_once()
