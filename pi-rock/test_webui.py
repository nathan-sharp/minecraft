#!/usr/bin/env python3
"""
IEEE 29119 Unit & Integration Test Suite for pi-rock/webui.py Address Management.
Follows strict Arrange-Act-Assert (AAA) structure with pure Python standard library.
"""

import base64
import http.client
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import webui


def _build_mock_pong(motd="Pi Bedrock", version="1.26.45.1", online="2", max_p="8", guid="9876543210"):
    """Helper to build a valid RakNet Unconnected Pong (0x1c) binary datagram."""
    server_id = f"MCPE;{motd};766;{version};{online};{max_p};{guid};Bedrock level;Survival;1;19132;19133;".encode("utf-8")
    return (
        b"\x1c"
        + struct.pack(">Q", 123456)
        + struct.pack(">Q", int(guid))
        + webui.RAKNET_OFFLINE_MAGIC
        + struct.pack(">H", len(server_id))
        + server_id
    )


class TestAddressValidationAndCloudflare(unittest.TestCase):
    """Tests for strict address parsing, IP validation, and Cloudflare CIDR checks."""

    def test_parse_valid_addresses(self):
        # Arrange
        valid_cases = [
            ("play.example.com", "play.example.com", "play.example.com", None, "domain"),
            ("  PLAY.EXAMPLE.COM:19135  ", "play.example.com:19135", "play.example.com", 19135, "domain"),
            ("93.184.216.34", "93.184.216.34", "93.184.216.34", None, "ipv4"),
            ("93.184.216.34:19132", "93.184.216.34:19132", "93.184.216.34", 19132, "ipv4"),
            ("2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1:248:1893:25c8:1946", None, "ipv6"),
            ("[2606:2800:220:1:248:1893:25c8:1946]", "2606:2800:220:1:248:1893:25c8:1946", "2606:2800:220:1:248:1893:25c8:1946", None, "ipv6"),
            ("[2606:2800:220:1:248:1893:25c8:1946]:19133", "[2606:2800:220:1:248:1893:25c8:1946]:19133", "2606:2800:220:1:248:1893:25c8:1946", 19133, "ipv6"),
        ]

        for raw, exp_norm, exp_host, exp_port, exp_type in valid_cases:
            with self.subTest(raw=raw):
                # Act
                parsed, err = webui.parse_server_address(raw)

                # Assert
                self.assertIsNone(err)
                self.assertEqual(parsed["raw_address"], exp_norm)
                self.assertEqual(parsed["host"], exp_host)
                self.assertEqual(parsed["port_override"], exp_port)
                self.assertEqual(parsed["address_type"], exp_type)

    def test_parse_invalid_and_ssrf_addresses(self):
        # Arrange
        invalid_cases = [
            ("", "empty_address"),
            ("   ", "empty_address"),
            ("http://play.example.com", "invalid_format"),
            ("https://play.example.com:443", "invalid_format"),
            ("play.example.com/world", "invalid_format"),
            ("play example.com", "invalid_format"),
            ("play.example.com\n", "invalid_format"),
            ("localhost", "invalid_format"),
            ("raspberrypi", "invalid_format"),
            ("play.example.com:0", "invalid_port"),
            ("play.example.com:65536", "invalid_port"),
            ("play.example.com:abc", "invalid_port"),
            ("play.example.com:-1", "invalid_port"),
            ("127.0.0.1", "private_ip"),
            ("10.0.0.1:19132", "private_ip"),
            ("192.168.1.50", "private_ip"),
            ("169.254.169.254", "private_ip"),
            ("100.64.0.1", "private_ip"),
            ("::1", "private_ip"),
            ("[::1]:19132", "private_ip"),
            ("fc00::1", "private_ip"),
            ("fe80::1", "private_ip"),
            ("::ffff:127.0.0.1", "private_ip"),
        ]

        for raw, exp_err in invalid_cases:
            with self.subTest(raw=raw):
                # Act
                parsed, err = webui.parse_server_address(raw)

                # Assert
                self.assertIsNone(parsed)
                self.assertEqual(err, exp_err)

    def test_cloudflare_proxy_cidr_detection(self):
        # Arrange
        cf_ips = ["104.21.10.20", "172.67.1.2", "2606:4700:3030::6815:1014"]
        non_cf_ips = ["93.184.216.34", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946", "not-an-ip"]

        # Act & Assert
        for ip_addr in cf_ips:
            self.assertTrue(webui.is_cloudflare_proxy_ip(ip_addr), msg=f"Expected CF IP: {ip_addr}")
        for ip_addr in non_cf_ips:
            self.assertFalse(webui.is_cloudflare_proxy_ip(ip_addr), msg=f"Expected non-CF IP: {ip_addr}")


class TestLocalProcNetAndRakNet(unittest.TestCase):
    """Tests for /proc/net/udp* parsing and RakNet UDP ping/pong helpers."""

    def test_get_bound_udp_ports_parses_hex_ports(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            udp4 = os.path.join(tmpdir, "udp")
            udp6 = os.path.join(tmpdir, "udp6")
            with open(udp4, "w", encoding="utf-8") as f:
                f.write("  sl  local_address rem_address   st tx_queue rx_queue\n")
                f.write("   0: 00000000:4ABC 00000000:0000 07 00000000:00000000\n")
            with open(udp6, "w", encoding="utf-8") as f:
                f.write("  sl  local_address                         remote_address\n")
                f.write("   0: 00000000000000000000000000000000:4ABD 00000000000000000000000000000000:0000 07\n")

            # Act
            res = webui.get_bound_udp_ports(proc_udp=udp4, proc_udp6=udp6)

            # Assert
            self.assertTrue(res["supported"])
            self.assertIn(19132, res["ipv4_ports"])
            self.assertIn(19133, res["ipv6_ports"])

    def test_get_bound_udp_ports_missing_files(self):
        # Arrange
        missing4 = os.path.join(tempfile.gettempdir(), "nonexistent_proc_udp_4")
        missing6 = os.path.join(tempfile.gettempdir(), "nonexistent_proc_udp_6")

        # Act
        res = webui.get_bound_udp_ports(proc_udp=missing4, proc_udp6=missing6)

        # Assert
        self.assertFalse(res["supported"])
        self.assertEqual(res["ipv4_ports"], set())
        self.assertEqual(res["ipv6_ports"], set())

    def test_build_and_parse_raknet_packets(self):
        # Arrange
        client_guid = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        pong_bytes = _build_mock_pong(motd="Pi World", version="1.26.45.1", online="3", max_p="10", guid="555666777")

        # Act
        ping_bytes = webui.build_raknet_ping_packet(client_guid=client_guid)
        parsed_pong = webui.parse_raknet_pong_packet(pong_bytes)
        bad_magic = webui.parse_raknet_pong_packet(b"\x1c" + b"\x00" * 40)
        short_pkt = webui.parse_raknet_pong_packet(b"\x1c\x01\x02")

        # Assert
        self.assertEqual(len(ping_bytes), 33)
        self.assertEqual(ping_bytes[0], 0x01)
        self.assertEqual(ping_bytes[9:25], webui.RAKNET_OFFLINE_MAGIC)
        self.assertEqual(ping_bytes[25:33], client_guid)
        self.assertIsNotNone(parsed_pong)
        self.assertEqual(parsed_pong["motd"], "Pi World")
        self.assertEqual(parsed_pong["version"], "1.26.45.1")
        self.assertEqual(parsed_pong["players_online"], "3")
        self.assertEqual(parsed_pong["players_max"], "10")
        self.assertEqual(parsed_pong["server_guid"], "555666777")
        self.assertIsNone(bad_magic)
        self.assertIsNone(short_pkt)


class TestChallengeAndSSRFProber(unittest.TestCase):
    """Tests for single-use verify tokens and SSRF protection in pinned HTTP probe."""

    def setUp(self):
        with webui._CHALLENGE_LOCK:
            webui._PENDING_CHALLENGES.clear()

    def test_challenge_single_use_and_replay_rejection(self):
        # Arrange
        cid, expected_proof = webui.create_verify_challenge()

        # Act
        first_read = webui.consume_verify_challenge(cid)
        replay_read = webui.consume_verify_challenge(cid)
        invalid_read = webui.consume_verify_challenge("not-a-valid-hex-id")

        # Assert
        self.assertEqual(first_read, expected_proof)
        self.assertIsNone(replay_read)
        self.assertIsNone(invalid_read)

    def test_challenge_expiration_and_capacity_eviction(self):
        # Arrange
        with mock.patch("webui.time.monotonic", return_value=100.0):
            cid_expired, _ = webui.create_verify_challenge()

        # Act
        with mock.patch("webui.time.monotonic", return_value=120.0):
            expired_result = webui.consume_verify_challenge(cid_expired)
            ids = [webui.create_verify_challenge()[0] for _ in range(webui.VERIFY_MAX_PENDING + 2)]
            oldest_after_cap = webui.consume_verify_challenge(ids[0])
            newest_after_cap = webui.consume_verify_challenge(ids[-1])

        # Assert
        self.assertIsNone(expired_result)
        self.assertIsNone(oldest_after_cap)
        self.assertIsNotNone(newest_after_cap)

    def test_probe_webui_blocks_private_pinned_ip_before_socket(self):
        # Arrange
        blocked_ips = ["127.0.0.1", "192.168.1.10", "::1", "::ffff:127.0.0.1"]

        # Act & Assert
        with mock.patch("webui.socket.create_connection") as mock_conn:
            for ip_addr in blocked_ips:
                res = webui.probe_webui_endpoint("http", "play.example.com", 8080, ip_addr, timeout=1.0)
                self.assertEqual(res["outcome"], "blocked")
                self.assertFalse(res["verified"])
            mock_conn.assert_not_called()


class TestConnectivityDiagnosticPipeline(unittest.TestCase):
    """Tests for run_connectivity_diagnostics scenarios with mocked probes."""

    def _base_patches(self):
        return {
            "read_properties": mock.patch("webui.read_properties", return_value={"server-port": "19132", "server-portv6": "19133"}),
            "get_service_status": mock.patch("webui.get_service_status", return_value="ACTIVE (RUNNING)"),
            "get_bound_udp_ports": mock.patch("webui.get_bound_udp_ports", return_value={"supported": True, "ipv4_ports": {19132}, "ipv6_ports": {19133}}),
            "get_local_lan_ipv4": mock.patch("webui.get_local_lan_ipv4", return_value="192.168.1.36"),
            "probe_raknet_udp": mock.patch("webui.probe_raknet_udp", return_value={"online": True, "latency_ms": 1.2, "version": "1.26.45.1", "players_online": "0", "players_max": "10", "server_guid": "11223344"}),
        }

    def test_healthy_direct_port_forwarding_and_https(self):
        # Arrange
        parsed, _ = webui.parse_server_address("play.example.com")
        patches = self._base_patches()
        with patches["read_properties"], patches["get_service_status"], patches["get_bound_udp_ports"], patches["get_local_lan_ipv4"], patches["probe_raknet_udp"], \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": ["93.184.216.34"], "ipv6": [], "non_public": [], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "93.184.216.34", "ipv6": "", "error": ""}), \
             mock.patch("webui.probe_external_bedrock", return_value={"reachable_api": True, "provider": "api.mcstatus.io", "online": True, "version": "1.26.45.1", "motd": "Pi", "players_online": 0, "players_max": 10, "server_guid": "11223344", "error": ""}), \
             mock.patch("webui.probe_webui_endpoint", return_value={"verified": True, "outcome": "verified", "status_code": 200}):
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        self.assertEqual(report["overall_status"], "PASS")
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(by_id["wan_ip_alignment"]["status"], "PASS")
        self.assertEqual(by_id["external_bedrock_udp"]["status"], "PASS")
        self.assertEqual(by_id["external_webui_access"]["status"], "PASS")

    def test_cloudflare_orange_cloud_proxy_fails(self):
        # Arrange
        parsed, _ = webui.parse_server_address("play.example.com")
        patches = self._base_patches()
        with patches["read_properties"], patches["get_service_status"], patches["get_bound_udp_ports"], patches["get_local_lan_ipv4"], patches["probe_raknet_udp"], \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": ["104.21.10.20"], "ipv6": [], "non_public": [], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "93.184.216.34", "ipv6": "", "error": ""}), \
             mock.patch("webui.probe_external_bedrock", return_value={"reachable_api": True, "provider": "api.mcstatus.io", "online": False, "version": "", "motd": "", "players_online": 0, "players_max": 0, "server_guid": "", "error": ""}), \
             mock.patch("webui.probe_webui_endpoint", return_value={"verified": True, "outcome": "verified", "status_code": 200}):
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(report["overall_status"], "FAIL")
        self.assertTrue(report["cloudflare_proxied"])
        self.assertEqual(by_id["wan_ip_alignment"]["status"], "FAIL")
        self.assertIn("Grey Cloud", by_id["wan_ip_alignment"]["remediation"])

    def test_udp_tunnel_playit_topology_passes(self):
        # Arrange
        parsed, _ = webui.parse_server_address("tunnel.example.com:25565")
        patches = self._base_patches()
        with patches["read_properties"], patches["get_service_status"], patches["get_bound_udp_ports"], patches["get_local_lan_ipv4"], patches["probe_raknet_udp"], \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": ["147.185.221.18"], "ipv6": [], "non_public": [], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "93.184.216.34", "ipv6": "", "error": ""}), \
             mock.patch("webui.probe_external_bedrock", return_value={"reachable_api": True, "provider": "api.mcstatus.io", "online": True, "version": "1.26.45.1", "motd": "Pi", "players_online": 1, "players_max": 10, "server_guid": "11223344", "error": ""}), \
             mock.patch("webui.probe_webui_endpoint", return_value={"verified": True, "outcome": "verified", "status_code": 200}):
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(report["overall_status"], "PASS")
        self.assertEqual(report["effective_bedrock_port"], 25565)
        self.assertEqual(by_id["wan_ip_alignment"]["status"], "PASS")
        self.assertIn("tunnel", by_id["wan_ip_alignment"]["detail"].lower())

    def test_dns_resolving_private_ip_blocks_outbound_probes(self):
        # Arrange
        parsed, _ = webui.parse_server_address("internal.example.com")
        patches = self._base_patches()
        with patches["read_properties"], patches["get_service_status"], patches["get_bound_udp_ports"], patches["get_local_lan_ipv4"], patches["probe_raknet_udp"], \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": [], "ipv6": [], "non_public": ["192.168.1.50"], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "93.184.216.34", "ipv6": "", "error": ""}), \
             mock.patch("webui.probe_external_bedrock") as mock_ext_mc, \
             mock.patch("webui.probe_webui_endpoint") as mock_ext_web:
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(report["overall_status"], "FAIL")
        self.assertEqual(by_id["dns_resolution"]["status"], "FAIL")
        self.assertIn("SSRF", by_id["dns_resolution"]["detail"])
        mock_ext_mc.assert_not_called()
        mock_ext_web.assert_not_called()

    def test_plaintext_http_webui_warns_about_owasp_asvs(self):
        # Arrange
        parsed, _ = webui.parse_server_address("play.example.com")
        patches = self._base_patches()
        probe_side_effect = [
            {"verified": False, "outcome": "refused", "status_code": 0},
            {"verified": True, "outcome": "verified", "status_code": 200},
        ]
        with patches["read_properties"], patches["get_service_status"], patches["get_bound_udp_ports"], patches["get_local_lan_ipv4"], patches["probe_raknet_udp"], \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": ["93.184.216.34"], "ipv6": [], "non_public": [], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "93.184.216.34", "ipv6": "", "error": ""}), \
             mock.patch("webui.probe_external_bedrock", return_value={"reachable_api": True, "provider": "api.mcstatus.io", "online": True, "version": "1.26.45.1", "motd": "Pi", "players_online": 0, "players_max": 10, "server_guid": "11223344", "error": ""}), \
             mock.patch("webui.probe_webui_endpoint", side_effect=probe_side_effect):
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(report["overall_status"], "WARN")
        self.assertEqual(by_id["external_webui_access"]["status"], "WARN")
        self.assertIn("OWASP ASVS", by_id["external_webui_access"]["detail"])
        self.assertIn("HTTPS", by_id["external_webui_access"]["remediation"])

    def test_ipv6_aaaa_record_runs_external_ipv6_check(self):
        # Arrange
        parsed, _ = webui.parse_server_address("dual.example.com")
        patches = self._base_patches()
        v6_ip = "2606:2800:220:1:248:1893:25c8:1946"
        with patches["read_properties"], patches["get_service_status"], patches["get_bound_udp_ports"], patches["get_local_lan_ipv4"], patches["probe_raknet_udp"], \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": ["93.184.216.34"], "ipv6": [v6_ip], "non_public": [], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "93.184.216.34", "ipv6": v6_ip, "error": ""}), \
             mock.patch("webui.probe_external_bedrock", return_value={"reachable_api": True, "provider": "api.mcstatus.io", "online": True, "version": "1.26.45.1", "motd": "Pi", "players_online": 0, "players_max": 10, "server_guid": "11223344", "error": ""}) as mock_mc, \
             mock.patch("webui.probe_webui_endpoint", return_value={"verified": True, "outcome": "verified", "status_code": 200}):
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(by_id["external_bedrock_ipv6"]["status"], "PASS")
        self.assertEqual(mock_mc.call_count, 2)
        mock_mc.assert_any_call(v6_ip, 19133, is_ipv6=True)


class TestWebUIServerIntegration(unittest.TestCase):
    """Live HTTP integration tests against ThreadingWebUIServer on 127.0.0.1."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.auth_file = os.path.join(self.tmpdir.name, "auth.json")
        self.addr_file = os.path.join(self.tmpdir.name, "address_config.json")
        self.props_file = os.path.join(self.tmpdir.name, "server.properties")
        self.allow_file = os.path.join(self.tmpdir.name, "allowlist.json")
        self.perm_file = os.path.join(self.tmpdir.name, "permissions.json")
        self.bk_cfg_file = os.path.join(self.tmpdir.name, "backup_config.json")
        self.bk_dir = os.path.join(self.tmpdir.name, "backups")
        os.makedirs(self.bk_dir, exist_ok=True)
        with open(self.auth_file, "w", encoding="utf-8") as f:
            json.dump({"admin_pass": "testpass99"}, f)
        with open(self.props_file, "w", encoding="utf-8") as f:
            f.write("server-name=TestPi\nserver-port=19132\nserver-portv6=19133\n")

        self.patchers = [
            mock.patch.object(webui, "AUTH_FILE", self.auth_file),
            mock.patch.object(webui, "ADDRESS_CONFIG_FILE", self.addr_file),
            mock.patch.object(webui, "PROPERTIES_FILE", self.props_file),
            mock.patch.object(webui, "ALLOWLIST_FILE", self.allow_file),
            mock.patch.object(webui, "PERMISSIONS_FILE", self.perm_file),
            mock.patch.object(webui, "BACKUP_CONFIG_FILE", self.bk_cfg_file),
            mock.patch.object(webui, "BACKUP_DIR", self.bk_dir),
            mock.patch.object(webui, "get_service_status", return_value="ACTIVE (RUNNING)"),
            mock.patch.object(webui, "get_device_stats", return_value={
                "uptime": "1d 2h 3m", "cpu_temp": "45.0 °C", "load_avg": "0.10, 0.12, 0.08",
                "root_used_gb": 5.0, "root_total_gb": 32.0, "root_pct": 15.6, "root_free_gb": 27.0,
                "worlds_path": "/opt/minecraft/bedrock/worlds", "is_external_worlds": False,
                "worlds_used_gb": 1.0, "worlds_total_gb": 32.0, "worlds_pct": 3.1,
                "ram_used_mb": 512, "ram_total_mb": 4096, "ram_pct": 12.5, "ram_free_mb": 3584,
                "swap_used_mb": 0, "swap_total_mb": 2048, "swap_pct": 0.0, "swap_free_mb": 2048,
            }),
        ]
        for p in self.patchers:
            p.start()

        self.server = webui.ThreadingWebUIServer(("127.0.0.1", 0), webui.WebUIHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        token = base64.b64encode(b"admin:testpass99").decode("ascii")
        self.auth_headers = {"Authorization": f"Basic {token}"}

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        for p in reversed(self.patchers):
            p.stop()
        self.tmpdir.cleanup()

    def _request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read()
            return resp.status, dict(resp.getheaders()), data
        finally:
            conn.close()

    def test_verify_challenge_endpoint_unauthenticated_and_single_use(self):
        # Arrange
        cid, expected_proof = webui.create_verify_challenge()

        # Act
        s1, _, b1 = self._request("GET", f"{webui.VERIFY_PATH_PREFIX}{cid}")
        s2, _, _ = self._request("GET", f"{webui.VERIFY_PATH_PREFIX}{cid}")
        s3, _, _ = self._request("GET", f"{webui.VERIFY_PATH_PREFIX}invalidtoken")
        s_admin, _, _ = self._request("GET", "/")

        # Assert
        self.assertEqual(s1, 200)
        self.assertEqual(json.loads(b1.decode("utf-8"))["proof"], expected_proof)
        self.assertEqual(s2, 404)
        self.assertEqual(s3, 404)
        self.assertEqual(s_admin, 401)

    def test_save_recheck_clear_and_xss_escaping(self):
        # Arrange
        fake_report = {
            "overall_status": "WARN",
            "checked_utc": "2026-11-19 16:00:00 UTC",
            "lan_ip": "192.168.1.36",
            "wan_ipv4": "93.184.216.34",
            "wan_ipv6": "",
            "effective_bedrock_port": 19132,
            "effective_bedrock_port_v6": 19133,
            "resolved_ipv4": ["93.184.216.34"],
            "resolved_ipv6": [],
            "cloudflare_proxied": False,
            "checks": [
                {
                    "id": "external_webui_access",
                    "category": "External Web UI",
                    "label": "External Web UI Reachability",
                    "status": "WARN",
                    "detail": "Probe note with <script>alert(1)</script>",
                    "remediation": "Enable HTTPS reverse proxy",
                }
            ],
        }

        with mock.patch("webui.run_connectivity_diagnostics", return_value=fake_report) as mock_diag:
            # Act: reject private IP
            hdrs_post = {**self.auth_headers, "Content-Type": "application/x-www-form-urlencoded"}
            s_priv, h_priv, _ = self._request("POST", "/address/save", body="address=192.168.1.1", headers=hdrs_post)
            # Act: save valid domain
            s_save, h_save, _ = self._request("POST", "/address/save", body="address=play.example.com", headers=hdrs_post)
            s_get, _, html_body = self._request("GET", "/?addr_msg=saved_checked", headers=self.auth_headers)
            # Act: manual recheck and clear
            s_chk, h_chk, _ = self._request("POST", "/address/check", body="", headers=hdrs_post)
            s_clr, h_clr, _ = self._request("POST", "/address/clear", body="", headers=hdrs_post)

        # Assert
        self.assertEqual(s_priv, 303)
        self.assertEqual(h_priv.get("Location"), "/?addr_err=private_ip")
        self.assertEqual(s_save, 303)
        self.assertEqual(h_save.get("Location"), "/?addr_msg=saved_checked")
        self.assertEqual(mock_diag.call_count, 2)
        self.assertEqual(s_get, 200)
        page = html_body.decode("utf-8")
        self.assertIn("Address &amp; Connectivity Management", page)
        self.assertIn("play.example.com:19132", page)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertEqual(s_chk, 303)
        self.assertEqual(h_chk.get("Location"), "/?addr_msg=rechecked")
        self.assertEqual(s_clr, 303)
        self.assertEqual(h_clr.get("Location"), "/?addr_msg=cleared")
        self.assertEqual(webui.read_address_config()["host"], "")


if __name__ == "__main__":
    unittest.main()
