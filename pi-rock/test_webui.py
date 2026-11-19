#!/usr/bin/env python3
"""
IEEE 29119 Unit & Integration Test Suite for pi-rock/webui.py Address Management.
Follows strict Arrange-Act-Assert (AAA) structure with pure Python standard library.
"""

import base64
import http.client
import http.server
import io
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
import zipfile
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

    def test_get_bound_tcp_ports_filters_listen_state_0a(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            tcp4 = os.path.join(tmpdir, "tcp")
            tcp6 = os.path.join(tmpdir, "tcp6")
            with open(tcp4, "w", encoding="utf-8") as f:
                f.write("  sl  local_address rem_address   st tx_queue rx_queue\n")
                f.write("   0: 00000000:1F90 00000000:0000 0A 00000000:00000000\n")
                f.write("   1: 0100007F:9999 0100007F:1F90 01 00000000:00000000\n")
            with open(tcp6, "w", encoding="utf-8") as f:
                f.write("  sl  local_address                         remote_address                        st\n")
                f.write("   0: 00000000000000000000000000000000:4ABC 00000000000000000000000000000000:0000 0A\n")
                f.write("   1: 00000000000000000000000000000000:4ABD 00000000000000000000000000000000:0000 06\n")

            # Act
            res = webui.get_bound_tcp_ports(proc_tcp=tcp4, proc_tcp6=tcp6)

            # Assert
            self.assertTrue(res["supported"])
            self.assertIn(8080, res["ipv4_ports"])
            self.assertNotIn(0x9999, res["ipv4_ports"])
            self.assertIn(19132, res["ipv6_ports"])
            self.assertNotIn(19133, res["ipv6_ports"])

    def test_detect_bedrock_transport_variants(self):
        # Arrange & Act & Assert
        tcp_19132 = {"supported": True, "ipv4_ports": set(), "ipv6_ports": {19132}}
        udp_none = {"supported": True, "ipv4_ports": {7551}, "ipv6_ports": set()}
        udp_19132 = {"supported": True, "ipv4_ports": {19132}, "ipv6_ports": set()}
        tcp_none = {"supported": True, "ipv4_ports": set(), "ipv6_ports": set()}

        self.assertEqual(webui.detect_bedrock_transport({"transport": "nethernet"}, 19132, tcp_none, udp_19132), "nethernet")
        self.assertEqual(webui.detect_bedrock_transport({"transport": "raknet"}, 19132, tcp_19132, udp_none), "raknet")
        self.assertEqual(webui.detect_bedrock_transport({"server-udp-ports": "19132"}, 19132, tcp_none, udp_none), "nethernet")
        self.assertEqual(webui.detect_bedrock_transport({}, 19132, tcp_19132, udp_none), "nethernet")
        self.assertEqual(webui.detect_bedrock_transport({}, 19132, tcp_none, udp_19132), "raknet")

    def test_probe_nethernet_http_live_and_ssrf_block(self):
        # Arrange
        class _JoinHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/v1/join":
                    payload = b'{"name":"Dedicated Server","protocol":2225,"version":"1.26.66","level":"Bedrock level","players":1,"maxPlayers":10,"gameType":0}'
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                pass

        srv = http.server.HTTPServer(("127.0.0.1", 0), _JoinHandler)
        port = srv.server_address[1]
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        try:
            # Act
            live_res = webui.probe_nethernet_http("127.0.0.1", port, pinned=False, timeout=2.0)
            with mock.patch("webui.socket.create_connection") as mock_sock:
                ssrf_res = webui.probe_nethernet_http("127.0.0.1", port, host_header="mc.example.com", pinned=True, timeout=2.0)
        finally:
            srv.shutdown()
            srv.server_close()

        # Assert
        self.assertTrue(live_res["online"])
        self.assertEqual(live_res["version"], "1.26.66")
        self.assertEqual(live_res["protocol"], "2225")
        self.assertEqual(live_res["players"], 1)
        self.assertEqual(live_res["max_players"], 10)
        self.assertFalse(ssrf_res["online"])
        self.assertEqual(ssrf_res["outcome"], "blocked")
        mock_sock.assert_not_called()


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

    def setUp(self):
        self._tcp_patch = mock.patch("webui.get_bound_tcp_ports", return_value={"supported": True, "ipv4_ports": set(), "ipv6_ports": set()})
        self._allow_patch = mock.patch("webui.read_allowlist", return_value=[])
        self._tcp_patch.start()
        self._allow_patch.start()

    def tearDown(self):
        self._allow_patch.stop()
        self._tcp_patch.stop()

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

    def test_nethernet_healthy_pass_and_allowlist_populated(self):
        # Arrange
        parsed, _ = webui.parse_server_address("mc.wuffs.xyz")
        props = {"server-port": "19132", "server-portv6": "19133", "transport": "nethernet", "server-udp-ports": "19132", "allow-list": "true"}
        tcp_bound = {"supported": True, "ipv4_ports": set(), "ipv6_ports": {19132}}
        udp_bound = {"supported": True, "ipv4_ports": {7551}, "ipv6_ports": set()}
        join_ok = {"online": True, "outcome": "ok", "latency_ms": 1.5, "name": "Dedicated Server", "version": "1.26.66", "protocol": "2225", "level": "Bedrock level", "players": 0, "max_players": 10}
        with mock.patch("webui.read_properties", return_value=props), \
             mock.patch("webui.get_service_status", return_value="ACTIVE (RUNNING)"), \
             mock.patch("webui.get_bound_tcp_ports", return_value=tcp_bound), \
             mock.patch("webui.get_bound_udp_ports", return_value=udp_bound), \
             mock.patch("webui.read_allowlist", return_value=[{"name": "PlayerOne"}]), \
             mock.patch("webui.get_local_lan_ipv4", return_value="192.168.0.36"), \
             mock.patch("webui.probe_nethernet_http", return_value=join_ok), \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": ["90.202.94.179"], "ipv6": [], "non_public": [], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "90.202.94.179", "ipv6": "", "error": ""}), \
             mock.patch("webui.probe_external_bedrock", return_value={"reachable_api": True, "provider": "api.mcstatus.io", "online": False, "version": "", "motd": "", "players_online": 0, "players_max": 0, "server_guid": "", "error": ""}), \
             mock.patch("webui.probe_webui_endpoint", return_value={"verified": True, "outcome": "verified", "status_code": 200}):
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(report["transport"], "nethernet")
        self.assertEqual(report["overall_status"], "PASS")
        self.assertEqual(by_id["local_udp_binding"]["status"], "PASS")
        self.assertEqual(by_id["local_raknet_ping"]["status"], "PASS")
        self.assertEqual(by_id["allowlist_readiness"]["status"], "PASS")
        self.assertEqual(by_id["external_bedrock_udp"]["status"], "PASS")

    def test_nethernet_hairpin_timeout_and_empty_allowlist_warn(self):
        # Arrange
        parsed, _ = webui.parse_server_address("mc.wuffs.xyz")
        props = {"server-port": "19132", "server-portv6": "19133", "transport": "nethernet", "server-udp-ports": "19132", "allow-list": "true"}
        tcp_bound = {"supported": True, "ipv4_ports": set(), "ipv6_ports": {19132}}
        udp_bound = {"supported": True, "ipv4_ports": {7551}, "ipv6_ports": set()}
        join_local = {"online": True, "outcome": "ok", "latency_ms": 1.1, "name": "Dedicated Server", "version": "1.26.66", "protocol": "2225", "level": "Bedrock level", "players": 0, "max_players": 10}
        join_timeout = {"online": False, "outcome": "timeout", "error": "HTTP timeout"}
        with mock.patch("webui.read_properties", return_value=props), \
             mock.patch("webui.get_service_status", return_value="ACTIVE (RUNNING)"), \
             mock.patch("webui.get_bound_tcp_ports", return_value=tcp_bound), \
             mock.patch("webui.get_bound_udp_ports", return_value=udp_bound), \
             mock.patch("webui.read_allowlist", return_value=[]), \
             mock.patch("webui.get_local_lan_ipv4", return_value="192.168.0.36"), \
             mock.patch("webui.probe_nethernet_http", side_effect=[join_local, join_timeout]), \
             mock.patch("webui.resolve_host_ips", return_value={"ipv4": ["90.202.94.179"], "ipv6": [], "non_public": [], "error": ""}), \
             mock.patch("webui.fetch_public_ips", return_value={"ipv4": "90.202.94.179", "ipv6": "", "error": ""}), \
             mock.patch("webui.probe_external_bedrock", return_value={"reachable_api": True, "provider": "api.mcsrvstat.us", "online": False, "version": "", "motd": "", "players_online": 0, "players_max": 0, "server_guid": "", "error": ""}), \
             mock.patch("webui.probe_webui_endpoint", return_value={"verified": False, "outcome": "timeout", "status_code": 0}):
            # Act
            report = webui.run_connectivity_diagnostics(parsed)

        # Assert
        by_id = {c["id"]: c for c in report["checks"]}
        self.assertEqual(report["overall_status"], "WARN")
        self.assertEqual(by_id["allowlist_readiness"]["status"], "WARN")
        self.assertEqual(by_id["external_bedrock_udp"]["status"], "WARN")
        self.assertIn("TCP and UDP port 19132", by_id["external_bedrock_udp"]["remediation"])
        self.assertIn("NAT hairpinning", by_id["external_bedrock_udp"]["detail"])


class TestWebUIServerIntegration(unittest.TestCase):
    """Live HTTP integration tests against ThreadingWebUIServer on 127.0.0.1."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.auth_file = os.path.join(self.tmpdir.name, "auth.json")
        self.addr_file = os.path.join(self.tmpdir.name, "address_config.json")
        self.update_status_file = os.path.join(self.tmpdir.name, "update_status.json")
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
            mock.patch.object(webui, "UPDATE_STATUS_FILE", self.update_status_file),
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

    def test_system_reinstall_post_requires_auth_and_redirects(self):
        # Arrange
        with open(self.update_status_file, "w", encoding="utf-8") as f:
            json.dump({
                "status": "SUCCESS",
                "commit_sha": "288e5dd000000000000000000000000000000000",
                "commit_short": "288e5dd",
                "commit_subject": "feat: address <script>x</script>",
                "updated_utc": "2026-11-19 16:30:00 UTC",
                "trigger": "webui",
                "message": "Done",
            }, f)

        # Act
        s_unauth, _, _ = self._request("POST", "/system/reinstall", body="")
        with mock.patch("webui.trigger_force_reinstall", return_value="started") as mock_trig:
            s_post, h_post, _ = self._request("POST", "/system/reinstall", body="", headers=self.auth_headers)
        s_get, _, html_body = self._request("GET", "/?update_msg=started", headers=self.auth_headers)

        # Assert
        self.assertEqual(s_unauth, 401)
        mock_trig.assert_called_once()
        self.assertEqual(s_post, 303)
        self.assertEqual(h_post.get("Location"), "/?update_msg=started")
        self.assertEqual(s_get, 200)
        page = html_body.decode("utf-8")
        self.assertIn("Software Version &amp; Force Reinstall", page)
        self.assertIn("288e5dd", page)
        self.assertIn("&lt;script&gt;x&lt;/script&gt;", page)
        self.assertNotIn("<script>x</script>", page)
        self.assertIn("Full GitHub reinstall started in the background.", page)


class TestReinstallControlsAndInstallerSync(unittest.TestCase):
    """Tests for update status reader, reinstall trigger, UI escaping, and installer sync."""

    def test_read_update_status_defaults_valid_and_corrupt(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_path = os.path.join(tmpdir, "missing.json")
            valid_path = os.path.join(tmpdir, "valid.json")
            corrupt_path = os.path.join(tmpdir, "corrupt.json")
            with open(valid_path, "w", encoding="utf-8") as f:
                json.dump({"status": "SUCCESS", "commit_short": "abc1234"}, f)
            with open(corrupt_path, "w", encoding="utf-8") as f:
                f.write("{bad json")

            # Act
            with mock.patch.object(webui, "UPDATE_STATUS_FILE", missing_path):
                d_res = webui.read_update_status()
            with mock.patch.object(webui, "UPDATE_STATUS_FILE", valid_path):
                v_res = webui.read_update_status()
            with mock.patch.object(webui, "UPDATE_STATUS_FILE", corrupt_path):
                c_res = webui.read_update_status()

            # Assert
            self.assertEqual(d_res["status"], "UNKNOWN")
            self.assertEqual(d_res["commit_short"], "Unknown")
            self.assertEqual(v_res["status"], "SUCCESS")
            self.assertEqual(v_res["commit_short"], "abc1234")
            self.assertEqual(c_res["status"], "UNKNOWN")

    def test_trigger_force_reinstall_handles_all_outcomes(self):
        # Arrange & Act & Assert
        with mock.patch("webui.os.path.exists", return_value=False), \
             mock.patch("webui.subprocess.run") as mock_run:
            self.assertEqual(webui.trigger_force_reinstall(), "unavailable")
            mock_run.assert_not_called()

        cases = [
            (mock.Mock(returncode=0, stderr=""), "started"),
            (mock.Mock(returncode=2, stderr="locked"), "already_running"),
            (mock.Mock(returncode=1, stderr="sudo: a password is required"), "unavailable"),
            (mock.Mock(returncode=1, stderr="unexpected error"), "failed_launch"),
        ]
        for proc_res, exp_code in cases:
            with self.subTest(exp_code=exp_code):
                with mock.patch("webui.os.path.exists", return_value=True), \
                     mock.patch("webui.subprocess.run", return_value=proc_res) as mock_run:
                    code = webui.trigger_force_reinstall()
                    self.assertEqual(code, exp_code)
                    mock_run.assert_called_once_with(
                        ["sudo", "-n", webui.REINSTALL_BIN, "--async"],
                        capture_output=True,
                        text=True,
                        timeout=15,
                    )

        with mock.patch("webui.os.path.exists", return_value=True), \
             mock.patch("webui.subprocess.run", side_effect=OSError("boom")):
            self.assertEqual(webui.trigger_force_reinstall(), "failed_launch")

    def test_render_reinstall_card_escapes_html_and_ignores_unknown_flash(self):
        # Arrange
        status = {
            "status": "ROLLED_BACK",
            "commit_sha": "deadbeef",
            "commit_short": "deadbeef",
            "commit_subject": "<img src=x onerror=alert(1)>",
            "updated_utc": "2026-11-19 16:30:00 UTC",
            "trigger": "cli",
            "message": "Rolled back <b>now</b>",
        }

        # Act
        card_html = webui.render_reinstall_card(status, flash_code="<script>bad</script>")

        # Assert
        self.assertIn("ROLLED_BACK", card_html)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", card_html)
        self.assertIn("Rolled back &lt;b&gt;now&lt;/b&gt;", card_html)
        self.assertNotIn("<img src=x", card_html)
        self.assertNotIn("<script>bad</script>", card_html)

    def test_installer_contains_mc_reinstall_sudoers_git_and_synced_webui(self):
        # Arrange
        base_dir = os.path.dirname(os.path.abspath(__file__))
        sh_path = os.path.join(base_dir, "setup_bedrock_server.sh")
        py_path = os.path.join(base_dir, "webui.py")
        with open(sh_path, "rb") as f:
            sh_bytes = f.read()
        with open(py_path, "rb") as f:
            py_bytes = f.read()
        sh_text = sh_bytes.decode("utf-8")

        # Act
        start_marker = b"cat > \"${webui_script}\" << 'PYEOF'\r\n"
        end_marker = b"\r\nPYEOF\r\n"
        s = sh_bytes.index(start_marker) + len(start_marker)
        e = sh_bytes.index(end_marker, s)
        embedded = sh_bytes[s:e]

        # Assert
        self.assertEqual(embedded, py_bytes.rstrip(b"\r\n"))
        self.assertIn("chmod 755 /usr/local/bin/mc-reinstall.tmp", sh_text)
        self.assertIn("mv -f /usr/local/bin/mc-reinstall.tmp /usr/local/bin/mc-reinstall", sh_text)
        self.assertIn("/usr/local/bin/mc-reinstall --async", sh_text)
        sudoers_line = [ln for ln in sh_text.splitlines() if ln.startswith("mcserver ALL=(ALL) NOPASSWD:")]
        self.assertEqual(len(sudoers_line), 1)
        self.assertNotIn("*", sudoers_line[0])
        self.assertIn("git", sh_text.split("install_system_dependencies()", 1)[1].split("}", 1)[0])
        fw_block = sh_text.split("configure_firewall()", 1)[1].split("}", 1)[0]
        self.assertIn("19132/tcp", fw_block)
        self.assertIn("19133/tcp", fw_block)
        self.assertIn("7551/udp", fw_block)
        self.assertIn("sed -i '/^white-list=/d'", sh_text)

    def test_legacy_whitelist_removed_on_save_and_flagged_in_diagnostics(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            props_path = os.path.join(tmpdir, "server.properties")
            with open(props_path, "w", encoding="utf-8") as f:
                f.write("server-port=19132\nallow-list=true\nwhite-list=true\n")

            # Act
            with mock.patch.object(webui, "PROPERTIES_FILE", props_path):
                webui.save_properties({"allow-list": "false"})
                updated = webui.read_properties()
            with mock.patch("webui.read_allowlist", return_value=[]):
                warn_chk = webui._check_allowlist_readiness({"allow-list": "false", "white-list": "true"})

        # Assert
        self.assertNotIn("white-list", webui.VALID_PROPERTIES)
        self.assertIn("allow-list", webui.VALID_PROPERTIES)
        self.assertEqual(updated.get("allow-list"), "false")
        self.assertNotIn("white-list", updated)
        self.assertEqual(warn_chk["status"], "WARN")
        self.assertIn("white-list=true", warn_chk["detail"])


class TestExternalUSBBackupStorage(unittest.TestCase):
    """Tests for USB drive detection, auto-mounting, fallback, uncompressed backups, and Web UI controls."""

    def test_detect_external_usb_drives_filters_system_and_identifies_windows_fs(self):
        # Arrange
        lsblk_payload = {
            "blockdevices": [
                {
                    "name": "mmcblk0", "kname": "mmcblk0", "path": "/dev/mmcblk0",
                    "tran": None, "rm": False, "hotplug": False, "type": "disk",
                    "fstype": None, "label": None, "uuid": None, "size": 32000000000,
                    "mountpoint": None,
                    "children": [
                        {
                            "name": "mmcblk0p1", "kname": "mmcblk0p1", "path": "/dev/mmcblk0p1",
                            "tran": None, "type": "part", "fstype": "vfat", "label": "bootfs",
                            "uuid": "BOOT-1", "size": 536870912, "mountpoint": "/boot/firmware",
                        },
                        {
                            "name": "mmcblk0p2", "kname": "mmcblk0p2", "path": "/dev/mmcblk0p2",
                            "tran": None, "type": "part", "fstype": "ext4", "label": "rootfs",
                            "uuid": "ROOT-2", "size": 31000000000, "mountpoint": "/",
                        },
                    ],
                },
                {
                    "name": "sda", "kname": "sda", "path": "/dev/sda",
                    "tran": "usb", "rm": True, "hotplug": True, "type": "disk",
                    "fstype": None, "label": None, "uuid": None, "size": 64 * (1024 ** 3),
                    "mountpoint": None,
                    "children": [
                        {
                            "name": "sda1", "kname": "sda1", "path": "/dev/sda1",
                            "tran": None, "type": "part", "fstype": "exfat", "label": "WIN_MC",
                            "uuid": "CAFE-BEEF", "size": 64 * (1024 ** 3), "mountpoint": "/media/mc-usb/CAFE-BEEF",
                        }
                    ],
                },
                {
                    "name": "sdb", "kname": "sdb", "path": "/dev/sdb",
                    "tran": "usb", "rm": True, "hotplug": True, "type": "disk",
                    "fstype": None, "label": None, "uuid": None, "size": 32 * (1024 ** 3),
                    "mountpoint": None,
                    "children": [
                        {
                            "name": "sdb1", "kname": "sdb1", "path": "/dev/sdb1",
                            "tran": None, "type": "part", "fstype": "ext4", "label": "LINUX_USB",
                            "uuid": "EXT4-9999", "size": 32 * (1024 ** 3), "mountpoint": None,
                        }
                    ],
                },
            ]
        }
        mock_proc = mock.Mock(returncode=0, stdout=json.dumps(lsblk_payload))

        # Act
        with mock.patch("webui.subprocess.run", return_value=mock_proc):
            drives = webui.detect_external_usb_drives()

        # Assert
        self.assertEqual(len(drives), 2)
        devices = [d["device"] for d in drives]
        self.assertNotIn("/dev/mmcblk0", devices)
        self.assertNotIn("/dev/mmcblk0p1", devices)
        self.assertNotIn("/dev/mmcblk0p2", devices)
        self.assertEqual(drives[0]["device"], "/dev/sda1")
        self.assertEqual(drives[0]["id"], "usb:UUID=CAFE-BEEF")
        self.assertTrue(drives[0]["windows_compatible"])
        self.assertEqual(drives[0]["size_gb"], 64.0)
        self.assertEqual(drives[1]["device"], "/dev/sdb1")
        self.assertFalse(drives[1]["windows_compatible"])

    def test_resolve_backup_storage_usb_active_auto_mount_and_unplugged_fallback(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            default_dir = os.path.join(tmpdir, "default_backups")
            usb_mp_mounted = os.path.join(tmpdir, "usb_mounted")
            usb_mp_automount = os.path.join(tmpdir, "usb_automount")
            os.makedirs(default_dir, exist_ok=True)
            os.makedirs(usb_mp_mounted, exist_ok=True)
            os.makedirs(usb_mp_automount, exist_ok=True)

            mounted_drive = {
                "device": "/dev/sda1", "kname": "sda1", "uuid": "AAA-111", "label": "WINUSB",
                "fstype": "exfat", "size_gb": 32.0, "mountpoint": usb_mp_mounted,
                "windows_compatible": True, "id": "usb:UUID=AAA-111",
                "backup_dir": os.path.join(usb_mp_mounted, "minecraft_backups"),
            }
            unmounted_drive = {
                "device": "/dev/sda1", "kname": "sda1", "uuid": "AAA-111", "label": "WINUSB",
                "fstype": "vfat", "size_gb": 32.0, "mountpoint": "",
                "windows_compatible": True, "id": "usb:UUID=AAA-111", "backup_dir": "",
            }
            ext4_drive = {
                "device": "/dev/sdb1", "kname": "sdb1", "uuid": "BBB-222", "label": "EXTUSB",
                "fstype": "ext4", "size_gb": 16.0, "mountpoint": "",
                "windows_compatible": False, "id": "usb:UUID=BBB-222", "backup_dir": "",
            }
            usb_cfg = {"backup_location": "usb:UUID=AAA-111", "usb_uuid": "AAA-111", "usb_device": "/dev/sda1"}

            with mock.patch.object(webui, "BACKUP_DIR", default_dir):
                # Act
                res_default = webui.resolve_backup_storage(backup_cfg={"backup_location": "default"}, drives=[mounted_drive])
                res_mounted = webui.resolve_backup_storage(backup_cfg=usb_cfg, drives=[mounted_drive])
                with mock.patch("webui.auto_mount_usb_drive", return_value=(True, usb_mp_automount, "")) as mock_mount:
                    res_automount = webui.resolve_backup_storage(backup_cfg=usb_cfg, drives=[unmounted_drive])
                res_incompat = webui.resolve_backup_storage(backup_cfg={"backup_location": "usb:UUID=BBB-222"}, drives=[ext4_drive])
                res_unplugged = webui.resolve_backup_storage(backup_cfg=usb_cfg, drives=[])

                # Assert
                self.assertEqual(res_default["status"], "default")
                self.assertEqual(res_default["active_dir"], default_dir)
                self.assertFalse(res_default["is_usb_active"])

                self.assertEqual(res_mounted["status"], "usb_active")
                self.assertTrue(res_mounted["is_usb_active"])
                self.assertEqual(res_mounted["format_type"], "uncompressed_folder")
                self.assertEqual(res_mounted["active_dir"], os.path.join(usb_mp_mounted, "minecraft_backups"))
                self.assertTrue(os.path.isdir(res_mounted["active_dir"]))

                mock_mount.assert_called_once_with("/dev/sda1")
                self.assertEqual(res_automount["status"], "usb_active")
                self.assertEqual(res_automount["active_dir"], os.path.join(usb_mp_automount, "minecraft_backups"))

                self.assertEqual(res_incompat["status"], "usb_incompatible_fs")
                self.assertTrue(res_incompat["is_fallback"])
                self.assertEqual(res_incompat["active_dir"], default_dir)

                self.assertEqual(res_unplugged["status"], "usb_unplugged_fallback")
                self.assertTrue(res_unplugged["is_fallback"])
                self.assertEqual(res_unplugged["active_dir"], default_dir)

    def _start_test_server(self, tmpdir, usb_drives_patch=None):
        auth_file = os.path.join(tmpdir, "auth.json")
        addr_file = os.path.join(tmpdir, "address_config.json")
        update_file = os.path.join(tmpdir, "update_status.json")
        base_dir = os.path.join(tmpdir, "bedrock")
        props_file = os.path.join(base_dir, "server.properties")
        allow_file = os.path.join(base_dir, "allowlist.json")
        perm_file = os.path.join(base_dir, "permissions.json")
        bk_cfg_file = os.path.join(tmpdir, "backup_config.json")
        bk_dir = os.path.join(tmpdir, "backups")
        os.makedirs(os.path.join(base_dir, "worlds"), exist_ok=True)
        os.makedirs(bk_dir, exist_ok=True)
        with open(auth_file, "w", encoding="utf-8") as f:
            json.dump({"admin_pass": "testpass99"}, f)
        with open(props_file, "w", encoding="utf-8") as f:
            f.write("server-name=TestPi\nlevel-name=Bedrock level\nserver-port=19132\n")

        patchers = [
            mock.patch.object(webui, "AUTH_FILE", auth_file),
            mock.patch.object(webui, "ADDRESS_CONFIG_FILE", addr_file),
            mock.patch.object(webui, "UPDATE_STATUS_FILE", update_file),
            mock.patch.object(webui, "BASE_DIR", base_dir),
            mock.patch.object(webui, "PROPERTIES_FILE", props_file),
            mock.patch.object(webui, "ALLOWLIST_FILE", allow_file),
            mock.patch.object(webui, "PERMISSIONS_FILE", perm_file),
            mock.patch.object(webui, "BACKUP_CONFIG_FILE", bk_cfg_file),
            mock.patch.object(webui, "BACKUP_DIR", bk_dir),
            mock.patch.object(webui, "get_service_status", return_value="ACTIVE (RUNNING)"),
            mock.patch.object(webui, "get_device_stats", return_value={
                "uptime": "1d", "cpu_temp": "44.0 °C", "load_avg": "0.10, 0.10, 0.10",
                "root_used_gb": 5.0, "root_total_gb": 32.0, "root_pct": 15.6, "root_free_gb": 27.0,
                "worlds_path": os.path.join(base_dir, "worlds"), "is_external_worlds": False,
                "worlds_used_gb": 1.0, "worlds_total_gb": 32.0, "worlds_pct": 3.1,
                "ram_used_mb": 512, "ram_total_mb": 4096, "ram_pct": 12.5, "ram_free_mb": 3584,
                "swap_used_mb": 0, "swap_total_mb": 2048, "swap_pct": 0.0, "swap_free_mb": 2048,
            }),
        ]
        if usb_drives_patch is not None:
            patchers.append(usb_drives_patch)
        for p in patchers:
            p.start()
        srv = webui.ThreadingWebUIServer(("127.0.0.1", 0), webui.WebUIHandler)
        t = threading.Thread(target=srv.serve_forever, daemon=True)
        t.start()
        token = base64.b64encode(b"admin:testpass99").decode("ascii")
        headers = {"Authorization": f"Basic {token}"}
        return srv, patchers, headers, base_dir, bk_dir

    def _http_call(self, port, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            return resp.status, dict(resp.getheaders()), resp.read()
        finally:
            conn.close()

    def test_uncompressed_folder_backups_list_prune_download_restore_and_delete(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            usb_mp = os.path.join(tmpdir, "usb_drive")
            usb_bk_dir = os.path.join(usb_mp, "minecraft_backups")
            os.makedirs(usb_bk_dir, exist_ok=True)
            fake_drive = {
                "device": "/dev/sda1", "kname": "sda1", "uuid": "CAFE-1111", "label": "MYUSB",
                "fstype": "exfat", "size_gb": 64.0, "mountpoint": usb_mp,
                "windows_compatible": True, "id": "usb:UUID=CAFE-1111", "backup_dir": usb_bk_dir,
            }
            srv, patchers, headers, base_dir, _ = self._start_test_server(
                tmpdir, usb_drives_patch=mock.patch.object(webui, "detect_external_usb_drives", return_value=[fake_drive])
            )
            try:
                webui.save_backup_config({
                    **webui.DEFAULT_BACKUP_CONFIG,
                    "backup_location": "usb:UUID=CAFE-1111",
                    "usb_device": "/dev/sda1",
                    "usb_uuid": "CAFE-1111",
                    "usb_label": "MYUSB",
                    "usb_mountpoint": usb_mp,
                })
                bk_new = os.path.join(usb_bk_dir, "bedrock_backup_20261119_200000")
                bk_old = os.path.join(usb_bk_dir, "bedrock_backup_20261110_100000")
                os.makedirs(os.path.join(bk_new, "worlds", "Bedrock level"), exist_ok=True)
                with open(os.path.join(bk_new, "worlds", "Bedrock level", "level.dat"), "wb") as f:
                    f.write(b"LEVELDATA123")
                with open(os.path.join(bk_new, "server.properties"), "w", encoding="utf-8") as f:
                    f.write("server-name=RestoredPi\nlevel-name=Bedrock level\n")
                os.makedirs(os.path.join(bk_old, "worlds", "Bedrock level"), exist_ok=True)
                with open(os.path.join(bk_old, "worlds", "Bedrock level", "level.dat"), "wb") as f:
                    f.write(b"OLD")
                old_ts = time.time() - (15 * 86400)
                os.utime(bk_old, (old_ts, old_ts))

                # Act: list, prune (with retention rules active), download zip, restore, delete
                listed_before = webui.list_backups(backup_dir=usb_bk_dir)
                webui.prune_backups(
                    retention_days=7,
                    max_backups=10,
                    backup_dir=usb_bk_dir,
                    usb_keep_until_full=False,
                )
                listed_after_prune = webui.list_backups(backup_dir=usb_bk_dir)

                dl_status, dl_hdrs, dl_bytes = self._http_call(
                    srv.server_address[1], "GET", "/backup/download?file=bedrock_backup_20261119_200000", headers=headers
                )
                post_hdrs = {**headers, "Content-Type": "application/x-www-form-urlencoded"}
                with mock.patch("webui.execute_action") as mock_act, \
                     mock.patch("webui.subprocess.run") as mock_sub:
                    rest_status, _, _ = self._http_call(
                        srv.server_address[1], "POST", "/backup/restore",
                        body="filename=bedrock_backup_20261119_200000", headers=post_hdrs
                    )
                del_status, _, _ = self._http_call(
                    srv.server_address[1], "POST", "/backup/delete",
                    body="filename=bedrock_backup_20261119_200000", headers=post_hdrs
                )
                restored_level = os.path.join(base_dir, "worlds", "Bedrock level", "level.dat")
                restored_props = os.path.join(base_dir, "server.properties")

                # Assert
                self.assertEqual(len(listed_before), 2)
                self.assertTrue(listed_before[0]["is_dir"])
                self.assertEqual([b["filename"] for b in listed_after_prune], ["bedrock_backup_20261119_200000"])
                self.assertFalse(os.path.exists(bk_old))

                self.assertEqual(dl_status, 200)
                self.assertIn("bedrock_backup_20261119_200000.zip", dl_hdrs.get("Content-Disposition", ""))
                with zipfile.ZipFile(io.BytesIO(dl_bytes), "r") as zf:
                    names = [n.replace("\\", "/") for n in zf.namelist()]
                    self.assertIn("worlds/Bedrock level/level.dat", names)
                    self.assertEqual(zf.read("worlds/Bedrock level/level.dat"), b"LEVELDATA123")

                self.assertEqual(rest_status, 303)
                mock_act.assert_any_call("backup")
                mock_act.assert_any_call("stop")
                mock_act.assert_any_call("start")
                self.assertTrue(mock_sub.called)
                self.assertTrue(os.path.isfile(restored_level))
                with open(restored_level, "rb") as f:
                    self.assertEqual(f.read(), b"LEVELDATA123")
                with open(restored_props, "r", encoding="utf-8") as f:
                    self.assertIn("server-name=RestoredPi", f.read())

                self.assertEqual(del_status, 303)
                self.assertFalse(os.path.exists(bk_new))
            finally:
                srv.shutdown()
                srv.server_close()
                for p in reversed(patchers):
                    p.stop()

    def test_webui_backup_location_dropdown_and_format_usb_post(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            usb_mp = os.path.join(tmpdir, "usb_exfat")
            os.makedirs(usb_mp, exist_ok=True)
            drive_exfat = {
                "device": "/dev/sda1", "kname": "sda1", "uuid": "WIN-001", "label": "MC_DRIVE",
                "fstype": "exfat", "size_gb": 128.0, "mountpoint": usb_mp,
                "windows_compatible": True, "id": "usb:UUID=WIN-001",
                "backup_dir": os.path.join(usb_mp, "minecraft_backups"),
            }
            drive_ext4 = {
                "device": "/dev/sdb1", "kname": "sdb1", "uuid": "EXT-002", "label": "OLD_EXT4",
                "fstype": "ext4", "size_gb": 32.0, "mountpoint": "",
                "windows_compatible": False, "id": "usb:UUID=EXT-002", "backup_dir": "",
            }
            srv, patchers, headers, _, _ = self._start_test_server(
                tmpdir,
                usb_drives_patch=mock.patch.object(
                    webui, "detect_external_usb_drives", return_value=[drive_exfat, drive_ext4]
                ),
            )
            try:
                post_hdrs = {**headers, "Content-Type": "application/x-www-form-urlencoded"}

                # Act
                s_get, _, body_bytes = self._http_call(srv.server_address[1], "GET", "/", headers=headers)
                s_set, h_set, _ = self._http_call(
                    srv.server_address[1],
                    "POST",
                    "/backup/settings",
                    body="auto_backup_enabled=true&interval_hours=6&retention_days=7&max_backups=20&usb_keep_until_full=true&backup_location=usb%3AUUID%3DWIN-001",
                    headers=post_hdrs,
                )
                saved_cfg = webui.read_backup_config()
                s_uncheck, h_uncheck, _ = self._http_call(
                    srv.server_address[1],
                    "POST",
                    "/backup/settings",
                    body="auto_backup_enabled=true&interval_hours=6&retention_days=7&max_backups=20&backup_location=usb%3AUUID%3DWIN-001",
                    headers=post_hdrs,
                )
                saved_cfg_unchecked = webui.read_backup_config()

                s_bad_fmt, h_bad_fmt, _ = self._http_call(
                    srv.server_address[1],
                    "POST",
                    "/backup/format_usb",
                    body="usb_device=%2Fdev%2Fmmcblk0p2",
                    headers=post_hdrs,
                )
                with mock.patch("webui.format_usb_drive_exfat", return_value=(True, usb_mp, "")) as mock_fmt:
                    s_fmt, h_fmt, _ = self._http_call(
                        srv.server_address[1],
                        "POST",
                        "/backup/format_usb",
                        body="usb_device=%2Fdev%2Fsdb1",
                        headers=post_hdrs,
                    )

                # Assert
                self.assertEqual(s_get, 200)
                page = body_bytes.decode("utf-8")
                self.assertIn('name="backup_location"', page)
                self.assertIn('name="usb_keep_until_full"', page)
                self.assertIn('id="usb_keep_until_full" name="usb_keep_until_full" value="true" checked', page)
                self.assertIn("Default Internal Storage", page)
                self.assertIn("External USB: MC_DRIVE (/dev/sda1", page)
                self.assertIn("Windows PC Ready - Uncompressed World Files", page)
                self.assertIn("Requires exFAT Format for Windows", page)
                self.assertIn('action="/backup/format_usb"', page)

                self.assertEqual(s_set, 303)
                self.assertEqual(h_set.get("Location"), "/?backup_msg=usb_mounted")
                self.assertEqual(saved_cfg["backup_location"], "usb:UUID=WIN-001")
                self.assertEqual(saved_cfg["usb_mountpoint"], usb_mp)
                self.assertTrue(saved_cfg["usb_keep_until_full"])

                self.assertEqual(s_uncheck, 303)
                self.assertEqual(h_uncheck.get("Location"), "/?backup_msg=usb_mounted")
                self.assertFalse(saved_cfg_unchecked["usb_keep_until_full"])

                self.assertEqual(s_bad_fmt, 303)
                self.assertEqual(h_bad_fmt.get("Location"), "/?backup_err=usb_invalid_device")

                mock_fmt.assert_called_once_with("/dev/sdb1")
                self.assertEqual(s_fmt, 303)
                self.assertEqual(h_fmt.get("Location"), "/?backup_msg=usb_formatted")
            finally:
                srv.shutdown()
                srv.server_close()
                for p in reversed(patchers):
                    p.stop()

    def test_usb_keep_until_full_ignores_retention_and_prunes_oldest_when_full(self):
        # Arrange
        with tempfile.TemporaryDirectory() as tmpdir:
            bk_cfg_file = os.path.join(tmpdir, "backup_config.json")
            usb_bk_dir = os.path.join(tmpdir, "usb_backups")
            os.makedirs(usb_bk_dir, exist_ok=True)
            names = [
                "bedrock_backup_20261001_000000",
                "bedrock_backup_20261015_000000",
                "bedrock_backup_20261119_120000",
            ]
            now = time.time()
            ages_days = [45, 30, 0]
            for name, age in zip(names, ages_days):
                folder = os.path.join(usb_bk_dir, name)
                os.makedirs(os.path.join(folder, "worlds", "Bedrock level"), exist_ok=True)
                with open(os.path.join(folder, "worlds", "Bedrock level", "level.dat"), "wb") as f:
                    f.write(b"DATA")
                ts = now - (age * 86400)
                os.utime(folder, (ts, ts))

            fake_usage_enough = mock.Mock(free=10_000)
            usage_seq = [
                mock.Mock(free=10),
                mock.Mock(free=20),
                mock.Mock(free=10_000),
            ]

            with mock.patch.object(webui, "BACKUP_CONFIG_FILE", bk_cfg_file):
                default_cfg = webui.read_backup_config()

                # Act 1: plenty of free space -> ignores retention_days=7 and max_backups=1
                with mock.patch("webui.shutil.disk_usage", return_value=fake_usage_enough):
                    webui.prune_backups(
                        retention_days=7,
                        max_backups=1,
                        backup_dir=usb_bk_dir,
                        is_usb_active=True,
                        min_free_bytes=100,
                    )
                after_plenty = sorted(os.listdir(usb_bk_dir))

                # Act 2: storage low -> deletes oldest backups first until free >= min_free_bytes
                with mock.patch("webui.shutil.disk_usage", side_effect=usage_seq):
                    webui.prune_backups(
                        retention_days=7,
                        max_backups=1,
                        backup_dir=usb_bk_dir,
                        is_usb_active=True,
                        min_free_bytes=100,
                    )
                after_full = sorted(os.listdir(usb_bk_dir))

            # Assert
            self.assertTrue(default_cfg["usb_keep_until_full"])
            self.assertEqual(after_plenty, names)
            self.assertEqual(after_full, ["bedrock_backup_20261119_120000"])


if __name__ == "__main__":
    unittest.main()
