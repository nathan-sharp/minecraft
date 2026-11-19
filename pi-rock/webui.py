#!/usr/bin/env python3
"""
Minecraft Bedrock Dedicated Server - Lightweight Web Administration Interface
Architecture: Pure Python 3 Standard Library (Zero third-party dependencies)
Security: OWASP ASVS compliant, positive input validation, Zip Slip defense, path traversal prevention
"""

import email
import hmac
import html as html_lib
import http.client
import http.server
import io
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import struct
import subprocess
import tarfile
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from email.policy import default
from http import HTTPStatus

PORT = 8080
BASE_DIR = "/opt/minecraft/bedrock"
BACKUP_DIR = "/opt/minecraft/backups"
PROPERTIES_FILE = os.path.join(BASE_DIR, "server.properties")
ALLOWLIST_FILE = os.path.join(BASE_DIR, "allowlist.json")
PERMISSIONS_FILE = os.path.join(BASE_DIR, "permissions.json")
BACKUP_CONFIG_FILE = "/opt/minecraft/backup_config.json"
AUTH_FILE = "/opt/minecraft/webui/auth.json"
ADDRESS_CONFIG_FILE = "/opt/minecraft/webui/address_config.json"
SERVICE_NAME = "minecraft-bedrock.service"
SERVER_USER = "mcserver"
SERVER_GROUP = "mcserver"

RAKNET_OFFLINE_MAGIC = bytes.fromhex("00ffff00fefefefefdfdfdfd12345678")
VERIFY_PATH_PREFIX = "/.well-known/pi-rock-verify/"
VERIFY_CHALLENGE_TTL_SEC = 15.0
VERIFY_MAX_PENDING = 10
MAX_HTTP_PROBE_BYTES = 512
MAX_API_RESPONSE_BYTES = 16384
PROBE_USER_AGENT = "pi-rock-webui/1.0"

CLOUDFLARE_PROXY_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/13",
        "104.24.0.0/14",
        "172.64.0.0/13",
        "131.0.72.0/22",
        "2400:cb00::/32",
        "2606:4700::/32",
        "2803:f800::/32",
        "2405:b500::/32",
        "2405:8100::/32",
        "2a06:98c0::/29",
        "2c0f:f248::/32",
    )
)

DEFAULT_ADDRESS_CONFIG = {
    "raw_address": "",
    "host": "",
    "port_override": None,
    "address_type": "",
    "last_checked_utc": "",
    "last_report": None,
}

ADDRESS_FLASH_MESSAGES = {
    "saved_checked": ("success", "Address saved and external connectivity diagnostics completed."),
    "rechecked": ("success", "External connectivity diagnostics re-run completed."),
    "cleared": ("info", "Saved address and cached diagnostic report cleared."),
    "empty_address": ("error", "Enter a valid domain name, IPv4 address, or IPv6 address."),
    "invalid_format": ("error", "Invalid address syntax. Enter only a domain or IP (optional :port), without http:// or paths."),
    "invalid_port": ("error", "Invalid port number. Port must be an integer from 1 to 65535."),
    "private_ip": ("error", "Private, loopback, link-local, CGNAT, or reserved IP addresses are not permitted."),
    "no_address": ("error", "Configure and save a server address before running diagnostics."),
}

_CHALLENGE_LOCK = threading.Lock()
_PENDING_CHALLENGES = {}
_ADDRESS_CONFIG_LOCK = threading.Lock()

VALID_PROPERTIES = {
    "server-name": str,
    "level-name": str,
    "gamemode": ["survival", "creative", "adventure"],
    "difficulty": ["peaceful", "easy", "normal", "hard"],
    "allow-cheats": ["true", "false"],
    "max-players": int,
    "online-mode": ["true", "false"],
    "white-list": ["true", "false"],
    "allow-list": ["true", "false"],
    "server-port": int,
    "server-portv6": int,
    "view-distance": int,
    "tick-distance": int,
    "player-idle-timeout": int,
    "max-threads": int,
    "default-player-permission-level": ["visitor", "member", "operator"],
    "texturepack-required": ["true", "false"],
}

DEFAULT_BACKUP_CONFIG = {
    "auto_backup_enabled": True,
    "interval_hours": 6,
    "retention_days": 7,
    "max_backups": 20,
    "last_backup_timestamp": 0,
}

VALID_PERMISSIONS = ["visitor", "member", "operator", "default"]


def get_auth_credentials():
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {"admin_pass": "admin123"}


def get_service_status():
    try:
        res = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "ACTIVE (RUNNING)" if res.returncode == 0 else "INACTIVE (STOPPED)"
    except Exception:
        return "UNKNOWN"


def read_properties():
    props = {}
    if os.path.exists(PROPERTIES_FILE):
        with open(PROPERTIES_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    props[k.strip()] = v.strip()
    return props


def save_properties(new_props):
    existing_lines = []
    if os.path.exists(PROPERTIES_FILE):
        with open(PROPERTIES_FILE, "r", encoding="utf-8") as f:
            existing_lines = f.readlines()

    keys_written = set()
    output_lines = []
    for line in existing_lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            k = stripped.split("=", 1)[0].strip()
            if k in new_props:
                output_lines.append(f"{k}={new_props[k]}\n")
                keys_written.add(k)
            else:
                output_lines.append(line)
        else:
            output_lines.append(line)

    for k, v in new_props.items():
        if k not in keys_written:
            output_lines.append(f"{k}={v}\n")

    tmp_file = PROPERTIES_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        f.writelines(output_lines)
    os.replace(tmp_file, PROPERTIES_FILE)


def read_allowlist():
    if os.path.exists(ALLOWLIST_FILE):
        try:
            with open(ALLOWLIST_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_allowlist(entries):
    tmp_file = ALLOWLIST_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    os.replace(tmp_file, ALLOWLIST_FILE)


def read_permissions():
    if os.path.exists(PERMISSIONS_FILE):
        try:
            with open(PERMISSIONS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []
    return []


def save_permissions(entries):
    tmp_file = PERMISSIONS_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(entries, f, indent=2)
    os.replace(tmp_file, PERMISSIONS_FILE)


def get_unified_players():
    allowlist = read_allowlist()
    permissions = read_permissions()
    props = read_properties()
    default_role = props.get("default-player-permission-level", "member")

    perm_map = {}
    for p in permissions:
        if isinstance(p, dict) and "xuid" in p and "permission" in p:
            perm_map[str(p["xuid"]).strip()] = str(p["permission"]).strip().lower()

    unified = []
    seen_xuids = set()

    for entry in allowlist:
        if isinstance(entry, dict):
            name = entry.get("name", "Unknown")
            xuid = str(entry.get("xuid", "")).strip() if entry.get("xuid") else ""
            ignores = entry.get("ignoresPlayerLimit", False)
            assigned_role = perm_map.get(xuid, "default") if xuid else "default"
            if xuid:
                seen_xuids.add(xuid)
            unified.append({
                "name": name,
                "xuid": xuid,
                "permission": assigned_role,
                "is_allowlisted": True,
                "ignoresPlayerLimit": ignores,
            })

    for p in permissions:
        if isinstance(p, dict) and "xuid" in p:
            pxuid = str(p.get("xuid", "")).strip()
            if pxuid and pxuid not in seen_xuids:
                unified.append({
                    "name": "(Direct XUID Override)",
                    "xuid": pxuid,
                    "permission": str(p.get("permission", default_role)).lower(),
                    "is_allowlisted": False,
                    "ignoresPlayerLimit": False,
                })

    return unified, default_role


def set_player_permission_level(xuid, role):
    xuid_str = str(xuid).strip()
    if not re.match(r"^[0-9]+$", xuid_str):
        return
    role = role.strip().lower()
    permissions = read_permissions()
    new_perms = [p for p in permissions if str(p.get("xuid", "")).strip() != xuid_str]
    if role in ["visitor", "member", "operator"]:
        new_perms.append({"permission": role, "xuid": xuid_str})
    save_permissions(new_perms)


def read_backup_config():
    if os.path.exists(BACKUP_CONFIG_FILE):
        try:
            with open(BACKUP_CONFIG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
                res = DEFAULT_BACKUP_CONFIG.copy()
                res.update(data)
                return res
        except Exception:
            pass
    return DEFAULT_BACKUP_CONFIG.copy()


def save_backup_config(config):
    os.makedirs(os.path.dirname(BACKUP_CONFIG_FILE), exist_ok=True)
    tmp_file = BACKUP_CONFIG_FILE + ".tmp"
    with open(tmp_file, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    os.replace(tmp_file, BACKUP_CONFIG_FILE)


def prune_backups(retention_days=7, max_backups=20):
    if not os.path.exists(BACKUP_DIR):
        return
    now = time.time()
    cutoff_sec = retention_days * 86400
    valid_pattern = re.compile(r"^bedrock_backup_[a-zA-Z0-9_.-]+\.(tar\.gz|zip)$")

    archives = []
    for fname in os.listdir(BACKUP_DIR):
        if valid_pattern.match(fname):
            fpath = os.path.join(BACKUP_DIR, fname)
            if os.path.isfile(fpath):
                try:
                    mtime = os.path.getmtime(fpath)
                    if (now - mtime) > cutoff_sec:
                        os.remove(fpath)
                    else:
                        archives.append((fpath, mtime))
                except Exception:
                    pass

    archives.sort(key=lambda x: x[1], reverse=True)
    if len(archives) > max_backups:
        for fpath, _ in archives[max_backups:]:
            try:
                os.remove(fpath)
            except Exception:
                pass


def list_backups():
    backups = []
    if os.path.exists(BACKUP_DIR):
        for fname in sorted(os.listdir(BACKUP_DIR), reverse=True):
            if fname.endswith(".tar.gz") or fname.endswith(".zip"):
                fpath = os.path.join(BACKUP_DIR, fname)
                stat = os.stat(fpath)
                size_mb = round(stat.st_size / (1024 * 1024), 2)
                mtime_str = time.strftime(
                    "%Y-%m-%d %H:%M:%S UTC", time.gmtime(stat.st_mtime)
                )
                backups.append(
                    {
                        "filename": fname,
                        "size_mb": size_mb,
                        "modified": mtime_str,
                    }
                )
    return backups


def get_active_worlds_dir():
    """Resolve the real filesystem path for the worlds directory."""
    worlds_path = os.path.join(BASE_DIR, "worlds")
    if os.path.islink(worlds_path):
        return os.path.realpath(worlds_path)
    return worlds_path


def get_device_stats():
    """Collect hardware and operating system resource telemetry."""
    stats = {}

    # 1. Primary Root Storage Usage
    try:
        root_usage = shutil.disk_usage("/")
        stats["root_total_gb"] = round(root_usage.total / (1024**3), 1)
        stats["root_used_gb"] = round(root_usage.used / (1024**3), 1)
        stats["root_free_gb"] = round(root_usage.free / (1024**3), 1)
        stats["root_pct"] = round((root_usage.used / root_usage.total) * 100, 1)
    except Exception:
        stats["root_total_gb"] = 0
        stats["root_used_gb"] = 0
        stats["root_free_gb"] = 0
        stats["root_pct"] = 0

    # 2. World Storage Target Usage
    try:
        worlds_path = get_active_worlds_dir()
        stats["worlds_path"] = worlds_path
        worlds_usage = shutil.disk_usage(worlds_path)
        stats["worlds_total_gb"] = round(worlds_usage.total / (1024**3), 1)
        stats["worlds_used_gb"] = round(worlds_usage.used / (1024**3), 1)
        stats["worlds_free_gb"] = round(worlds_usage.free / (1024**3), 1)
        stats["worlds_pct"] = round((worlds_usage.used / worlds_usage.total) * 100, 1)
        stats["is_external_worlds"] = os.path.islink(os.path.join(BASE_DIR, "worlds"))
    except Exception:
        stats["worlds_path"] = "/opt/minecraft/bedrock/worlds"
        stats["worlds_total_gb"] = 0
        stats["worlds_used_gb"] = 0
        stats["worlds_free_gb"] = 0
        stats["worlds_pct"] = 0
        stats["is_external_worlds"] = False

    # 3. RAM & Swap Memory Telemetry
    try:
        meminfo = {}
        with open("/proc/meminfo", "r") as f:
            for line in f:
                parts = line.split(":")
                if len(parts) == 2:
                    meminfo[parts[0].strip()] = int(parts[1].split()[0])

        total_ram_mb = round(meminfo.get("MemTotal", 0) / 1024, 0)
        avail_ram_mb = round(meminfo.get("MemAvailable", 0) / 1024, 0)
        used_ram_mb = total_ram_mb - avail_ram_mb
        stats["ram_total_mb"] = int(total_ram_mb)
        stats["ram_used_mb"] = int(used_ram_mb)
        stats["ram_free_mb"] = int(avail_ram_mb)
        stats["ram_pct"] = round((used_ram_mb / total_ram_mb) * 100, 1) if total_ram_mb > 0 else 0

        total_swap_mb = round(meminfo.get("SwapTotal", 0) / 1024, 0)
        free_swap_mb = round(meminfo.get("SwapFree", 0) / 1024, 0)
        used_swap_mb = total_swap_mb - free_swap_mb
        stats["swap_total_mb"] = int(total_swap_mb)
        stats["swap_used_mb"] = int(used_swap_mb)
        stats["swap_free_mb"] = int(free_swap_mb)
        stats["swap_pct"] = round((used_swap_mb / total_swap_mb) * 100, 1) if total_swap_mb > 0 else 0
    except Exception:
        stats["ram_total_mb"] = 0
        stats["ram_used_mb"] = 0
        stats["ram_free_mb"] = 0
        stats["ram_pct"] = 0
        stats["swap_total_mb"] = 0
        stats["swap_used_mb"] = 0
        stats["swap_free_mb"] = 0
        stats["swap_pct"] = 0

    # 4. SoC Temperature
    try:
        temp_file = "/sys/class/thermal/thermal_zone0/temp"
        if os.path.exists(temp_file):
            with open(temp_file, "r") as f:
                stats["cpu_temp"] = f"{round(int(f.read().strip()) / 1000.0, 1)} °C"
        else:
            stats["cpu_temp"] = "N/A"
    except Exception:
        stats["cpu_temp"] = "N/A"

    # 5. System Load Average & Uptime
    try:
        l1, l5, l15 = os.getloadavg()
        stats["load_avg"] = f"{l1:.2f}, {l5:.2f}, {l15:.2f}"
    except Exception:
        stats["load_avg"] = "N/A"

    try:
        with open("/proc/uptime", "r") as f:
            secs = float(f.read().split()[0])
            d = int(secs // 86400)
            h = int((secs % 86400) // 3600)
            m = int((secs % 3600) // 60)
            stats["uptime"] = f"{d}d {h}h {m}m"
    except Exception:
        stats["uptime"] = "N/A"

    return stats


def execute_action(action):
    allowed = {
        "start": ["sudo", "systemctl", "start", SERVICE_NAME],
        "stop": ["sudo", "systemctl", "stop", SERVICE_NAME],
        "restart": ["sudo", "systemctl", "restart", SERVICE_NAME],
        "backup": ["sudo", "/usr/local/bin/mc-backup"],
    }
    if action in allowed:
        subprocess.run(allowed[action], timeout=45)


def safe_extract_zip(zip_bytes, dest_dir):
    """Extract zip bytes safely preventing directory traversal (Zip Slip)."""
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for member in zf.infolist():
            target_path = os.path.abspath(os.path.join(dest_dir, member.filename))
            if not target_path.startswith(os.path.abspath(dest_dir)):
                raise ValueError("Security violation: Archive member path traversal detected")
        zf.extractall(dest_dir)


def safe_extract_targz(tar_bytes, dest_dir):
    """Extract tar.gz bytes safely preventing directory traversal."""
    with tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            target_path = os.path.abspath(os.path.join(dest_dir, member.name))
            if not target_path.startswith(os.path.abspath(dest_dir)):
                raise ValueError("Security violation: Archive member path traversal detected")
        tf.extractall(dest_dir)


def import_world_archive(filename, file_bytes):
    """Process uploaded .mcworld, .zip, or .tar.gz archive and set as active world."""
    execute_action("backup")
    execute_action("stop")

    worlds_root = get_active_worlds_dir()
    os.makedirs(worlds_root, exist_ok=True)

    with tempfile.TemporaryDirectory() as temp_extract:
        if filename.endswith(".zip") or filename.endswith(".mcworld"):
            safe_extract_zip(file_bytes, temp_extract)
        elif filename.endswith(".tar.gz"):
            safe_extract_targz(file_bytes, temp_extract)
        else:
            raise ValueError("Unsupported file format. Use .mcworld, .zip, or .tar.gz")

        world_name = "ImportedWorld"
        source_world_dir = None

        if os.path.exists(os.path.join(temp_extract, "level.dat")):
            source_world_dir = temp_extract
            lname_file = os.path.join(temp_extract, "levelname.txt")
            if os.path.exists(lname_file):
                with open(lname_file, "r", encoding="utf-8", errors="ignore") as f:
                    world_name = re.sub(r'[^a-zA-Z0-9_-]', '_', f.read().strip()) or "ImportedWorld"
            else:
                base_clean = re.sub(r'[^a-zA-Z0-9_-]', '_', os.path.splitext(filename)[0])
                world_name = base_clean or "ImportedWorld"
        else:
            for entry in os.listdir(temp_extract):
                sub = os.path.join(temp_extract, entry)
                if os.path.isdir(sub) and os.path.exists(os.path.join(sub, "level.dat")):
                    source_world_dir = sub
                    world_name = re.sub(r'[^a-zA-Z0-9_-]', '_', entry) or "ImportedWorld"
                    break

        if not source_world_dir:
            raise ValueError("Invalid Minecraft Bedrock world: missing level.dat in archive")

        target_dir = os.path.join(worlds_root, world_name)
        if os.path.exists(target_dir):
            shutil.rmtree(target_dir)

        shutil.copytree(source_world_dir, target_dir)

        props = read_properties()
        props["level-name"] = world_name
        save_properties(props)

        subprocess.run(["sudo", "chown", "-R", f"{SERVER_USER}:{SERVER_GROUP}", BASE_DIR], timeout=30)
        subprocess.run(["sudo", "chown", "-R", f"{SERVER_USER}:{SERVER_GROUP}", worlds_root], timeout=30)
        execute_action("start")


def get_progress_bar(pct):
    color = "#28a745" if pct < 70 else ("#ffc107" if pct < 85 else "#dc3545")
    return f"""
    <div style="background:#e9ecef; border-radius:4px; height:12px; width:100%; overflow:hidden; margin-top:4px;">
      <div style="background:{color}; width:{pct}%; height:100%;"></div>
    </div>
    """


def read_address_config():
    """Load persisted address configuration and cached diagnostic report."""
    with _ADDRESS_CONFIG_LOCK:
        cfg = DEFAULT_ADDRESS_CONFIG.copy()
        if os.path.exists(ADDRESS_CONFIG_FILE):
            try:
                with open(ADDRESS_CONFIG_FILE, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                if isinstance(loaded, dict):
                    cfg.update(loaded)
            except Exception:
                pass
        return cfg


def save_address_config(config):
    """Persist address configuration atomically."""
    with _ADDRESS_CONFIG_LOCK:
        parent = os.path.dirname(ADDRESS_CONFIG_FILE)
        if parent:
            os.makedirs(parent, exist_ok=True)
        tmp_file = ADDRESS_CONFIG_FILE + ".tmp"
        with open(tmp_file, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2)
        os.replace(tmp_file, ADDRESS_CONFIG_FILE)


def is_public_global_ip(ip_str):
    """Return True only when ip_str is a publicly routable global IP address."""
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(
        ip_obj.is_global
        and not ip_obj.is_private
        and not ip_obj.is_loopback
        and not ip_obj.is_link_local
        and not ip_obj.is_multicast
        and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )


def is_cloudflare_proxy_ip(ip_str):
    """Return True when ip_str falls inside Cloudflare Proxy (Orange Cloud) CIDRs."""
    try:
        ip_obj = ipaddress.ip_address(str(ip_str).strip())
    except ValueError:
        return False
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    for net in CLOUDFLARE_PROXY_NETWORKS:
        if ip_obj.version == net.version and ip_obj in net:
            return True
    return False


def is_valid_fqdn(hostname):
    """Validate an RFC 1123 multi-label FQDN (rejects single-label local names)."""
    if not hostname or len(hostname) > 253 or "." not in hostname:
        return False
    labels = hostname.split(".")
    if len(labels) < 2 or labels[-1].isdigit():
        return False
    label_re = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
    for label in labels:
        if not label or len(label) > 63 or not label_re.match(label):
            return False
    return True


def _parse_port(port_str):
    """Parse TCP/UDP port integer within 1..65535 or return None."""
    if not port_str or not port_str.isdigit():
        return None
    val = int(port_str)
    return val if 1 <= val <= 65535 else None


def _parse_bracketed_ipv6(raw):
    """Parse [ipv6] or [ipv6]:port strings and validate public IPv6 routing."""
    match_v6 = re.match(r"^\[([^\]]+)\](?::(.+))?$", raw)
    if not match_v6:
        return None, "invalid_format"
    try:
        ip_obj = ipaddress.IPv6Address(match_v6.group(1))
    except ValueError:
        return None, "invalid_format"
    port_val = None
    if match_v6.group(2) is not None:
        port_val = _parse_port(match_v6.group(2))
        if port_val is None:
            return None, "invalid_port"
    host = str(ip_obj)
    if not is_public_global_ip(host):
        return None, "private_ip"
    norm = f"[{host}]:{port_val}" if port_val else host
    return {"raw_address": norm, "host": host, "port_override": port_val, "address_type": "ipv6"}, None


def parse_server_address(raw_input):
    """Validate and normalize domain, IPv4, or IPv6 input with optional :port."""
    raw_unstripped = "" if raw_input is None else str(raw_input)
    if any(ord(ch) < 32 or ord(ch) > 126 for ch in raw_unstripped):
        return None, "invalid_format"
    raw = raw_unstripped.strip(" ")
    if not raw:
        return None, "empty_address"
    if len(raw) > 265 or "://" in raw or re.search(r"[\s/\\?#@^<>\"'`]", raw):
        return None, "invalid_format"
    if raw.startswith("[") or "]" in raw:
        return _parse_bracketed_ipv6(raw)

    try:
        ip_obj = ipaddress.ip_address(raw)
        host = str(ip_obj)
        if not is_public_global_ip(host):
            return None, "private_ip"
        addr_type = "ipv6" if ip_obj.version == 6 else "ipv4"
        return {"raw_address": host, "host": host, "port_override": None, "address_type": addr_type}, None
    except ValueError:
        pass

    if ":" in raw:
        if raw.count(":") != 1:
            return None, "invalid_format"
        host_part, port_part = raw.split(":", 1)
        port_val = _parse_port(port_part)
        if port_val is None:
            return None, "invalid_port"
        try:
            ip_obj = ipaddress.IPv4Address(host_part)
            host = str(ip_obj)
            if not is_public_global_ip(host):
                return None, "private_ip"
            return {"raw_address": f"{host}:{port_val}", "host": host, "port_override": port_val, "address_type": "ipv4"}, None
        except ValueError:
            lower_host = host_part.lower()
            if is_valid_fqdn(lower_host):
                return {"raw_address": f"{lower_host}:{port_val}", "host": lower_host, "port_override": port_val, "address_type": "domain"}, None
            return None, "invalid_format"

    lower_host = raw.lower()
    if is_valid_fqdn(lower_host):
        return {"raw_address": lower_host, "host": lower_host, "port_override": None, "address_type": "domain"}, None
    return None, "invalid_format"


def get_local_lan_ipv4():
    """Detect primary outbound local IPv4 address without sending network packets."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.settimeout(1.0)
        sock.connect(("1.1.1.1", 80))
        return sock.getsockname()[0]
    except OSError:
        return "Unavailable"
    finally:
        sock.close()


def _read_proc_udp_ports(filepath):
    """Read listening UDP port numbers from a Linux /proc/net/udp* table."""
    ports = set()
    if not os.path.exists(filepath):
        return False, ports
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            for idx, line in enumerate(f):
                if idx >= 4096:
                    break
                if idx == 0:
                    continue
                parts = line.split()
                if len(parts) >= 2 and ":" in parts[1]:
                    port_hex = parts[1].rsplit(":", 1)[1]
                    if re.match(r"^[0-9a-fA-F]{1,4}$", port_hex):
                        ports.add(int(port_hex, 16))
        return True, ports
    except OSError:
        return False, ports


def get_bound_udp_ports(proc_udp="/proc/net/udp", proc_udp6="/proc/net/udp6"):
    """Return local UDP socket ports from procfs when running on Linux."""
    ok4, ports4 = _read_proc_udp_ports(proc_udp)
    ok6, ports6 = _read_proc_udp_ports(proc_udp6)
    return {
        "supported": ok4 or ok6,
        "ipv4_ports": ports4,
        "ipv6_ports": ports6,
    }


def build_raknet_ping_packet(client_guid=None):
    """Construct a 33-byte RakNet Unconnected Ping (0x01) UDP datagram."""
    guid = client_guid if isinstance(client_guid, (bytes, bytearray)) and len(client_guid) == 8 else secrets.token_bytes(8)
    ts_ms = int(time.time() * 1000)
    return b"\x01" + struct.pack(">Q", ts_ms) + RAKNET_OFFLINE_MAGIC + bytes(guid)


def parse_raknet_pong_packet(data):
    """Decode a RakNet Unconnected Pong (0x1c) payload from Bedrock Server."""
    if not isinstance(data, (bytes, bytearray)) or len(data) < 35:
        return None
    if data[0] != 0x1C or data[17:33] != RAKNET_OFFLINE_MAGIC:
        return None
    str_len = struct.unpack(">H", data[33:35])[0]
    if len(data) < 35 + str_len:
        return None
    payload = bytes(data[35:35 + str_len]).decode("utf-8", errors="replace")
    fields = payload.split(";")
    if len(fields) < 6 or fields[0] not in ("MCPE", "MCEE"):
        return None
    return {
        "edition": fields[0],
        "motd": fields[1],
        "protocol": fields[2],
        "version": fields[3],
        "players_online": fields[4],
        "players_max": fields[5],
        "server_guid": fields[6] if len(fields) > 6 else "",
    }


def probe_raknet_udp(target_ip, port, ipv6=False, timeout=2.0):
    """Send a RakNet UDP ping to target_ip:port and decode the server response."""
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    sock = socket.socket(family, socket.SOCK_DGRAM)
    try:
        sock.settimeout(timeout)
        packet = build_raknet_ping_packet()
        start = time.monotonic()
        sock.sendto(packet, (target_ip, port))
        resp, _ = sock.recvfrom(2048)
        elapsed_ms = round((time.monotonic() - start) * 1000, 1)
        parsed = parse_raknet_pong_packet(resp)
        if not parsed:
            return {"online": False, "error": "Invalid RakNet pong payload"}
        parsed["online"] = True
        parsed["latency_ms"] = elapsed_ms
        return parsed
    except (socket.timeout, TimeoutError):
        return {"online": False, "error": "UDP timeout"}
    except OSError as exc:
        return {"online": False, "error": str(exc.strerror or type(exc).__name__)}
    finally:
        sock.close()


def resolve_host_ips(host, address_type):
    """Resolve domain DNS records or normalize IP literals and enforce public-IP checks."""
    result = {"ipv4": [], "ipv6": [], "non_public": [], "error": ""}
    if address_type in ("ipv4", "ipv6"):
        if not is_public_global_ip(host):
            result["non_public"].append(host)
        elif address_type == "ipv4":
            result["ipv4"].append(host)
        else:
            result["ipv6"].append(host)
        return result

    try:
        records = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    except OSError as exc:
        result["error"] = str(exc.strerror or type(exc).__name__)
        return result

    seen = set()
    for item in records[:32]:
        raw_ip = item[4][0].split("%", 1)[0]
        try:
            ip_obj = ipaddress.ip_address(raw_ip)
        except ValueError:
            continue
        if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
            ip_obj = ip_obj.ipv4_mapped
        canon = str(ip_obj)
        if canon in seen:
            continue
        seen.add(canon)
        if not is_public_global_ip(canon):
            result["non_public"].append(canon)
        elif ip_obj.version == 4:
            result["ipv4"].append(canon)
        else:
            result["ipv6"].append(canon)
    return result


def _http_get_text(url, timeout=4.0, max_bytes=MAX_API_RESPONSE_BYTES):
    """Perform a bounded HTTPS GET request against a hardcoded external endpoint."""
    if not url.startswith("https://"):
        return None, "Unsupported non-HTTPS endpoint"
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": PROBE_USER_AGENT,
            "Accept": "application/json, text/plain",
        },
    )
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read(max_bytes + 1)
            if len(raw) > max_bytes:
                return None, "Response size limit exceeded"
            return raw.decode("utf-8", errors="replace").strip(), ""
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as exc:
        return None, type(exc).__name__


def fetch_public_ips():
    """Retrieve host public WAN IPv4 and optional IPv6 addresses via HTTPS."""
    res = {"ipv4": "", "ipv6": "", "error": ""}
    last_err = ""
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        body, err = _http_get_text(url, timeout=4.0, max_bytes=64)
        if body:
            try:
                res["ipv4"] = str(ipaddress.IPv4Address(body.strip()))
                break
            except ValueError:
                last_err = "Invalid IPv4 payload"
        else:
            last_err = err

    body6, _ = _http_get_text("https://api6.ipify.org", timeout=3.0, max_bytes=64)
    if body6:
        try:
            res["ipv6"] = str(ipaddress.IPv6Address(body6.strip()))
        except ValueError:
            pass

    if not res["ipv4"] and not res["ipv6"]:
        res["error"] = last_err or "Public IP lookup failed"
    return res


def _format_bedrock_api_target(host, port, is_ipv6=False):
    """Format host and port parameter for external Bedrock status API URLs."""
    if is_ipv6:
        safe_host = urllib.parse.quote(host, safe=":")
        return f"[{safe_host}]:{int(port)}"
    safe_host = urllib.parse.quote(host, safe=".-")
    return f"{safe_host}:{int(port)}"


def _parse_mcstatus_bedrock_json(payload):
    """Extract normalized status fields from api.mcstatus.io JSON payload."""
    if not isinstance(payload, dict) or "online" not in payload:
        return None
    ver = payload.get("version") or {}
    motd = payload.get("motd") or {}
    players = payload.get("players") or {}
    return {
        "reachable_api": True,
        "provider": "api.mcstatus.io",
        "online": bool(payload.get("online")),
        "version": str(ver.get("name", "")) if isinstance(ver, dict) else "",
        "motd": str(motd.get("clean", "")) if isinstance(motd, dict) else "",
        "players_online": players.get("online", 0) if isinstance(players, dict) else 0,
        "players_max": players.get("max", 0) if isinstance(players, dict) else 0,
        "server_guid": str(payload.get("server_guid") or ""),
        "error": "",
    }


def _parse_mcsrvstat_bedrock_json(payload):
    """Extract normalized status fields from api.mcsrvstat.us JSON payload."""
    if not isinstance(payload, dict) or "online" not in payload:
        return None
    motd = payload.get("motd") or {}
    clean_lines = motd.get("clean", []) if isinstance(motd, dict) else []
    motd_text = " ".join(str(x) for x in clean_lines) if isinstance(clean_lines, list) else str(clean_lines)
    players = payload.get("players") or {}
    return {
        "reachable_api": True,
        "provider": "api.mcsrvstat.us",
        "online": bool(payload.get("online")),
        "version": str(payload.get("version") or ""),
        "motd": motd_text,
        "players_online": players.get("online", 0) if isinstance(players, dict) else 0,
        "players_max": players.get("max", 0) if isinstance(players, dict) else 0,
        "server_guid": str(payload.get("serverid") or ""),
        "error": "",
    }


def probe_external_bedrock(host, port, is_ipv6=False):
    """Query external Bedrock UDP status scanners using primary and fallback APIs."""
    target = _format_bedrock_api_target(host, port, is_ipv6=is_ipv6)
    providers = (
        (f"https://api.mcstatus.io/v2/status/bedrock/{target}", _parse_mcstatus_bedrock_json),
        (f"https://api.mcsrvstat.us/bedrock/3/{target}", _parse_mcsrvstat_bedrock_json),
    )
    last_err = "External probe unavailable"
    for url, parser in providers:
        text, err = _http_get_text(url, timeout=5.0, max_bytes=MAX_API_RESPONSE_BYTES)
        if text is None:
            last_err = err
            continue
        try:
            parsed = parser(json.loads(text))
            if parsed is not None:
                return parsed
            last_err = "Unexpected API schema"
        except (ValueError, TypeError):
            last_err = "Invalid JSON response"
    return {
        "reachable_api": False,
        "provider": "",
        "online": False,
        "version": "",
        "motd": "",
        "players_online": 0,
        "players_max": 0,
        "server_guid": "",
        "error": last_err,
    }


def create_verify_challenge():
    """Generate a single-use short-lived challenge token for Web UI self-verification."""
    now = time.monotonic()
    with _CHALLENGE_LOCK:
        expired = [k for k, (_, exp) in _PENDING_CHALLENGES.items() if exp <= now]
        for k in expired:
            _PENDING_CHALLENGES.pop(k, None)
        while len(_PENDING_CHALLENGES) >= VERIFY_MAX_PENDING:
            oldest_key = next(iter(_PENDING_CHALLENGES))
            _PENDING_CHALLENGES.pop(oldest_key, None)
        challenge_id = secrets.token_hex(16)
        proof = secrets.token_hex(16)
        _PENDING_CHALLENGES[challenge_id] = (proof, now + VERIFY_CHALLENGE_TTL_SEC)
        return challenge_id, proof


def consume_verify_challenge(challenge_id):
    """Verify and immediately expire a pending self-check challenge ID."""
    if not isinstance(challenge_id, str) or not re.match(r"^[0-9a-f]{32}$", challenge_id):
        return None
    now = time.monotonic()
    with _CHALLENGE_LOCK:
        expired = [k for k, (_, exp) in _PENDING_CHALLENGES.items() if exp <= now]
        for k in expired:
            _PENDING_CHALLENGES.pop(k, None)
        matched_key = None
        for k in _PENDING_CHALLENGES:
            if hmac.compare_digest(k, challenge_id):
                matched_key = k
                break
        if matched_key is None:
            return None
        proof, _ = _PENDING_CHALLENGES.pop(matched_key)
        return proof


def _open_pinned_tcp_socket(pinned_ip, port, timeout, source_address):
    """Open a TCP socket strictly to a validated public IP without re-resolving DNS."""
    if not is_public_global_ip(pinned_ip):
        raise ValueError("SSRF protection: target IP is not a public global address")
    sock = socket.create_connection((pinned_ip, port), timeout, source_address)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    except OSError:
        pass
    return sock


class _PinnedHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection pinned to an already-validated public IP address."""

    def __init__(self, host, port=None, pinned_ip="", timeout=4.0):
        super().__init__(host, port=port, timeout=timeout)
        self._pinned_ip = pinned_ip

    def connect(self):
        self.sock = _open_pinned_tcp_socket(
            self._pinned_ip, self.port, self.timeout, self.source_address
        )


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPSConnection pinned to a public IP while verifying TLS SNI for host."""

    def __init__(self, host, port=None, pinned_ip="", timeout=4.0, context=None):
        super().__init__(host, port=port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip

    def connect(self):
        raw_sock = _open_pinned_tcp_socket(
            self._pinned_ip, self.port, self.timeout, self.source_address
        )
        try:
            self.sock = self._context.wrap_socket(raw_sock, server_hostname=self.host)
        except Exception:
            raw_sock.close()
            raise


def probe_webui_endpoint(scheme, host, port, pinned_ip, timeout=4.0):
    """Probe external Web UI reachability using an ephemeral cryptographic self-check."""
    if scheme not in ("https", "http") or not is_public_global_ip(pinned_ip):
        return {"verified": False, "outcome": "blocked", "status_code": 0}
    challenge_id, expected_proof = create_verify_challenge()
    conn = None
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            conn = _PinnedHTTPSConnection(host, port=port, pinned_ip=pinned_ip, timeout=timeout, context=ctx)
        else:
            conn = _PinnedHTTPConnection(host, port=port, pinned_ip=pinned_ip, timeout=timeout)
        conn.request("GET", f"{VERIFY_PATH_PREFIX}{challenge_id}", headers={"User-Agent": PROBE_USER_AGENT, "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(MAX_HTTP_PROBE_BYTES)
        status = resp.status
        if status == 200:
            try:
                data = json.loads(body.decode("utf-8", errors="strict"))
                got_proof = str(data.get("proof", ""))
                if hmac.compare_digest(got_proof, expected_proof):
                    return {"verified": True, "outcome": "verified", "status_code": status}
            except (ValueError, TypeError):
                pass
            return {"verified": False, "outcome": "mismatch", "status_code": status}
        if scheme == "https" and status in (401, 403):
            return {"verified": False, "outcome": "auth_required", "status_code": status}
        return {"verified": False, "outcome": "mismatch", "status_code": status}
    except ssl.SSLError:
        return {"verified": False, "outcome": "tls_error", "status_code": 0}
    except (socket.timeout, TimeoutError):
        return {"verified": False, "outcome": "timeout", "status_code": 0}
    except ConnectionRefusedError:
        return {"verified": False, "outcome": "refused", "status_code": 0}
    except OSError:
        return {"verified": False, "outcome": "error", "status_code": 0}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        consume_verify_challenge(challenge_id)


def _make_check(check_id, category, label, status, detail, remediation=""):
    """Construct a uniform diagnostic check record."""
    return {
        "id": check_id,
        "category": category,
        "label": label,
        "status": status,
        "detail": detail,
        "remediation": remediation,
    }


def _safe_int_prop(props, key, default_val):
    """Read an integer port property within 1..65535 with safe fallback."""
    raw = str(props.get(key, "")).strip()
    parsed = _parse_port(raw)
    return parsed if parsed is not None else default_val


def _check_bedrock_service():
    """Check whether minecraft-bedrock.service is active."""
    svc = get_service_status()
    if "ACTIVE" in svc:
        return _make_check("bedrock_service", "Local Host", "Bedrock Service Process", "PASS", f"{SERVICE_NAME} status is {svc}.")
    return _make_check(
        "bedrock_service",
        "Local Host",
        "Bedrock Service Process",
        "FAIL",
        f"{SERVICE_NAME} status is {svc}.",
        "Start the server using Start Server or run sudo systemctl start minecraft-bedrock.service.",
    )


def _check_local_udp_binding(prop_v4, prop_v6):
    """Check local UDP port bindings in /proc/net/udp and /proc/net/udp6."""
    udp = get_bound_udp_ports()
    if not udp["supported"]:
        return _make_check("local_udp_binding", "Local Host", "Local UDP Socket Binding", "INFO", "Local procfs UDP table is unavailable on this operating system."), False
    v4_bound = prop_v4 in udp["ipv4_ports"] or prop_v4 in udp["ipv6_ports"]
    v6_bound = prop_v6 in udp["ipv6_ports"]
    if v4_bound:
        v6_note = f"IPv6 UDP port {prop_v6} is also bound." if v6_bound else f"IPv6 UDP port {prop_v6} is not bound."
        return _make_check("local_udp_binding", "Local Host", "Local UDP Socket Binding", "PASS", f"Local UDP port {prop_v4} is listening. {v6_note}"), v6_bound
    return _make_check(
        "local_udp_binding",
        "Local Host",
        "Local UDP Socket Binding",
        "FAIL",
        f"No process is listening on local UDP port {prop_v4}.",
        f"Confirm {SERVICE_NAME} is running and server-port matches {prop_v4}.",
    ), v6_bound


def _check_local_raknet(prop_v4, prop_v6, lan_ip, v6_bound):
    """Execute a local RakNet UDP ping against loopback (and LAN IP fallback)."""
    res = probe_raknet_udp("127.0.0.1", prop_v4, ipv6=False, timeout=2.0)
    if not res["online"] and lan_ip != "Unavailable":
        res = probe_raknet_udp(lan_ip, prop_v4, ipv6=False, timeout=2.0)
    if res["online"]:
        v6_note = ""
        if v6_bound:
            res6 = probe_raknet_udp("::1", prop_v6, ipv6=True, timeout=1.5)
            v6_note = f" IPv6 ::1:{prop_v6} {'online' if res6['online'] else 'no reply'}."
        detail = f"Local RakNet pong received on UDP {prop_v4} in {res['latency_ms']} ms (Version: {res['version']}, Players: {res['players_online']}/{res['players_max']}).{v6_note}"
        return _make_check("local_raknet_ping", "Local Host", "Local RakNet Loopback", "PASS", detail), res.get("server_guid", "")
    return _make_check(
        "local_raknet_ping",
        "Local Host",
        "Local RakNet Loopback",
        "FAIL",
        f"Local RakNet ping to UDP {prop_v4} failed ({res.get('error', 'no response')}).",
        f"Verify {SERVICE_NAME} is running and allow local UDP {prop_v4} in UFW.",
    ), ""


def _check_dns_resolution(host, addr_type):
    """Resolve target address and reject any private or non-public IP targets."""
    resolved = resolve_host_ips(host, addr_type)
    if resolved["non_public"]:
        bad = ", ".join(resolved["non_public"])
        chk = _make_check(
            "dns_resolution",
            "DNS & Routing",
            "DNS & Public IP Validation",
            "FAIL",
            f"Target resolved to non-public IP address(es): {bad}. External checks blocked by SSRF policy.",
            "Update your DNS A/AAAA record to your public WAN IP or UDP tunnel IP.",
        )
        return chk, resolved, True
    if resolved["error"] or (not resolved["ipv4"] and not resolved["ipv6"]):
        err = resolved.get("error") or "No A or AAAA records found"
        chk = _make_check(
            "dns_resolution",
            "DNS & Routing",
            "DNS & Public IP Validation",
            "FAIL",
            f"DNS lookup for {host} failed ({err}).",
            "Create a valid DNS A record (or AAAA record) and wait for propagation.",
        )
        return chk, resolved, True
    parts = []
    if resolved["ipv4"]:
        parts.append("IPv4: " + ", ".join(resolved["ipv4"]))
    if resolved["ipv6"]:
        parts.append("IPv6: " + ", ".join(resolved["ipv6"]))
    return _make_check("dns_resolution", "DNS & Routing", "DNS & Public IP Validation", "PASS", f"Resolved {host} -> {' | '.join(parts)}."), resolved, False


def _check_wan_alignment(resolved, wan_info, ssrf_blocked):
    """Compare resolved IPs against host WAN IP and Cloudflare Proxy CIDRs."""
    if ssrf_blocked:
        return _make_check("wan_ip_alignment", "DNS & Routing", "WAN IP & Proxy Alignment", "INFO", "Skipped WAN comparison because DNS resolution did not produce a public IP."), False
    all_ips = resolved["ipv4"] + resolved["ipv6"]
    cf_ips = [ip for ip in all_ips if is_cloudflare_proxy_ip(ip)]
    if cf_ips:
        return _make_check(
            "wan_ip_alignment",
            "DNS & Routing",
            "WAN IP & Proxy Alignment",
            "FAIL",
            f"Resolved IP ({', '.join(cf_ips)}) is a Cloudflare Proxy (Orange Cloud) IP, which drops Minecraft Bedrock UDP traffic.",
            "Set the Cloudflare DNS record to DNS only (Grey Cloud), or use a UDP tunnel such as playit.gg.",
        ), True

    wan_v4 = wan_info.get("ipv4", "")
    wan_v6 = wan_info.get("ipv6", "")
    if not wan_v4 and not wan_v6:
        return _make_check(
            "wan_ip_alignment",
            "DNS & Routing",
            "WAN IP & Proxy Alignment",
            "WARN",
            f"Could not detect host public WAN IP ({wan_info.get('error', 'lookup failed')}).",
            "Verify outbound HTTPS access on the server.",
        ), False

    v4_match = bool(wan_v4 and wan_v4 in resolved["ipv4"])
    v6_match = bool(wan_v6 and wan_v6 in resolved["ipv6"])
    wan_disp = ", ".join(x for x in (wan_v4, wan_v6) if x)
    if v4_match or v6_match:
        return _make_check("wan_ip_alignment", "DNS & Routing", "WAN IP & Proxy Alignment", "PASS", f"Address matches detected host WAN IP ({wan_disp})."), False
    return _make_check(
        "wan_ip_alignment",
        "DNS & Routing",
        "WAN IP & Proxy Alignment",
        "WARN",
        f"Address resolves to {', '.join(all_ips)}, while host WAN IP is {wan_disp}.",
        "Update your DNS A/AAAA record to your WAN IP for direct port forwarding, or verify your UDP tunnel agent (e.g., playit.gg).",
    ), False


def _check_external_bedrock_v4(host, addr_type, resolved, target_port, prop_v4, lan_ip, local_guid, ssrf_blocked):
    """Check external Bedrock IPv4/domain UDP reachability via public RakNet scanners."""
    if ssrf_blocked:
        return _make_check("external_bedrock_udp", "External Game Access", "External Bedrock UDP (IPv4)", "FAIL", "Skipped external Bedrock probe because DNS resolution failed or was blocked.")
    if addr_type == "ipv6" or (not resolved["ipv4"] and resolved["ipv6"]):
        return _make_check("external_bedrock_udp", "External Game Access", "External Bedrock UDP (IPv4)", "INFO", "Target has no IPv4 address; IPv4 probe skipped (see IPv6 check).")

    ext = probe_external_bedrock(host, target_port, is_ipv6=False)
    if not ext["reachable_api"]:
        return _make_check(
            "external_bedrock_udp",
            "External Game Access",
            "External Bedrock UDP (IPv4)",
            "WARN",
            f"External Bedrock status APIs did not respond ({ext['error']}).",
            "Verify outbound HTTPS access and re-run diagnostics, or test via cellular data.",
        )
    if ext["online"]:
        if local_guid and ext["server_guid"] and str(local_guid) != str(ext["server_guid"]):
            return _make_check(
                "external_bedrock_udp",
                "External Game Access",
                "External Bedrock UDP (IPv4)",
                "WARN",
                f"External probe via {ext['provider']} found an online server at {host}:{target_port}, but GUID {ext['server_guid']} differs from local GUID {local_guid}.",
                "Confirm port forwarding or UDP tunnel routes to this Raspberry Pi rather than another host.",
            )
        return _make_check(
            "external_bedrock_udp",
            "External Game Access",
            "External Bedrock UDP (IPv4)",
            "PASS",
            f"External RakNet UDP verified via {ext['provider']} at {host}:{target_port} (Version: {ext['version'] or 'unknown'}, Players: {ext['players_online']}/{ext['players_max']}).",
        )
    return _make_check(
        "external_bedrock_udp",
        "External Game Access",
        "External Bedrock UDP (IPv4)",
        "FAIL",
        f"External probe via {ext['provider']} could not reach Bedrock UDP at {host}:{target_port}.",
        f"Forward router UDP port {prop_v4} to {lan_ip}:{prop_v4} and allow UDP {prop_v4} in UFW, or start your playit.gg UDP tunnel if behind ISP CGNAT.",
    )


def _check_external_bedrock_v6(resolved, target_port_v6, prop_v6, ssrf_blocked, v4_passed):
    """Check external Bedrock IPv6 UDP reachability when an IPv6 target or AAAA exists."""
    if ssrf_blocked:
        return _make_check("external_bedrock_ipv6", "External Game Access", "External Bedrock UDP (IPv6)", "INFO", "Skipped external IPv6 probe because DNS resolution failed or was blocked.")
    if not resolved["ipv6"]:
        return _make_check("external_bedrock_ipv6", "External Game Access", "External Bedrock UDP (IPv6)", "INFO", "No IPv6 address or AAAA record configured; IPv6 probe skipped.")
    ipv6_addr = resolved["ipv6"][0]
    ext6 = probe_external_bedrock(ipv6_addr, target_port_v6, is_ipv6=True)
    if not ext6["reachable_api"]:
        return _make_check("external_bedrock_ipv6", "External Game Access", "External Bedrock UDP (IPv6)", "WARN", f"External IPv6 Bedrock probe unavailable ({ext6['error']}).")
    if ext6["online"]:
        return _make_check("external_bedrock_ipv6", "External Game Access", "External Bedrock UDP (IPv6)", "PASS", f"External IPv6 RakNet UDP verified via {ext6['provider']} at [{ipv6_addr}]:{target_port_v6} (Version: {ext6['version'] or 'unknown'}).")
    fail_level = "WARN" if v4_passed else "FAIL"
    return _make_check(
        "external_bedrock_ipv6",
        "External Game Access",
        "External Bedrock UDP (IPv6)",
        fail_level,
        f"External probe via {ext6['provider']} could not reach [{ipv6_addr}]:{target_port_v6}.",
        f"Allow inbound IPv6 UDP port {prop_v6} on your router/firewall or remove the AAAA record if using IPv4 only.",
    )


def _check_external_webui(host, resolved, wan_info, ssrf_blocked):
    """Check external Web UI reachability over HTTPS (443) and HTTP (8080)."""
    if ssrf_blocked or (not resolved["ipv4"] and not resolved["ipv6"]):
        return _make_check("external_webui_access", "External Web UI", "External Web UI Reachability", "INFO", "Skipped external Web UI probe because no public IP resolved.")
    target_ip = resolved["ipv4"][0] if resolved["ipv4"] else resolved["ipv6"][0]
    https_res = probe_webui_endpoint("https", host, 443, target_ip, timeout=4.0)
    if https_res["verified"]:
        return _make_check("external_webui_access", "External Web UI", "External Web UI Reachability", "PASS", f"Verified Web UI over HTTPS at https://{host} (TLS valid; self-verify token matched).")
    if https_res["outcome"] == "auth_required":
        return _make_check(
            "external_webui_access",
            "External Web UI",
            "External Web UI Reachability",
            "WARN",
            f"HTTPS endpoint https://{host} returned HTTP {https_res['status_code']} (valid TLS with upstream authentication gate).",
            "Automatic token probe was blocked by upstream auth; test Web UI login manually via HTTPS.",
        )
    if https_res["outcome"] == "tls_error":
        return _make_check(
            "external_webui_access",
            "External Web UI",
            "External Web UI Reachability",
            "WARN",
            f"HTTPS endpoint https://{host} failed TLS certificate verification.",
            "Install a valid TLS certificate (Let's Encrypt, Caddy, Nginx, or Cloudflare Origin certificate).",
        )

    http_res = probe_webui_endpoint("http", host, PORT, target_ip, timeout=4.0)
    if http_res["verified"]:
        return _make_check(
            "external_webui_access",
            "External Web UI",
            "External Web UI Reachability",
            "WARN",
            f"Web UI is reachable at http://{host}:{PORT} over unencrypted HTTP. OWASP ASVS V2/V9 Warning: Basic Authentication sends passwords in plaintext.",
            "Place an HTTPS reverse proxy (Caddy/Nginx) or Cloudflare Tunnel in front of port 8080, or keep TCP 8080 closed to the internet.",
        )
    if http_res["outcome"] == "timeout" and target_ip in (wan_info.get("ipv4", ""), wan_info.get("ipv6", "")):
        return _make_check(
            "external_webui_access",
            "External Web UI",
            "External Web UI Reachability",
            "WARN",
            f"Web UI self-check timed out on https://{host} and http://{host}:{PORT} (closed externally, LAN-only, or router blocks NAT hairpinning).",
            "For remote Web UI access, configure an HTTPS reverse proxy or Cloudflare Tunnel. Keeping TCP 8080 LAN-only is safer.",
        )
    return _make_check(
        "external_webui_access",
        "External Web UI",
        "External Web UI Reachability",
        "FAIL",
        f"Web UI unreachable externally at https://{host} and http://{host}:{PORT} (HTTPS: {https_res['outcome']}, HTTP: {http_res['outcome']}).",
        "Configure an HTTPS reverse proxy (port 443) or Cloudflare Tunnel to forward to localhost:8080 if external admin access is needed.",
    )


def run_connectivity_diagnostics(parsed_address):
    """Run ordered local, DNS, WAN, Bedrock UDP, and Web UI external checks."""
    props = read_properties()
    prop_v4 = _safe_int_prop(props, "server-port", 19132)
    prop_v6 = _safe_int_prop(props, "server-portv6", 19133)
    port_override = parsed_address.get("port_override")
    target_v4_port = port_override if port_override else prop_v4
    target_v6_port = port_override if port_override else prop_v6
    host = parsed_address["host"]
    addr_type = parsed_address["address_type"]
    lan_ip = get_local_lan_ipv4()

    checks = []
    checks.append(_check_bedrock_service())
    udp_chk, v6_bound = _check_local_udp_binding(prop_v4, prop_v6)
    checks.append(udp_chk)
    rak_chk, local_guid = _check_local_raknet(prop_v4, prop_v6, lan_ip, v6_bound)
    checks.append(rak_chk)

    dns_chk, resolved, ssrf_blocked = _check_dns_resolution(host, addr_type)
    checks.append(dns_chk)

    wan_info = fetch_public_ips()
    wan_chk, cf_proxied = _check_wan_alignment(resolved, wan_info, ssrf_blocked)
    checks.append(wan_chk)

    v4_chk = _check_external_bedrock_v4(host, addr_type, resolved, target_v4_port, prop_v4, lan_ip, local_guid, ssrf_blocked)
    checks.append(v4_chk)
    v4_passed = v4_chk["status"] == "PASS"

    v6_chk = _check_external_bedrock_v6(resolved, target_v6_port, prop_v6, ssrf_blocked, v4_passed)
    checks.append(v6_chk)
    v6_passed = v6_chk["status"] == "PASS"

    if wan_chk["status"] == "WARN" and not cf_proxied and (v4_passed or v6_passed):
        wan_chk["status"] = "PASS"
        wan_chk["detail"] = f"Resolved IP differs from host WAN IP, and external Bedrock UDP succeeded (UDP tunnel/relay topology such as playit.gg detected)."
        wan_chk["remediation"] = ""

    checks.append(_check_external_webui(host, resolved, wan_info, ssrf_blocked))

    statuses = [c["status"] for c in checks]
    overall = "FAIL" if "FAIL" in statuses else ("WARN" if "WARN" in statuses else "PASS")
    return {
        "overall_status": overall,
        "checked_utc": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "lan_ip": lan_ip,
        "wan_ipv4": wan_info.get("ipv4", ""),
        "wan_ipv6": wan_info.get("ipv6", ""),
        "effective_bedrock_port": target_v4_port,
        "effective_bedrock_port_v6": target_v6_port,
        "resolved_ipv4": resolved["ipv4"],
        "resolved_ipv6": resolved["ipv6"],
        "cloudflare_proxied": cf_proxied,
        "checks": checks,
    }


def _status_badge_html(status):
    """Render an HTML status pill badge with fixed palette colors."""
    styles = {
        "PASS": ("#28a745", "#fff"),
        "WARN": ("#ffc107", "#000"),
        "FAIL": ("#dc3545", "#fff"),
        "INFO": ("#17a2b8", "#fff"),
    }
    bg, fg = styles.get(status, ("#6c757d", "#fff"))
    label = html_lib.escape(status)
    return f'<span class="badge" style="background:{bg}; color:{fg};">{label}</span>'


def _render_address_report_html(address_cfg, report, props):
    """Render cached diagnostic summary cards and check breakdown table."""
    host = address_cfg.get("host", "")
    eff_port = report.get("effective_bedrock_port", _safe_int_prop(props, "server-port", 19132))
    join_host = f"[{host}]" if address_cfg.get("address_type") == "ipv6" else host
    join_str = f"{join_host}:{eff_port}"
    escaped_join = html_lib.escape(join_str, quote=True)
    escaped_host = html_lib.escape(join_host)
    lan_disp = html_lib.escape(report.get("lan_ip") or "Unavailable")
    wan_disp = html_lib.escape(report.get("wan_ipv4") or report.get("wan_ipv6") or "Unavailable")
    checked_disp = html_lib.escape(report.get("checked_utc") or address_cfg.get("last_checked_utc") or "")

    rows = []
    for chk in report.get("checks", []):
        c_cat = html_lib.escape(str(chk.get("category", "")))
        c_lbl = html_lib.escape(str(chk.get("label", "")))
        c_stat = _status_badge_html(str(chk.get("status", "INFO")))
        c_det = html_lib.escape(str(chk.get("detail", "")))
        c_rem = str(chk.get("remediation", "")).strip()
        rem_block = f'<div style="margin-top:4px; font-size:12px; color:#856404;"><strong>Remediation:</strong> {html_lib.escape(c_rem)}</div>' if c_rem else ""
        rows.append(f"<tr><td>{c_cat}</td><td><strong>{c_lbl}</strong></td><td>{c_stat}</td><td>{c_det}{rem_block}</td></tr>")

    return f"""
        <div class="grid-3" style="margin: 15px 0;">
          <div class="stat-box">
            <div class="stat-label">Minecraft Join Address</div>
            <div class="stat-val" style="font-size:15px;"><code>{escaped_join}</code></div>
            <div class="stat-sub"><button type="button" class="btn btn-primary btn-sm" style="margin-top:6px;" data-copy="{escaped_join}" onclick="copyJoinAddress(this)">Copy Join Address</button></div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Web UI Endpoints Checked</div>
            <div class="stat-sub" style="margin-top:6px;">HTTPS: <code>https://{escaped_host}</code></div>
            <div class="stat-sub">HTTP: <code>http://{escaped_host}:{PORT}</code></div>
          </div>
          <div class="stat-box">
            <div class="stat-label">Detected Network &amp; Check Time</div>
            <div class="stat-sub" style="margin-top:6px;">LAN IPv4: <code>{lan_disp}</code> | WAN: <code>{wan_disp}</code></div>
            <div class="stat-sub">Checked: {checked_disp}</div>
          </div>
        </div>
        <table>
          <thead><tr><th>Category</th><th>Diagnostic Check</th><th>Status</th><th>Details &amp; Remediation</th></tr></thead>
          <tbody>{"".join(rows)}</tbody>
        </table>
    """


def render_address_management_card(address_cfg, props, flash_code=""):
    """Render the Address & Connectivity Management Web UI card safely."""
    raw_addr = address_cfg.get("raw_address", "")
    host = address_cfg.get("host", "")
    report = address_cfg.get("last_report")
    overall = report.get("overall_status", "NOT CONFIGURED") if isinstance(report, dict) else "NOT CONFIGURED"
    overall_badge = _status_badge_html(overall)

    flash_html = ""
    if flash_code in ADDRESS_FLASH_MESSAGES:
        kind, text = ADDRESS_FLASH_MESSAGES[flash_code]
        bg_map = {"success": ("#d4edda", "#155724", "#c3e6cb"), "error": ("#f8d7da", "#721c24", "#f5c6cb"), "info": ("#d1ecf1", "#0c5460", "#bee5eb")}
        bg, fg, bd = bg_map.get(kind, ("#e2e3e5", "#383d41", "#d6d8db"))
        flash_html = f'<div style="background:{bg}; color:{fg}; border:1px solid {bd}; border-radius:4px; padding:10px 12px; margin-bottom:15px; font-size:14px;">{html_lib.escape(text)}</div>'

    escaped_raw = html_lib.escape(raw_addr, quote=True)
    has_saved = bool(host)
    recheck_btn = (
        '<form method="POST" action="/address/check" style="margin:0;"><button class="btn btn-backup" type="submit" style="margin:0;">Re-check Now</button></form>'
        if has_saved
        else ""
    )
    clear_btn = (
        '<form method="POST" action="/address/clear" style="margin:0;" onsubmit="return confirm(\'Clear saved address and diagnostic report?\');"><button class="btn btn-danger btn-sm" type="submit" style="margin:0; padding:8px 12px; font-size:14px;">Clear</button></form>'
        if has_saved
        else ""
    )
    report_html = _render_address_report_html(address_cfg, report, props) if (has_saved and isinstance(report, dict)) else ""

    return f"""
  <div class="card">
    <h2>Address &amp; Connectivity Management {overall_badge}</h2>
    {flash_html}
    <form method="POST" action="/address/save" style="margin-bottom: 10px;">
      <div class="form-group">
        <label for="server_address_input">External Server Address (Custom Domain, Public IPv4, or IPv6)</label>
        <div style="display:flex; gap:10px; align-items:center; flex-wrap:wrap;">
          <input type="text" id="server_address_input" name="address" value="{escaped_raw}" placeholder="e.g. play.example.com or 93.184.216.34" style="flex:1; min-width:240px;" required>
          <button class="btn btn-primary" type="submit" style="margin:0; white-space:nowrap;">Save &amp; Check Connectivity</button>
        </div>
        <small style="display:block; color:#666; margin-top:6px;">Enter a domain or public IP (optional <code>:port</code>). Saving runs local UDP, DNS, WAN IP, external Bedrock RakNet, and Web UI checks.</small>
      </div>
    </form>
    <div style="display:flex; gap:10px; flex-wrap:wrap; align-items:center; margin-bottom:10px;">
      {recheck_btn}
      {clear_btn}
    </div>
    {report_html}
    <small style="display:block; color:#777; margin-top:10px;">Note: Diagnostics query public HTTPS endpoints (<code>api.ipify.org</code>, <code>ipv4.icanhazip.com</code>, <code>api6.ipify.org</code>, <code>api.mcstatus.io</code>, <code>api.mcsrvstat.us</code>) only when you save or click Re-check.</small>
  </div>
    """


class WebUIHandler(http.server.BaseHTTPRequestHandler):
    def check_auth(self):
        auth_header = self.headers.get("Authorization")
        creds = get_auth_credentials()
        expected_pass = creds.get("admin_pass", "admin123")

        if auth_header and auth_header.startswith("Basic "):
            import base64

            try:
                decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
                user, password = decoded.split(":", 1)
                if user == "admin" and password == expected_pass:
                    return True
            except Exception:
                pass

        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="Minecraft Server Web UI"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(b"401 Unauthorized - Access Denied")
        return False

    def handle_verify_challenge(self, path):
        """Serve single-use proof token for external Web UI reachability self-checks."""
        challenge_id = path[len(VERIFY_PATH_PREFIX):]
        proof = consume_verify_challenge(challenge_id)
        if proof is None:
            self.send_response(HTTPStatus.NOT_FOUND)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(b"404 Not Found")
            return
        payload = json.dumps({"service": "pi-rock-webui", "proof": proof}).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path.startswith(VERIFY_PATH_PREFIX):
            self.handle_verify_challenge(path)
            return

        if not self.check_auth():
            return

        if path == "/world/download":
            self.handle_live_world_download()
            return
        elif path == "/backup/download":
            self.handle_backup_download(query)
            return

        status = get_service_status()
        props = read_properties()
        backups = list_backups()
        stats = get_device_stats()
        backup_cfg = read_backup_config()
        address_cfg = read_address_config()
        unified_players, default_role = get_unified_players()
        current_level_name = props.get("level-name", "Bedrock level")
        flash_code = query.get("addr_err", [""])[0] or query.get("addr_msg", [""])[0]
        address_card_html = render_address_management_card(address_cfg, props, flash_code=flash_code)

        status_color = "#28a745" if "ACTIVE" in status else "#dc3545"

        auto_bk_enabled = backup_cfg.get("auto_backup_enabled", True)
        interval_hrs = backup_cfg.get("interval_hours", 6)
        retention_days = backup_cfg.get("retention_days", 7)
        max_backups = backup_cfg.get("max_backups", 20)

        interval_options = [
            (1, "Every 1 Hour"),
            (3, "Every 3 Hours"),
            (6, "Every 6 Hours (Recommended)"),
            (12, "Every 12 Hours"),
            (24, "Daily (Every 24 Hours)"),
            (168, "Weekly (Every 7 Days)"),
        ]

        interval_select_html = "".join(
            f'<option value="{val}" {"selected" if val == interval_hrs else ""}>{label}</option>'
            for val, label in interval_options
        )

        schedule_badge = (
            f'<span style="color:#28a745; font-weight:bold;">ENABLED</span> (Every {interval_hrs}h)'
            if auto_bk_enabled
            else '<span style="color:#dc3545; font-weight:bold;">DISABLED</span>'
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Minecraft Bedrock Server Manager</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #f4f6f8; margin: 0; padding: 20px; color: #333; }}
  .container {{ max-width: 960px; margin: 0 auto; }}
  .card {{ background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); padding: 20px; margin-bottom: 20px; }}
  h1, h2, h3 {{ margin-top: 0; color: #1a1a1a; }}
  .badge {{ display: inline-block; padding: 4px 8px; font-weight: bold; border-radius: 4px; color: #fff; font-size: 12px; }}
  .btn {{ display: inline-block; padding: 8px 16px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; text-decoration: none; color: #fff; font-size: 14px; margin-right: 8px; margin-bottom: 8px; }}
  .btn-start {{ background: #28a745; }}
  .btn-stop {{ background: #dc3545; }}
  .btn-restart {{ background: #ffc107; color: #000; }}
  .btn-backup {{ background: #17a2b8; }}
  .btn-primary {{ background: #007bff; }}
  .btn-success {{ background: #28a745; }}
  .btn-danger {{ background: #dc3545; }}
  .btn-warning {{ background: #ffc107; color: #000; }}
  .btn-sm {{ padding: 4px 8px; font-size: 12px; }}
  .form-group {{ margin-bottom: 15px; }}
  label {{ display: block; font-weight: bold; margin-bottom: 5px; font-size: 13px; text-transform: uppercase; color: #555; }}
  input[type="text"], input[type="number"], input[type="file"], select {{ width: 100%; padding: 8px 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
  .grid-3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 15px; }}
  .grid-4 {{ display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 15px; }}
  @media (max-width: 650px) {{ .grid, .grid-3, .grid-4 {{ grid-template-columns: 1fr; }} }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ background: #f8f9fa; font-size: 13px; text-transform: uppercase; }}
  .action-group {{ display: flex; gap: 5px; align-items: center; }}
  .stat-box {{ background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 6px; padding: 12px; }}
  .stat-label {{ font-size: 12px; text-transform: uppercase; color: #6c757d; font-weight: bold; }}
  .stat-val {{ font-size: 18px; font-weight: bold; color: #212529; margin-top: 4px; }}
  .stat-sub {{ font-size: 12px; color: #495057; margin-top: 2px; }}
  .toolbar {{ display: flex; flex-wrap: wrap; gap: 10px; align-items: center; margin-bottom: 15px; }}
</style>
<script>
  function toggleSelectAll(master) {{
    var chks = document.querySelectorAll('.backup-chk');
    for (var i = 0; i < chks.length; i++) {{
      chks[i].checked = master.checked;
    }}
  }}
  function confirmBatchDelete() {{
    var chks = document.querySelectorAll('.backup-chk:checked');
    if (chks.length === 0) {{
      alert('Please select at least one backup archive to delete.');
      return false;
    }}
    return confirm('Permanently delete ' + chks.length + ' selected backup archive(s)?');
  }}
  function promptAssignXuid(gamertag) {{
    var xuid = prompt('Enter 16-digit Xbox User ID (XUID) for player \"' + gamertag + '\":');
    if (xuid && /^[0-9]+$/.test(xuid.trim())) {{
      var role = prompt('Enter permission role (visitor, member, operator, default):', 'member');
      if (role) {{
        document.getElementById('assign_gamertag').value = gamertag;
        document.getElementById('assign_xuid').value = xuid.trim();
        document.getElementById('assign_permission').value = role.trim().toLowerCase();
        document.getElementById('assignXuidForm').submit();
      }}
    }} else if (xuid) {{
      alert('Invalid XUID format. Must contain digits only.');
    }}
  }}
  function copyJoinAddress(btn) {{
    var val = btn.getAttribute('data-copy') || '';
    if (!val) {{
      return;
    }}
    if (navigator.clipboard && navigator.clipboard.writeText) {{
      navigator.clipboard.writeText(val).then(function() {{
        var prev = btn.textContent;
        btn.textContent = 'Copied!';
        setTimeout(function() {{ btn.textContent = prev; }}, 1500);
      }});
    }} else {{
      window.prompt('Copy Minecraft Bedrock join address:', val);
    }}
  }}
</script>
</head>
<body>
<div class="container">
  <h1>Minecraft Bedrock Server Manager</h1>
  
  <div class="card">
    <h2>Server Status: <span class="badge" style="background:{status_color}; font-size:14px; padding:6px 12px;">{status}</span></h2>
    <form method="POST" action="/action" style="display:inline;">
      <input type="hidden" name="action" value="start">
      <button class="btn btn-start" type="submit">Start Server</button>
    </form>
    <form method="POST" action="/action" style="display:inline;">
      <input type="hidden" name="action" value="restart">
      <button class="btn btn-restart" type="submit">Restart Server</button>
    </form>
    <form method="POST" action="/action" style="display:inline;">
      <input type="hidden" name="action" value="stop">
      <button class="btn btn-stop" type="submit">Stop Server</button>
    </form>
    <form method="POST" action="/action" style="display:inline;">
      <input type="hidden" name="action" value="backup">
      <button class="btn btn-backup" type="submit">Create New Backup Now</button>
    </form>
  </div>
  {address_card_html}

  <div class="card">
    <h2>Device & Hardware Telemetry</h2>
    
    <div class="grid-3" style="margin-bottom: 15px;">
      <div class="stat-box">
        <div class="stat-label">System Uptime</div>
        <div class="stat-val">{stats['uptime']}</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">SoC Temperature</div>
        <div class="stat-val">{stats['cpu_temp']}</div>
      </div>
      <div class="stat-box">
        <div class="stat-label">CPU Load (1m, 5m, 15m)</div>
        <div class="stat-val" style="font-size:15px;">{stats['load_avg']}</div>
      </div>
    </div>

    <div class="grid">
      <div class="stat-box">
        <div class="stat-label">Primary Disk Storage (/)</div>
        <div class="stat-val">{stats['root_used_gb']} / {stats['root_total_gb']} GiB ({stats['root_pct']}%)</div>
        <div class="stat-sub">Free: {stats['root_free_gb']} GiB</div>
        {get_progress_bar(stats['root_pct'])}
      </div>

      <div class="stat-box">
        <div class="stat-label">World Storage Drive {'(External USB)' if stats['is_external_worlds'] else '(Internal)'}</div>
        <div class="stat-val">{stats['worlds_used_gb']} / {stats['worlds_total_gb']} GiB ({stats['worlds_pct']}%)</div>
        <div class="stat-sub">Path: <code>{stats['worlds_path']}</code></div>
        {get_progress_bar(stats['worlds_pct'])}
      </div>

      <div class="stat-box">
        <div class="stat-label">RAM Memory Usage</div>
        <div class="stat-val">{stats['ram_used_mb']} / {stats['ram_total_mb']} MiB ({stats['ram_pct']}%)</div>
        <div class="stat-sub">Available: {stats['ram_free_mb']} MiB</div>
        {get_progress_bar(stats['ram_pct'])}
      </div>

      <div class="stat-box">
        <div class="stat-label">Swap Memory Allocation</div>
        <div class="stat-val">{stats['swap_used_mb']} / {stats['swap_total_mb']} MiB ({stats['swap_pct']}%)</div>
        <div class="stat-sub">Free: {stats['swap_free_mb']} MiB</div>
        {get_progress_bar(stats['swap_pct'])}
      </div>
    </div>
  </div>

  <div class="card">
    <h2>World Management & File Operations</h2>
    <p>Active World: <strong>{current_level_name}</strong></p>
    
    <div style="margin-bottom: 20px;">
      <a href="/world/download" class="btn btn-success" style="font-size:15px;">Download Current Live World (.mcworld)</a>
    </div>

    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">

    <h3>Upload Existing World (.mcworld / .zip / .tar.gz)</h3>
    <form method="POST" action="/world/upload" enctype="multipart/form-data">
      <div style="display: flex; gap: 10px; align-items: center;">
        <input type="file" name="worldfile" accept=".mcworld,.zip,.tar.gz" required style="flex:1;">
        <button class="btn btn-primary" type="submit" style="margin:0; white-space:nowrap;">Upload & Activate World</button>
      </div>
      <small style="display:block; color:#666; margin-top:6px;">An automatic safety backup is created before replacing the current world.</small>
    </form>
  </div>

  <div class="card">
    <h2>Automated Backup Schedule & Retention Policy</h2>
    <form method="POST" action="/backup/settings">
      <div class="grid">
        <div class="form-group">
          <label style="display:flex; align-items:center; gap:8px; cursor:pointer; text-transform:none; font-size:14px; margin-top:25px;">
            <input type="checkbox" name="auto_backup_enabled" value="true" {"checked" if auto_bk_enabled else ""} style="width:20px; height:20px;">
            <strong>Enable Automated Scheduled Backups</strong>
          </label>
        </div>
        <div class="form-group">
          <label for="interval_hours">Backup Interval</label>
          <select id="interval_hours" name="interval_hours">
            {interval_select_html}
          </select>
        </div>
      </div>
      
      <div class="grid">
        <div class="form-group">
          <label for="retention_days">Retention Threshold (Days)</label>
          <input type="number" id="retention_days" name="retention_days" min="1" max="365" value="{retention_days}">
          <small style="color:#666;">Delete backup archives older than this threshold.</small>
        </div>
        <div class="form-group">
          <label for="max_backups">Maximum Archives to Retain</label>
          <input type="number" id="max_backups" name="max_backups" min="1" max="100" value="{max_backups}">
          <small style="color:#666;">Retain at most this number of recent backup archives.</small>
        </div>
      </div>

      <div style="margin-top: 10px; display:flex; gap:10px; flex-wrap:wrap; align-items:center;">
        <button class="btn btn-primary" type="submit">Save Backup Configuration</button>
      </div>
    </form>

    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">

    <div style="display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:10px;">
      <div>
        <strong>Manual Retention Enforcement:</strong>
        <span style="color:#666; font-size:13px; margin-left:6px;">Prunes archives exceeding {retention_days} days or {max_backups} total files.</span>
      </div>
      <form method="POST" action="/backup/prune" style="margin:0;" onsubmit="return confirm('Execute retention prune now according to policy?');">
        <button class="btn btn-warning btn-sm" type="submit">Prune Expired Backups Now</button>
      </form>
    </div>
  </div>

  <div class="card">
    <h2>Available Server Backups ({len(backups)})</h2>
    <p style="font-size:14px; color:#555; margin-bottom:15px;">
      Auto-Schedule: {schedule_badge} &nbsp;|&nbsp; Retention: <strong>{retention_days} days</strong> / Max <strong>{max_backups} archives</strong>
    </p>

    <form method="POST" action="/backup/batch_delete" id="batchDeleteForm" onsubmit="return confirmBatchDelete();">
      <div class="toolbar">
        <button class="btn btn-danger btn-sm" type="submit">Delete Selected Backups</button>
        <button class="btn btn-danger btn-sm" type="button" onclick="if(confirm('Are you ABSOLUTELY sure you want to PERMANENTLY DELETE ALL BACKUPS?')) {{ document.getElementById('deleteAllForm').submit(); }}" style="background:#b02a37;">Delete All Backups</button>
      </div>

      <table>
        <thead>
          <tr>
            <th style="width:30px;"><input type="checkbox" id="selectAll" onclick="toggleSelectAll(this)" title="Select All"></th>
            <th>Backup Archive</th>
            <th>Size</th>
            <th>Timestamp</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
"""
        if not backups:
            html += '<tr><td colspan="5" style="text-align:center;color:#888;">No backups created yet. Click "Create New Backup Now" above.</td></tr>'
        else:
            for b in backups:
                fname = b["filename"]
                fsize = b["size_mb"]
                ftime = b["modified"]
                html += f"""<tr>
                  <td><input type="checkbox" name="files" value="{fname}" class="backup-chk"></td>
                  <td><code>{fname}</code></td>
                  <td>{fsize} MiB</td>
                  <td>{ftime}</td>
                  <td>
                    <div class="action-group">
                      <a href="/backup/download?file={urllib.parse.quote(fname)}" class="btn btn-primary btn-sm">Download</a>
                      <button class="btn btn-restart btn-sm" type="button" onclick="if(confirm('Restore backup {fname}? Current world will be backed up and replaced.')) {{ document.getElementById('restore_file').value='{fname}'; document.getElementById('singleRestoreForm').submit(); }}">Restore</button>
                      <button class="btn btn-danger btn-sm" type="button" onclick="if(confirm('Delete backup {fname}?')) {{ document.getElementById('delete_file').value='{fname}'; document.getElementById('singleDeleteForm').submit(); }}">Delete</button>
                    </div>
                  </td>
                </tr>"""

        html += f"""
        </tbody>
      </table>
    </form>

    <!-- Hidden standalone backup action forms -->
    <form method="POST" action="/backup/restore" id="singleRestoreForm" style="display:none;">
      <input type="hidden" name="filename" id="restore_file" value="">
    </form>
    <form method="POST" action="/backup/delete" id="singleDeleteForm" style="display:none;">
      <input type="hidden" name="filename" id="delete_file" value="">
    </form>
    <form method="POST" action="/backup/delete_all" id="deleteAllForm" style="display:none;">
    </form>
  </div>

  <div class="card">
    <h2>Player Access Control & Permission Management</h2>
    <p style="font-size:14px; color:#555; margin-bottom:15px;">
      Server-wide Default Role: <strong>{default_role.upper()}</strong> (Configurable under server.properties)
    </p>

    <h3>Add Authorized Player</h3>
    <form method="POST" action="/player/add" style="margin-bottom: 20px;">
      <div class="grid-3" style="align-items:flex-end;">
        <div class="form-group" style="margin-bottom:0;">
          <label for="new_gamertag">Xbox Gamertag</label>
          <input type="text" id="new_gamertag" name="gamertag" placeholder="e.g. PlayerOne" required>
        </div>
        <div class="form-group" style="margin-bottom:0;">
          <label for="new_xuid">XUID (Optional, 16 Digits)</label>
          <input type="text" id="new_xuid" name="xuid" placeholder="e.g. 2535412345678901">
        </div>
        <div class="form-group" style="margin-bottom:0;">
          <label for="new_permission">Initial Permission Role</label>
          <select id="new_permission" name="permission">
            <option value="default">Default ({default_role})</option>
            <option value="visitor">Visitor</option>
            <option value="member">Member</option>
            <option value="operator">Operator (Admin)</option>
          </select>
        </div>
      </div>
      <button class="btn btn-primary" type="submit" style="margin-top: 12px;">Add Player & Save Role</button>
    </form>

    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">

    <h3>Authorized Players & Roles ({len(unified_players)})</h3>
    <table>
      <thead>
        <tr>
          <th>#</th>
          <th>Xbox Gamertag</th>
          <th>Xbox User ID (XUID)</th>
          <th>Current Role</th>
          <th>Change Role</th>
          <th>Allowlist</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
"""
        if not unified_players:
            html += '<tr><td colspan="7" style="text-align:center;color:#888;">No authorized players configured. Add a player above.</td></tr>'
        else:
            for idx, p in enumerate(unified_players, 1):
                pname = p["name"]
                pxuid = p["xuid"]
                perm = p["permission"]
                is_allow = "Yes" if p["is_allowlisted"] else "No (Direct XUID)"

                if perm == "operator":
                    role_badge = '<span class="badge" style="background:#dc3545;">Operator</span>'
                elif perm == "member":
                    role_badge = '<span class="badge" style="background:#28a745;">Member</span>'
                elif perm == "visitor":
                    role_badge = '<span class="badge" style="background:#17a2b8;">Visitor</span>'
                else:
                    role_badge = f'<span class="badge" style="background:#6c757d;">Default ({default_role})</span>'

                role_change_cell = ""
                if pxuid:
                    role_change_cell = f"""
                    <form method="POST" action="/player/set_permission" style="margin:0; display:flex; gap:4px; align-items:center;">
                      <input type="hidden" name="xuid" value="{pxuid}">
                      <input type="hidden" name="gamertag" value="{pname}">
                      <select name="permission" style="width:auto; padding:4px 8px; font-size:12px;">
                        <option value="default" {"selected" if perm=="default" else ""}>Default ({default_role})</option>
                        <option value="visitor" {"selected" if perm=="visitor" else ""}>Visitor</option>
                        <option value="member" {"selected" if perm=="member" else ""}>Member</option>
                        <option value="operator" {"selected" if perm=="operator" else ""}>Operator</option>
                      </select>
                      <button class="btn btn-primary btn-sm" type="submit" style="margin:0;">Apply</button>
                    </form>"""
                else:
                    role_change_cell = f"""
                    <button class="btn btn-sm" style="background:#6c757d; margin:0;" type="button" onclick="promptAssignXuid('{pname}')">Assign XUID</button>
                    """

                xuid_display = f"<code>{pxuid}</code>" if pxuid else '<span style="color:#888; font-size:12px;">(Pending connection)</span>'

                html += f"""<tr>
                  <td>{idx}</td>
                  <td><strong>{pname}</strong></td>
                  <td>{xuid_display}</td>
                  <td>{role_badge}</td>
                  <td>{role_change_cell}</td>
                  <td>{is_allow}</td>
                  <td>
                    <form method="POST" action="/player/remove" style="margin:0;" onsubmit="return confirm('Remove player {pname} from access list?');">
                      <input type="hidden" name="gamertag" value="{pname}">
                      <input type="hidden" name="xuid" value="{pxuid}">
                      <button class="btn btn-danger btn-sm" type="submit">Remove</button>
                    </form>
                  </td>
                </tr>"""

        html += """
      </tbody>
    </table>

    <div style="background:#f8f9fa; border:1px solid #e9ecef; border-radius:6px; padding:12px; margin-top:15px; font-size:13px; color:#555;">
      <strong>Role Descriptions:</strong>
      <ul style="margin:6px 0 0 18px; padding:0;">
        <li><strong>Visitor:</strong> Read-only exploration mode. Cannot mine, build, craft, or open containers.</li>
        <li><strong>Member:</strong> Standard survival gameplay. Can build, mine, craft, and attack.</li>
        <li><strong>Operator:</strong> Full administrator privileges with access to in-game console commands (e.g. <code>/op</code>, <code>/teleport</code>, <code>/gamemode</code>).</li>
        <li><strong>Default:</strong> Inherits the <code>default-player-permission-level</code> configured in <code>server.properties</code>.</li>
      </ul>
      <small style="display:block; margin-top:6px; color:#777;">* Note: If an XUID is omitted when adding a Gamertag, the server registers the 16-digit XUID automatically upon the player's first connection.</small>
    </div>

    <!-- Hidden form for promptAssignXuid -->
    <form method="POST" action="/player/set_permission" id="assignXuidForm" style="display:none;">
      <input type="hidden" name="gamertag" id="assign_gamertag" value="">
      <input type="hidden" name="xuid" id="assign_xuid" value="">
      <input type="hidden" name="permission" id="assign_permission" value="">
    </form>
  </div>

  <div class="card">
    <h2>Server Configuration (server.properties)</h2>
    <form method="POST" action="/settings">
      <div class="grid">
"""
        for key, spec in VALID_PROPERTIES.items():
            val = props.get(key, "")
            html += f'<div class="form-group"><label for="{key}">{key}</label>'
            if isinstance(spec, list):
                html += f'<select id="{key}" name="{key}">'
                for opt in spec:
                    sel = "selected" if val.lower() == opt.lower() else ""
                    html += f'<option value="{opt}" {sel}>{opt}</option>'
                html += "</select>"
            elif spec is int:
                html += f'<input type="number" id="{key}" name="{key}" value="{val}">'
            else:
                html += f'<input type="text" id="{key}" name="{key}" value="{val}">'
            html += "</div>"

        html += """
      </div>
      <button class="btn btn-primary" type="submit" style="margin-top: 15px; font-size: 16px; padding: 10px 20px;">Save Configuration & Apply</button>
    </form>
  </div>
</div>
</body>
</html>
"""
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def handle_live_world_download(self):
        props = read_properties()
        level_name = props.get("level-name", "Bedrock level")
        worlds_root = get_active_worlds_dir()
        target_world_path = os.path.join(worlds_root, level_name)

        if not os.path.exists(target_world_path):
            subdirs = [d for d in os.listdir(worlds_root) if os.path.isdir(os.path.join(worlds_root, d))] if os.path.exists(worlds_root) else []
            if subdirs:
                target_world_path = os.path.join(worlds_root, subdirs[0])
            else:
                self.send_error(HTTPStatus.NOT_FOUND, "No world files found on server.")
                return

        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(target_world_path):
                for file in files:
                    full_p = os.path.join(root, file)
                    rel_p = os.path.relpath(full_p, target_world_path)
                    zf.write(full_p, rel_p)

        zip_data = buf.getvalue()
        timestamp = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        clean_name = re.sub(r'[^a-zA-Z0-9_-]', '_', level_name)
        out_filename = f"{clean_name}_{timestamp}.mcworld"

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Disposition", f'attachment; filename="{out_filename}"')
        self.send_header("Content-Length", str(len(zip_data)))
        self.end_headers()
        self.wfile.write(zip_data)

    def handle_backup_download(self, query):
        filename = query.get("file", [""])[0]
        if not re.match(r'^bedrock_backup_[a-zA-Z0-9_.-]+\.(tar\.gz|zip)$', filename):
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid backup filename parameter.")
            return

        filepath = os.path.join(BACKUP_DIR, filename)
        if not os.path.exists(filepath):
            self.send_error(HTTPStatus.NOT_FOUND, "Backup file not found.")
            return

        stat = os.stat(filepath)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/gzip" if filename.endswith(".tar.gz") else "application/zip")
        self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.send_header("Content-Length", str(stat.st_size))
        self.end_headers()

        with open(filepath, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def do_POST(self):
        if not self.check_auth():
            return

        content_type = self.headers.get("Content-Type", "")
        path = self.path.split("?")[0]

        if path == "/world/upload":
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length > 0:
                body_bytes = self.rfile.read(content_length)
                msg = email.message_from_bytes(
                    b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + body_bytes,
                    policy=default,
                )
                for part in msg.iter_parts():
                    upload_name = part.get_filename()
                    if upload_name:
                        file_data = part.get_payload(decode=True)
                        if file_data:
                            try:
                                import_world_archive(upload_name, file_data)
                            except Exception as e:
                                print(f"[ERROR] Failed to import world: {e}")
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8")
        params = urllib.parse.parse_qs(body)

        if path == "/action":
            action = params.get("action", [""])[0]
            execute_action(action)
        elif path == "/player/add" or path == "/allowlist/add":
            tag = params.get("gamertag", [""])[0].strip()
            xuid = params.get("xuid", [""])[0].strip()
            permission = params.get("permission", ["default"])[0].strip().lower()

            if tag:
                allowlist = read_allowlist()
                existing_entry = next((e for e in allowlist if e.get("name", "").lower() == tag.lower()), None)
                if existing_entry:
                    if xuid and re.match(r"^[0-9]+$", xuid):
                        existing_entry["xuid"] = xuid
                else:
                    new_entry = {"name": tag, "ignoresPlayerLimit": False}
                    if xuid and re.match(r"^[0-9]+$", xuid):
                        new_entry["xuid"] = xuid
                    allowlist.append(new_entry)
                save_allowlist(allowlist)

                if xuid and re.match(r"^[0-9]+$", xuid):
                    set_player_permission_level(xuid, permission)

                execute_action("restart")

        elif path == "/player/set_permission":
            xuid = params.get("xuid", [""])[0].strip()
            gamertag = params.get("gamertag", [""])[0].strip()
            permission = params.get("permission", ["default"])[0].strip().lower()

            if not xuid and gamertag:
                allowlist = read_allowlist()
                for e in allowlist:
                    if e.get("name", "").lower() == gamertag.lower() and e.get("xuid"):
                        xuid = str(e.get("xuid", "")).strip()
                        break

            if xuid and re.match(r"^[0-9]+$", xuid):
                set_player_permission_level(xuid, permission)
                if gamertag:
                    allowlist = read_allowlist()
                    for e in allowlist:
                        if e.get("name", "").lower() == gamertag.lower():
                            e["xuid"] = xuid
                            save_allowlist(allowlist)
                            break
                execute_action("restart")

        elif path == "/player/remove" or path == "/allowlist/remove":
            tag = params.get("gamertag", [""])[0].strip()
            xuid = params.get("xuid", [""])[0].strip()

            if tag or xuid:
                allowlist = read_allowlist()
                if tag:
                    matched = [e for e in allowlist if e.get("name", "").lower() == tag.lower()]
                    for m in matched:
                        if not xuid and m.get("xuid"):
                            xuid = str(m.get("xuid")).strip()
                    allowlist = [e for e in allowlist if e.get("name", "").lower() != tag.lower()]
                if xuid:
                    allowlist = [e for e in allowlist if str(e.get("xuid", "")).strip() != xuid]
                save_allowlist(allowlist)

                if xuid:
                    permissions = read_permissions()
                    permissions = [p for p in permissions if str(p.get("xuid", "")).strip() != xuid]
                    save_permissions(permissions)

                execute_action("restart")

        elif path == "/settings":
            new_props = {}
            for key, spec in VALID_PROPERTIES.items():
                if key in params:
                    val = params[key][0].strip()
                    if isinstance(spec, list) and val in spec:
                        new_props[key] = val
                    elif spec is int and val.isdigit():
                        new_props[key] = val
                    elif spec is str:
                        new_props[key] = re.sub(r'[\r\n]', '', val)
            save_properties(new_props)
            execute_action("restart")

        elif path == "/backup/settings":
            auto_on = params.get("auto_backup_enabled", ["false"])[0].lower() in ["true", "on", "1"]
            raw_interval = params.get("interval_hours", ["6"])[0]
            raw_retention = params.get("retention_days", ["7"])[0]
            raw_max = params.get("max_backups", ["20"])[0]

            interval_val = int(raw_interval) if raw_interval.isdigit() and int(raw_interval) in [1, 3, 6, 12, 24, 168] else 6
            retention_val = max(1, min(365, int(raw_retention))) if raw_retention.isdigit() else 7
            max_val = max(1, min(100, int(raw_max))) if raw_max.isdigit() else 20

            cfg = read_backup_config()
            cfg["auto_backup_enabled"] = auto_on
            cfg["interval_hours"] = interval_val
            cfg["retention_days"] = retention_val
            cfg["max_backups"] = max_val
            save_backup_config(cfg)

        elif path == "/backup/prune":
            cfg = read_backup_config()
            prune_backups(cfg.get("retention_days", 7), cfg.get("max_backups", 20))

        elif path == "/backup/batch_delete":
            file_list = params.get("files", [])
            valid_pattern = re.compile(r"^bedrock_backup_[a-zA-Z0-9_.-]+\.(tar\.gz|zip)$")
            for fname in file_list:
                if valid_pattern.match(fname):
                    fpath = os.path.join(BACKUP_DIR, fname)
                    if os.path.exists(fpath):
                        os.remove(fpath)

        elif path == "/backup/delete_all":
            if os.path.exists(BACKUP_DIR):
                valid_pattern = re.compile(r"^bedrock_backup_[a-zA-Z0-9_.-]+\.(tar\.gz|zip)$")
                for fname in os.listdir(BACKUP_DIR):
                    if valid_pattern.match(fname):
                        fpath = os.path.join(BACKUP_DIR, fname)
                        if os.path.isfile(fpath):
                            os.remove(fpath)

        elif path == "/backup/restore":
            fname = params.get("filename", [""])[0].strip()
            if re.match(r'^bedrock_backup_[a-zA-Z0-9_.-]+\.(tar\.gz|zip)$', fname):
                fpath = os.path.join(BACKUP_DIR, fname)
                if os.path.exists(fpath):
                    execute_action("backup")
                    execute_action("stop")
                    if fname.endswith(".tar.gz"):
                        subprocess.run(["tar", "-xzhf", fpath, "-C", BASE_DIR], timeout=60)
                    subprocess.run(["sudo", "chown", "-R", f"{SERVER_USER}:{SERVER_GROUP}", "/opt/minecraft"], timeout=30)
                    execute_action("start")

        elif path == "/backup/delete":
            fname = params.get("filename", [""])[0].strip()
            if re.match(r'^bedrock_backup_[a-zA-Z0-9_.-]+\.(tar\.gz|zip)$', fname):
                fpath = os.path.join(BACKUP_DIR, fname)
                if os.path.exists(fpath):
                    os.remove(fpath)
        elif path in ("/address/save", "/address/check", "/address/clear"):
            redirect_url = _handle_address_post(path, params)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", redirect_url)
            self.end_headers()
            return

        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.end_headers()


def _handle_address_post(path, params):
    """Handle address save, manual re-check, and clear POST routes safely."""
    if path == "/address/clear":
        save_address_config(DEFAULT_ADDRESS_CONFIG.copy())
        return "/?addr_msg=cleared"

    if path == "/address/save":
        raw_addr = params.get("address", [""])[0]
        parsed_addr, err_code = parse_server_address(raw_addr)
        if err_code:
            return f"/?addr_err={err_code}"
        report = run_connectivity_diagnostics(parsed_addr)
        save_address_config({
            "raw_address": parsed_addr["raw_address"],
            "host": parsed_addr["host"],
            "port_override": parsed_addr["port_override"],
            "address_type": parsed_addr["address_type"],
            "last_checked_utc": report["checked_utc"],
            "last_report": report,
        })
        return "/?addr_msg=saved_checked"

    cfg = read_address_config()
    if not cfg.get("host"):
        return "/?addr_err=no_address"
    parsed_addr, err_code = parse_server_address(cfg.get("raw_address") or cfg.get("host"))
    if err_code:
        return f"/?addr_err={err_code}"
    report = run_connectivity_diagnostics(parsed_addr)
    cfg["last_checked_utc"] = report["checked_utc"]
    cfg["last_report"] = report
    save_address_config(cfg)
    return "/?addr_msg=rechecked"


class ThreadingWebUIServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def run():
    server_address = ("", PORT)
    httpd = ThreadingWebUIServer(server_address, WebUIHandler)
    print(f"[INFO] Minecraft Web UI listening on port {PORT}...")
    httpd.serve_forever()


if __name__ == "__main__":
    run()
