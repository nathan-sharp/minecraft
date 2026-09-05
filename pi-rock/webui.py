#!/usr/bin/env python3
"""
Minecraft Bedrock Dedicated Server - Lightweight Web Administration Interface
Architecture: Pure Python 3 Standard Library (Zero third-party dependencies)
Security: OWASP ASVS compliant, positive input validation, Zip Slip defense, path traversal prevention
"""

import email
import http.server
import io
import json
import os
import re
import shutil
import socketserver
import subprocess
import tarfile
import tempfile
import time
import urllib.parse
import zipfile
from email.policy import default
from http import HTTPStatus

PORT = 8080
BASE_DIR = "/opt/minecraft/bedrock"
BACKUP_DIR = "/opt/minecraft/backups"
PROPERTIES_FILE = os.path.join(BASE_DIR, "server.properties")
ALLOWLIST_FILE = os.path.join(BASE_DIR, "allowlist.json")
BACKUP_CONFIG_FILE = "/opt/minecraft/backup_config.json"
AUTH_FILE = "/opt/minecraft/webui/auth.json"
SERVICE_NAME = "minecraft-bedrock.service"
SERVER_USER = "mcserver"
SERVER_GROUP = "mcserver"

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

    def do_GET(self):
        if not self.check_auth():
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        if path == "/world/download":
            self.handle_live_world_download()
            return
        elif path == "/backup/download":
            self.handle_backup_download(query)
            return

        status = get_service_status()
        props = read_properties()
        allowlist = read_allowlist()
        backups = list_backups()
        stats = get_device_stats()
        backup_cfg = read_backup_config()
        current_level_name = props.get("level-name", "Bedrock level")

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
  .badge {{ display: inline-block; padding: 6px 12px; font-weight: bold; border-radius: 4px; color: #fff; background: {status_color}; }}
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
  .action-group {{ display: flex; gap: 5px; }}
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
</script>
</head>
<body>
<div class="container">
  <h1>Minecraft Bedrock Server Manager</h1>
  
  <div class="card">
    <h2>Server Status: <span class="badge">{status}</span></h2>
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

        html += """
        </tbody>
      </table>
    </form>

    <!-- Hidden standalone action forms -->
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
    <h2>Player Allowlist Access Control</h2>
    <form method="POST" action="/allowlist/add" style="margin-bottom: 15px;">
      <div style="display: flex; gap: 10px;">
        <input type="text" name="gamertag" placeholder="Enter Xbox Gamertag" required style="flex:1;">
        <button class="btn btn-primary" type="submit" style="margin:0;">Add Player</button>
      </div>
    </form>
    <table>
      <thead><tr><th>#</th><th>Authorized Gamertag</th><th>Ignore Limits</th><th>Action</th></tr></thead>
      <tbody>
"""
        if not allowlist:
            html += '<tr><td colspan="4" style="text-align:center;color:#888;">No players on allowlist</td></tr>'
        else:
            for idx, entry in enumerate(allowlist, 1):
                name = entry.get("name", "Unknown")
                ignore = "Yes" if entry.get("ignoresPlayerLimit") else "No"
                html += f"""<tr>
                  <td>{idx}</td>
                  <td><strong>{name}</strong></td>
                  <td>{ignore}</td>
                  <td>
                    <form method="POST" action="/allowlist/remove" style="margin:0;">
                      <input type="hidden" name="gamertag" value="{name}">
                      <button class="btn btn-danger btn-sm" type="submit">Remove</button>
                    </form>
                  </td>
                </tr>"""

        html += """
      </tbody>
    </table>
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
        elif path == "/allowlist/add":
            tag = params.get("gamertag", [""])[0].strip()
            if tag:
                allowlist = read_allowlist()
                if not any(e.get("name", "").lower() == tag.lower() for e in allowlist):
                    allowlist.append({"name": tag, "ignoresPlayerLimit": False})
                    save_allowlist(allowlist)
                    execute_action("restart")
        elif path == "/allowlist/remove":
            tag = params.get("gamertag", [""])[0].strip()
            if tag:
                allowlist = read_allowlist()
                allowlist = [e for e in allowlist if e.get("name", "").lower() != tag.lower()]
                save_allowlist(allowlist)
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

        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", "/")
        self.end_headers()


def run():
    server_address = ("", PORT)
    httpd = socketserver.TCPServer(server_address, WebUIHandler)
    httpd.allow_reuse_address = True
    print(f"[INFO] Minecraft Web UI listening on port {PORT}...")
    httpd.serve_forever()


if __name__ == "__main__":
    run()
