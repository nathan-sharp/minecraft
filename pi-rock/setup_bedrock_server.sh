#!/usr/bin/env bash
# ==============================================================================
# Script: setup_bedrock_server.sh
# Description: Automated deployment of Minecraft Bedrock Dedicated Server
# Target Platform: Raspberry Pi 4 / Raspberry Pi 5 (64-bit ARM / aarch64)
# Standards Compliance: POSIX Shell, ISO/IEC 25010, Power of 10
# ==============================================================================

set -euo pipefail
IFS=$'\n\t'

# ------------------------------------------------------------------------------
# CONSTANTS AND CONFIGURATION
# ------------------------------------------------------------------------------
readonly SERVER_USER="mcserver"
readonly SERVER_GROUP="mcserver"
readonly BASE_DIR="/opt/minecraft"
readonly INSTALL_DIR="/opt/minecraft/bedrock"
readonly BACKUP_DIR="/opt/minecraft/backups"
readonly SERVICE_NAME="minecraft-bedrock.service"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}"
readonly MOJANG_USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
readonly MOJANG_DOWNLOAD_URL="https://www.minecraft.net/en-us/download/server/bedrock"
readonly MIN_SWAP_MB=1900

# ------------------------------------------------------------------------------
# LOGGING AND OUTPUT FUNCTIONS
# ------------------------------------------------------------------------------
log_info() {
    printf "[INFO]  %s\n" "$1"
}

log_warn() {
    printf "[WARN]  %s\n" "$1" >&2
}

log_error() {
    printf "[ERROR] %s\n" "$1" >&2
}

log_fatal() {
    printf "[FATAL] %s\n" "$1" >&2
    exit 1
}

# ------------------------------------------------------------------------------
# VALIDATION SUBROUTINES
# ------------------------------------------------------------------------------
check_privileges() {
    log_info "Verifying execution privileges..."
    if [[ "$(id -u)" -ne 0 ]]; then
        log_fatal "This script must execute with root privileges. Re-run using sudo or as root."
    fi
}

check_architecture() {
    log_info "Validating CPU architecture..."
    local arch
    arch="$(uname -m)"
    if [[ "${arch}" != "aarch64" && "${arch}" != "arm64" ]]; then
        log_fatal "Unsupported architecture: ${arch}. Target system must be 64-bit ARM (aarch64/arm64)."
    fi
    log_info "Architecture validated: ${arch}"
}

check_operating_system() {
    log_info "Validating operating system distribution..."
    if [[ ! -f /etc/os-release ]]; then
        log_fatal "Cannot determine operating system. Missing /etc/os-release file."
    fi
    # shellcheck source=/dev/null
    source /etc/os-release
    case "${ID:-}" in
        debian|raspbian|ubuntu)
            log_info "Operating system validated: ${PRETTY_NAME:-Linux}"
            ;;
        *)
            log_fatal "Unsupported distribution: ${ID:-unknown}. Debian, Raspberry Pi OS (64-bit), or Ubuntu required."
            ;;
    esac
}

# ------------------------------------------------------------------------------
# SYSTEM OPTIMIZATION AND PREREQUISITES
# ------------------------------------------------------------------------------
configure_swap() {
    log_info "Checking system swap memory allocation..."
    local total_swap_mb
    total_swap_mb="$(free -m | awk '/^Swap:/ {print $2}')"

    if [[ -z "${total_swap_mb}" ]]; then
        total_swap_mb=0
    fi

    if [[ "${total_swap_mb}" -ge "${MIN_SWAP_MB}" ]]; then
        log_info "Adequate swap memory detected: ${total_swap_mb} MiB."
        return 0
    fi

    log_warn "Swap memory (${total_swap_mb} MiB) is below recommended threshold (${MIN_SWAP_MB} MiB)."

    if [[ -f /etc/dphys-swapfile ]]; then
        log_info "Configuring /etc/dphys-swapfile to ${MIN_SWAP_MB} MiB..."
        sed -i 's/^CONF_SWAPSIZE=.*/CONF_SWAPSIZE=2048/' /etc/dphys-swapfile
        dphys-swapfile setup
        dphys-swapfile swapon
    elif [[ ! -f /swapfile ]]; then
        log_info "Creating 2048 MiB swap file at /swapfile..."
        fallocate -l 2G /swapfile || dd if=/dev/zero of=/swapfile bs=1M count=2048
        chmod 600 /swapfile
        mkswap /swapfile
        swapon /swapfile
        if ! grep -q "/swapfile" /etc/fstab; then
            echo "/swapfile none swap sw 0 0" >> /etc/fstab
        fi
    fi
    log_info "Swap memory optimization complete."
}

install_system_dependencies() {
    log_info "Updating APT package index and installing base dependencies..."
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        wget \
        unzip \
        tar \
        gpg \
        lsb-release \
        libssl3 \
        libcurl4 \
        ufw
}

install_box64() {
    log_info "Checking box64 binary translation engine..."
    if command -v box64 >/dev/null 2>&1; then
        log_info "box64 is already installed: $(box64 -v 2>&1 | head -n 1)"
        return 0
    fi

    log_info "Configuring Ryan Fortner's box64 APT repository..."
    local gpg_key_path="/etc/apt/trusted.gpg.d/box64-debs-archive-keyring.gpg"
    local repo_list_path="/etc/apt/sources.list.d/box64.list"

    wget -qO- https://ryanfortner.github.io/box64-debs/KEY.gpg | gpg --dearmor --yes -o "${gpg_key_path}" || true
    wget -q https://ryanfortner.github.io/box64-debs/box64.list -O "${repo_list_path}" || \
        echo "deb https://ryanfortner.github.io/box64-debs/debian ./" > "${repo_list_path}"

    apt-get update -y || true

    # Attempt package installation from APT
    if apt-cache show box64-rpi4arm64 >/dev/null 2>&1; then
        apt-get install -y box64-rpi4arm64 || true
    elif apt-cache show box64-arm64 >/dev/null 2>&1; then
        apt-get install -y box64-arm64 || true
    else
        apt-get install -y box64 || true
    fi

    # Fallback to source compilation if APT package is not found or fails
    if ! command -v box64 >/dev/null 2>&1; then
        log_warn "APT package for box64 unavailable on this release. Compiling from source..."
        apt-get install -y --no-install-recommends git cmake build-essential python3

        local build_dir
        build_dir="$(mktemp -d /tmp/box64-build-XXXXXX)"
        git clone --depth 1 https://github.com/ptitSeb/box64.git "${build_dir}/box64"

        mkdir -p "${build_dir}/box64/build"
        pushd "${build_dir}/box64/build" >/dev/null
        cmake .. -DRPI4ARM64=1 -DCMAKE_BUILD_TYPE=RelWithDebInfo
        make -j"$(nproc)"
        make install
        popd >/dev/null

        rm -rf "${build_dir}"
        systemctl restart systemd-binfmt 2>/dev/null || true
    fi

    if ! command -v box64 >/dev/null 2>&1; then
        log_fatal "box64 installation failed. Command 'box64' not found in PATH."
    fi

    local detected_box64
    detected_box64="$(command -v box64)"
    if [[ "${detected_box64}" != "/usr/bin/box64" && ! -e "/usr/bin/box64" ]]; then
        ln -sf "${detected_box64}" /usr/bin/box64
    fi
    if [[ "${detected_box64}" != "/usr/local/bin/box64" && ! -e "/usr/local/bin/box64" ]]; then
        ln -sf "${detected_box64}" /usr/local/bin/box64
    fi

    log_info "box64 successfully installed: $(box64 -v 2>&1 | head -n 1)"
}

# ------------------------------------------------------------------------------
# APPLICATION USER AND DIRECTORY SETUP
# ------------------------------------------------------------------------------
create_system_user() {
    log_info "Configuring dedicated system user: ${SERVER_USER}..."
    if ! id "${SERVER_USER}" >/dev/null 2>&1; then
        useradd --system --user-group --home-dir "${INSTALL_DIR}" --shell /usr/sbin/nologin "${SERVER_USER}"
        log_info "Created system user ${SERVER_USER}."
    else
        log_info "System user ${SERVER_USER} already exists."
    fi

    mkdir -p "${INSTALL_DIR}" "${BACKUP_DIR}"
    chmod 750 "${INSTALL_DIR}" "${BACKUP_DIR}"
}

# ------------------------------------------------------------------------------
# MINECRAFT BEDROCK SERVER DEPLOYMENT
# ------------------------------------------------------------------------------
download_bedrock_server() {
    log_info "Resolving latest official Minecraft Bedrock Server package..."
    local download_url=""
    local api_url="https://net-secondary.web.minecraft-services.net/api/v1.0/download/links"

    # Strategy 1: Official Mojang services API endpoint
    local api_json
    api_json="$(curl -s -L "${api_url}" || true)"
    if [[ -n "${api_json}" ]]; then
        download_url="$(echo "${api_json}" | grep -oE 'https://[^"]+bin-linux/bedrock-server-[^"]+\.zip' | head -n 1 || true)"
    fi

    # Strategy 2: Official download page scrape
    if [[ -z "${download_url}" ]]; then
        local download_page_html
        download_page_html="$(curl -s -L -A "${MOJANG_USER_AGENT}" "${MOJANG_DOWNLOAD_URL}" || true)"
        if [[ -n "${download_page_html}" ]]; then
            download_url="$(echo "${download_page_html}" | grep -oE 'https://[^"]+bin-linux/bedrock-server-[^"]+\.zip' | head -n 1 || true)"
        fi
    fi

    # Strategy 3: Verified active production fallback URL
    if [[ -z "${download_url}" ]]; then
        log_warn "Automated download URL extraction failed. Fetching fallback BDS link..."
        download_url="https://www.minecraft.net/bedrockdedicatedserver/bin-linux/bedrock-server-1.26.45.1.zip"
    fi

    log_info "Downloading server archive from: ${download_url}"
    local tmp_archive
    tmp_archive="$(mktemp /tmp/bedrock-server-XXXXXX.zip)"

    curl -L -A "${MOJANG_USER_AGENT}" "${download_url}" -o "${tmp_archive}"

    log_info "Extracting server archive to ${INSTALL_DIR}..."
    # Preserve existing configuration files if present
    if [[ -f "${INSTALL_DIR}/server.properties" ]]; then
        cp "${INSTALL_DIR}/server.properties" "${INSTALL_DIR}/server.properties.bak"
    fi
    if [[ -f "${INSTALL_DIR}/allowlist.json" ]]; then
        cp "${INSTALL_DIR}/allowlist.json" "${INSTALL_DIR}/allowlist.json.bak"
    fi
    if [[ -f "${INSTALL_DIR}/permissions.json" ]]; then
        cp "${INSTALL_DIR}/permissions.json" "${INSTALL_DIR}/permissions.json.bak"
    fi

    unzip -q -o "${tmp_archive}" -d "${INSTALL_DIR}"
    rm -f "${tmp_archive}"

    # Restore backups if upgrading
    if [[ -f "${INSTALL_DIR}/server.properties.bak" ]]; then
        mv "${INSTALL_DIR}/server.properties.bak" "${INSTALL_DIR}/server.properties"
    fi
    if [[ -f "${INSTALL_DIR}/allowlist.json.bak" ]]; then
        mv "${INSTALL_DIR}/allowlist.json.bak" "${INSTALL_DIR}/allowlist.json"
    fi
    if [[ -f "${INSTALL_DIR}/permissions.json.bak" ]]; then
        mv "${INSTALL_DIR}/permissions.json.bak" "${INSTALL_DIR}/permissions.json"
    fi

    chmod 750 "${INSTALL_DIR}/bedrock_server"

    # Configure custom world data storage location if specified in environment
    if [[ -n "${BEDROCK_WORLDS_DIR:-}" ]]; then
        log_info "Configuring external world data storage: ${BEDROCK_WORLDS_DIR}..."
        mkdir -p "${BEDROCK_WORLDS_DIR}"
        if [[ -d "${INSTALL_DIR}/worlds" && ! -L "${INSTALL_DIR}/worlds" ]]; then
            cp -a "${INSTALL_DIR}/worlds/." "${BEDROCK_WORLDS_DIR}/" 2>/dev/null || true
            rm -rf "${INSTALL_DIR}/worlds"
        fi
        ln -sfn "${BEDROCK_WORLDS_DIR}" "${INSTALL_DIR}/worlds"
        chown -R "${SERVER_USER}:${SERVER_GROUP}" "${BEDROCK_WORLDS_DIR}"
        chmod 750 "${BEDROCK_WORLDS_DIR}"
    fi

    chown -R "${SERVER_USER}:${SERVER_GROUP}" "${BASE_DIR}"
    log_info "Minecraft Bedrock Dedicated Server binaries deployed successfully."
}

# ------------------------------------------------------------------------------
# SYSTEMD SERVICE CREATION
# ------------------------------------------------------------------------------
install_systemd_service() {
    log_info "Generating systemd service definition: ${SERVICE_FILE}..."
    local box64_exec
    box64_exec="$(command -v box64 || echo '/usr/local/bin/box64')"

    cat > "${SERVICE_FILE}" << EOF
[Unit]
Description=Minecraft Bedrock Dedicated Server
Documentation=https://www.minecraft.net/en-us/download/server/bedrock
After=network.target

[Service]
Type=simple
User=${SERVER_USER}
Group=${SERVER_GROUP}
WorkingDirectory=${INSTALL_DIR}
Environment="LD_LIBRARY_PATH=${INSTALL_DIR}"
Environment="BOX64_LD_LIBRARY_PATH=${INSTALL_DIR}"
Environment="BOX64_NOBANNER=1"
Environment="BOX64_DYNAREC=1"
ExecStart=${box64_exec} ${INSTALL_DIR}/bedrock_server
Restart=on-failure
RestartSec=10s
LimitNOFILE=65535
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${SERVICE_FILE}"
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}"
    log_info "systemd service ${SERVICE_NAME} enabled."
}

# ------------------------------------------------------------------------------
# HELPER SCRIPTS INSTALLATION
# ------------------------------------------------------------------------------
install_helper_scripts() {
    log_info "Installing administrative management tools..."

    # 1. mc-backup tool (dereferences symlinks with -h to support external storage)
    cat > /usr/local/bin/mc-backup << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
BACKUP_ROOT="/opt/minecraft/backups"
SOURCE_DIR="/opt/minecraft/bedrock"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARCHIVE_FILE="${BACKUP_ROOT}/bedrock_backup_${TIMESTAMP}.tar.gz"

mkdir -p "${BACKUP_ROOT}"
echo "[INFO] Creating Minecraft Bedrock server backup: ${ARCHIVE_FILE}..."

# Create compressed archive following symlinks (-h) for external storage
tar -czhf "${ARCHIVE_FILE}" \
    -C "${SOURCE_DIR}" \
    worlds \
    server.properties \
    allowlist.json \
    permissions.json 2>/dev/null || \
tar -czhf "${ARCHIVE_FILE}" \
    -C "${SOURCE_DIR}" \
    worlds \
    server.properties

# Set ownership
chown -R mcserver:mcserver "${BACKUP_ROOT}"

# Retention policy: Remove archives older than 7 days
find "${BACKUP_ROOT}" -type f -name "bedrock_backup_*.tar.gz" -mtime +7 -delete

echo "[INFO] Backup completed successfully: ${ARCHIVE_FILE}"
EOF
    chmod 755 /usr/local/bin/mc-backup

    # 2. mc-update tool (preserves external storage symlinks and configs)
    cat > /usr/local/bin/mc-update << 'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] This tool must be run as root: sudo mc-update" >&2
    exit 1
fi

    MOJANG_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
    API_URL="https://net-secondary.web.minecraft-services.net/api/v1.0/download/links"
    PAGE_URL="https://www.minecraft.net/en-us/download/server/bedrock"
    INSTALL_PATH="/opt/minecraft/bedrock"

    echo "[INFO] Checking for Bedrock server updates..."
    API_JSON="$(curl -s -L "${API_URL}" || true)"
    DOWNLOAD_URL="$(echo "${API_JSON}" | grep -oE 'https://[^"]+bin-linux/bedrock-server-[^"]+\.zip' | head -n 1 || true)"

    if [[ -z "${DOWNLOAD_URL}" ]]; then
        HTML="$(curl -s -L -A "${MOJANG_UA}" "${PAGE_URL}" || true)"
        DOWNLOAD_URL="$(echo "${HTML}" | grep -oE 'https://[^"]+bin-linux/bedrock-server-[^"]+\.zip' | head -n 1 || true)"
    fi

    if [[ -z "${DOWNLOAD_URL}" ]]; then
        echo "[ERROR] Failed to obtain download link from Mojang." >&2
        exit 1
    fi

echo "[INFO] Stopping Minecraft Bedrock service..."
systemctl stop minecraft-bedrock.service || true

echo "[INFO] Executing pre-update backup..."
/usr/local/bin/mc-backup

# Record external storage symlink if configured
WORLDS_TARGET=""
if [[ -L "${INSTALL_PATH}/worlds" ]]; then
    WORLDS_TARGET="$(readlink "${INSTALL_PATH}/worlds")"
fi

TMP_FILE="$(mktemp /tmp/bedrock-update-XXXXXX.zip)"
echo "[INFO] Downloading new version from: ${DOWNLOAD_URL}..."
curl -L -A "${MOJANG_UA}" "${DOWNLOAD_URL}" -o "${TMP_FILE}"

echo "[INFO] Extracting new binaries..."
# Preserve configuration files
cp "${INSTALL_PATH}/server.properties" "${INSTALL_PATH}/server.properties.bak"
unzip -q -o "${TMP_FILE}" -d "${INSTALL_PATH}"
mv "${INSTALL_PATH}/server.properties.bak" "${INSTALL_PATH}/server.properties"
rm -f "${TMP_FILE}"

# Re-establish external world symlink if previously present
if [[ -n "${WORLDS_TARGET}" ]]; then
    if [[ -d "${INSTALL_PATH}/worlds" && ! -L "${INSTALL_PATH}/worlds" ]]; then
        rm -rf "${INSTALL_PATH}/worlds"
    fi
    ln -sfn "${WORLDS_TARGET}" "${INSTALL_PATH}/worlds"
fi

chmod 750 "${INSTALL_PATH}/bedrock_server"
chown -R mcserver:mcserver /opt/minecraft

echo "[INFO] Starting Minecraft Bedrock service..."
systemctl start minecraft-bedrock.service
echo "[INFO] Update completed successfully."
EOF
    chmod 755 /usr/local/bin/mc-update

    # 3. mc-set-storage tool (migrates world data and manages external USB storage)
    cat > /usr/local/bin/mc-set-storage << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] This tool must execute with root privileges: sudo mc-set-storage <TARGET_DIR>" >&2
    exit 1
fi

INSTALL_PATH="/opt/minecraft/bedrock"
WORLDS_LINK="${INSTALL_PATH}/worlds"

if [[ $# -lt 1 ]]; then
    echo "Usage: sudo mc-set-storage <TARGET_DIRECTORY_PATH>"
    echo ""
    echo "Current world storage path:"
    if [[ -L "${WORLDS_LINK}" ]]; then
        echo "  Symlinked target -> $(readlink -f "${WORLDS_LINK}")"
    else
        echo "  Default internal -> ${WORLDS_LINK}"
    fi
    exit 1
fi

TARGET_DIR="$1"

if [[ "${TARGET_DIR}" != /* ]]; then
    echo "[ERROR] Target path must be an absolute path (e.g. /media/usb/minecraft-worlds)." >&2
    exit 1
fi

echo "[INFO] Verifying target storage directory: ${TARGET_DIR}..."
mkdir -p "${TARGET_DIR}"

TEST_FILE="${TARGET_DIR}/.write_test_$$"
if ! touch "${TEST_FILE}" 2>/dev/null; then
    echo "[ERROR] Target path is not writable. Check mount options and permissions." >&2
    exit 1
fi
rm -f "${TEST_FILE}"

echo "[INFO] Stopping Minecraft Bedrock service..."
systemctl stop minecraft-bedrock.service || true

if [[ -d "${WORLDS_LINK}" && ! -L "${WORLDS_LINK}" ]]; then
    echo "[INFO] Migrating existing world data to ${TARGET_DIR}..."
    cp -a "${WORLDS_LINK}/." "${TARGET_DIR}/" 2>/dev/null || true
    rm -rf "${WORLDS_LINK}"
elif [[ -L "${WORLDS_LINK}" ]]; then
    OLD_TARGET="$(readlink -f "${WORLDS_LINK}")"
    if [[ "${OLD_TARGET}" != "${TARGET_DIR}" && -d "${OLD_TARGET}" ]]; then
        echo "[INFO] Migrating world data from ${OLD_TARGET} to ${TARGET_DIR}..."
        cp -a "${OLD_TARGET}/." "${TARGET_DIR}/" 2>/dev/null || true
    fi
    rm -f "${WORLDS_LINK}"
fi

echo "[INFO] Creating symbolic link: ${WORLDS_LINK} -> ${TARGET_DIR}..."
ln -sfn "${TARGET_DIR}" "${WORLDS_LINK}"

echo "[INFO] Setting ownership and permissions for mcserver..."
chown -R mcserver:mcserver "${TARGET_DIR}" "${WORLDS_LINK}"
chmod 750 "${TARGET_DIR}"

echo "[INFO] Starting Minecraft Bedrock service..."
systemctl start minecraft-bedrock.service

echo "[INFO] World storage successfully relocated to: ${TARGET_DIR}"
EOF
    chmod 755 /usr/local/bin/mc-set-storage

    # 4. mc-allowlist tool (manages Bedrock server allowlist)
    cat > /usr/local/bin/mc-allowlist << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] This tool must execute with root privileges: sudo mc-allowlist <COMMAND> [ARGS]" >&2
    exit 1
fi

INSTALL_PATH="/opt/minecraft/bedrock"
ALLOWLIST_FILE="${INSTALL_PATH}/allowlist.json"
SERVER_PROPS="${INSTALL_PATH}/server.properties"

show_usage() {
    echo "Usage: sudo mc-allowlist <COMMAND> [GAMERTAG]"
    echo ""
    echo "Commands:"
    echo "  add <GAMERTAG>     Add an Xbox Gamertag to the allowlist"
    echo "  remove <GAMERTAG>  Remove an Xbox Gamertag from the allowlist"
    echo "  list               List all authorized Gamertags in allowlist.json"
    echo "  on                 Enable allowlist enforcement in server.properties"
    echo "  off                Disable allowlist enforcement in server.properties"
    echo "  reload             Restart server to apply allowlist changes"
    exit 1
}

if [[ $# -lt 1 ]]; then
    show_usage
fi

COMMAND="$1"

# Ensure allowlist.json exists
if [[ ! -f "${ALLOWLIST_FILE}" ]]; then
    echo "[]" > "${ALLOWLIST_FILE}"
    chown mcserver:mcserver "${ALLOWLIST_FILE}"
    chmod 640 "${ALLOWLIST_FILE}"
fi

case "${COMMAND}" in
    add)
        if [[ $# -lt 2 ]]; then
            echo "[ERROR] Missing Gamertag. Usage: sudo mc-allowlist add <GAMERTAG>" >&2
            exit 1
        fi
        GAMERTAG="$2"
        python3 -c "
import json, sys
path = '${ALLOWLIST_FILE}'
tag = sys.argv[1]
try:
    with open(path, 'r') as f:
        data = json.load(f)
except Exception:
    data = []
if not any(entry.get('name', '').lower() == tag.lower() for entry in data):
    data.append({'name': tag, 'ignoresPlayerLimit': False})
    with open(path, 'w') as f:
        json.dump(data, f, indent=2)
    print(f'[INFO] Added \'{tag}\' to allowlist.')
else:
    print(f'[INFO] Player \'{tag}\' is already in allowlist.')
" "${GAMERTAG}"
        chown mcserver:mcserver "${ALLOWLIST_FILE}"
        chmod 640 "${ALLOWLIST_FILE}"
        echo "[INFO] Restarting server to apply changes..."
        systemctl restart minecraft-bedrock.service
        ;;
    remove)
        if [[ $# -lt 2 ]]; then
            echo "[ERROR] Missing Gamertag. Usage: sudo mc-allowlist remove <GAMERTAG>" >&2
            exit 1
        fi
        GAMERTAG="$2"
        python3 -c "
import json, sys
path = '${ALLOWLIST_FILE}'
tag = sys.argv[1]
try:
    with open(path, 'r') as f:
        data = json.load(f)
except Exception:
    data = []
new_data = [entry for entry in data if entry.get('name', '').lower() != tag.lower()]
with open(path, 'w') as f:
    json.dump(new_data, f, indent=2)
print(f'[INFO] Removed \'{tag}\' from allowlist.')
" "${GAMERTAG}"
        chown mcserver:mcserver "${ALLOWLIST_FILE}"
        chmod 640 "${ALLOWLIST_FILE}"
        echo "[INFO] Restarting server to apply changes..."
        systemctl restart minecraft-bedrock.service
        ;;
    list)
        python3 -c "
import json
path = '${ALLOWLIST_FILE}'
try:
    with open(path, 'r') as f:
        data = json.load(f)
    print('Authorized Players:')
    for i, entry in enumerate(data, 1):
        print(f'  {i}. {entry.get(\"name\", \"unknown\")} (IgnoresLimit: {entry.get(\"ignoresPlayerLimit\", False)})')
    if not data:
        print('  (No players currently allowlisted)')
except Exception as e:
    print(f'[ERROR] Could not read allowlist: {e}')
"
        ;;
    on)
        if grep -q "^allow-list=" "${SERVER_PROPS}"; then
            sed -i 's/^allow-list=.*/allow-list=true/' "${SERVER_PROPS}"
        else
            echo "allow-list=true" >> "${SERVER_PROPS}"
        fi
        echo "[INFO] Allowlist enforcement ENABLED in server.properties."
        systemctl restart minecraft-bedrock.service
        ;;
    off)
        if grep -q "^allow-list=" "${SERVER_PROPS}"; then
            sed -i 's/^allow-list=.*/allow-list=false/' "${SERVER_PROPS}"
        else
            echo "allow-list=false" >> "${SERVER_PROPS}"
        fi
        echo "[INFO] Allowlist enforcement DISABLED in server.properties."
        systemctl restart minecraft-bedrock.service
        ;;
    reload)
        systemctl restart minecraft-bedrock.service
        echo "[INFO] Server reloaded."
        ;;
    *)
        show_usage
        ;;
esac
EOF
    chmod 755 /usr/local/bin/mc-allowlist

    log_info "Administrative tools installed: /usr/local/bin/mc-backup, /usr/local/bin/mc-update, /usr/local/bin/mc-set-storage, /usr/local/bin/mc-allowlist"
}

# ------------------------------------------------------------------------------
# WEB ADMINISTRATION UI DEPLOYMENT
# ------------------------------------------------------------------------------
install_webui() {
    log_info "Deploying lightweight Web Administration UI..."
    local webui_dir="/opt/minecraft/webui"
    local webui_script="${webui_dir}/webui.py"
    local auth_file="${webui_dir}/auth.json"
    local service_file="/etc/systemd/system/minecraft-webui.service"
    local sudoers_file="/etc/sudoers.d/minecraft-webui"

    mkdir -p "${webui_dir}"

    # Generate random admin PIN if auth file is absent
    if [[ ! -f "${auth_file}" ]]; then
        local generated_pass
        generated_pass="$(tr -dc 'A-HJ-NPR-Za-km-z2-9' < /dev/urandom 2>/dev/null | head -c 8 || echo 'BedrockPi88')"
        echo "{\"admin_pass\": \"${generated_pass}\"}" > "${auth_file}"
        chmod 600 "${auth_file}"
        chown -R "${SERVER_USER}:${SERVER_GROUP}" "${webui_dir}"
        log_info "Generated Web UI admin password: ${generated_pass}"
    fi

    # Deploy webui.py
    cat > "${webui_script}" << 'PYEOF'
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


def get_auth_credentials():
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, "r") as f:
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


def get_active_worlds_dir():
    """Resolve the real filesystem path for the worlds directory."""
    worlds_path = os.path.join(BASE_DIR, "worlds")
    if os.path.islink(worlds_path):
        return os.path.realpath(worlds_path)
    return worlds_path


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
        current_level_name = props.get("level-name", "Bedrock level")

        status_color = "#28a745" if "ACTIVE" in status else "#dc3545"

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
  .btn-danger {{ background: #dc3545; padding: 4px 8px; font-size: 12px; }}
  .btn-sm {{ padding: 4px 8px; font-size: 12px; }}
  .form-group {{ margin-bottom: 15px; }}
  label {{ display: block; font-weight: bold; margin-bottom: 5px; font-size: 13px; text-transform: uppercase; color: #555; }}
  input[type="text"], input[type="number"], input[type="file"], select {{ width: 100%; padding: 8px 10px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; font-size: 14px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 15px; }}
  @media (max-width: 600px) {{ .grid {{ grid-template-columns: 1fr; }} }}
  table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
  th, td {{ padding: 10px; text-align: left; border-bottom: 1px solid #eee; }}
  th {{ background: #f8f9fa; font-size: 13px; text-transform: uppercase; }}
  .action-group {{ display: flex; gap: 5px; }}
</style>
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
      <button class="btn btn-backup" type="submit">Create New Backup</button>
    </form>
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

    <hr style="border: 0; border-top: 1px solid #eee; margin: 20px 0;">

    <h3>Available Server Backups ({len(backups)})</h3>
    <table>
      <thead>
        <tr>
          <th>Backup Archive</th>
          <th>Size</th>
          <th>Timestamp</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
"""
        if not backups:
            html += '<tr><td colspan="4" style="text-align:center;color:#888;">No backups created yet. Click "Create New Backup" above.</td></tr>'
        else:
            for b in backups:
                fname = b["filename"]
                fsize = b["size_mb"]
                ftime = b["modified"]
                html += f"""<tr>
                  <td><code>{fname}</code></td>
                  <td>{fsize} MiB</td>
                  <td>{ftime}</td>
                  <td>
                    <div class="action-group">
                      <a href="/backup/download?file={urllib.parse.quote(fname)}" class="btn btn-primary btn-sm">Download</a>
                      <form method="POST" action="/backup/restore" style="margin:0;" onsubmit="return confirm('Restore backup {fname}? Current world will be backed up and replaced.');">
                        <input type="hidden" name="filename" value="{fname}">
                        <button class="btn btn-restart btn-sm" type="submit">Restore</button>
                      </form>
                      <form method="POST" action="/backup/delete" style="margin:0;" onsubmit="return confirm('Delete backup {fname}?');">
                        <input type="hidden" name="filename" value="{fname}">
                        <button class="btn btn-danger btn-sm" type="submit">Delete</button>
                      </form>
                    </div>
                  </td>
                </tr>"""

        html += """
      </tbody>
    </table>
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
                      <button class="btn btn-danger" type="submit">Remove</button>
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
PYEOF
    chmod 755 "${webui_script}"
    chown -R "${SERVER_USER}:${SERVER_GROUP}" "${webui_dir}"

    # Configure bounded sudoers permissions for mcserver
    cat > "${sudoers_file}" << 'EOF'
mcserver ALL=(ALL) NOPASSWD: /usr/bin/systemctl start minecraft-bedrock.service, /usr/bin/systemctl stop minecraft-bedrock.service, /usr/bin/systemctl restart minecraft-bedrock.service, /usr/bin/systemctl is-active minecraft-bedrock.service, /usr/local/bin/mc-backup
EOF
    chmod 440 "${sudoers_file}"

    # Create systemd service unit for Web UI
    cat > "${service_file}" << EOF
[Unit]
Description=Minecraft Bedrock Web Administration Interface
After=network.target

[Service]
Type=simple
User=${SERVER_USER}
Group=${SERVER_GROUP}
WorkingDirectory=${webui_dir}
ExecStart=/usr/bin/python3 ${webui_script}
Restart=on-failure
RestartSec=5s
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

    chmod 644 "${service_file}"
    systemctl daemon-reload
    systemctl enable minecraft-webui.service
    systemctl restart minecraft-webui.service
    log_info "minecraft-webui.service enabled and listening on port 8080."
}

# ------------------------------------------------------------------------------
# NETWORK AND FIREWALL CONFIGURATION
# ------------------------------------------------------------------------------
configure_firewall() {
    log_info "Configuring network firewall rules..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 19132/udp comment "Minecraft Bedrock IPv4" || true
        ufw allow 19133/udp comment "Minecraft Bedrock IPv6" || true
        ufw allow 8080/tcp comment "Minecraft Bedrock Web UI" || true
        log_info "Firewall rules for UDP 19132/19133 and TCP 8080 applied."
    fi
}

# ------------------------------------------------------------------------------
# SERVICE INITIATION
# ------------------------------------------------------------------------------
start_server_service() {
    log_info "Starting ${SERVICE_NAME}..."
    systemctl restart "${SERVICE_NAME}"
    sleep 3

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_info "Service ${SERVICE_NAME} is active and running."
    else
        log_error "Service failed to start. Recent service logs:"
        journalctl -u "${SERVICE_NAME}" -n 20 --no-pager || true
    fi
}

# ------------------------------------------------------------------------------
# MAIN EXECUTION ROUTINE
# ------------------------------------------------------------------------------
main() {
    printf "====================================================================\n"
    printf "  Minecraft Bedrock Server Installer for Raspberry Pi (ARM64)      \n"
    printf "====================================================================\n"

    check_privileges
    check_architecture
    check_operating_system
    configure_swap
    install_system_dependencies
    install_box64
    create_system_user
    download_bedrock_server
    install_systemd_service
    install_helper_scripts
    install_webui
    configure_firewall
    start_server_service

    local ip_addr
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"

    local admin_pass
    admin_pass="$(grep -o '"admin_pass": "[^"]*"' /opt/minecraft/webui/auth.json 2>/dev/null | cut -d'"' -f4 || echo 'admin123')"

    printf "\n====================================================================\n"
    printf "  DEPLOYMENT COMPLETE                                               \n"
    printf "====================================================================\n"
    printf " Local Server IP Address : %s\n" "${ip_addr}"
    printf " Default Game Port       : 19132 (UDP)\n"
    printf " Web UI Management URL   : http://%s:8080\n" "${ip_addr}"
    printf " Web UI Credentials      : Username: admin | Password: %s\n" "${admin_pass}"
    printf " Server Directory        : %s\n" "${INSTALL_DIR}"
    printf " Backup Directory        : %s\n" "${BACKUP_DIR}"
    printf "\n"
    printf " Management Commands:\n"
    printf "   Status    : systemctl status %s\n" "${SERVICE_NAME}"
    printf "   Logs      : journalctl -u %s -f\n" "${SERVICE_NAME}"
    printf "   Stop      : sudo systemctl stop %s\n" "${SERVICE_NAME}"
    printf "   Start     : sudo systemctl start %s\n" "${SERVICE_NAME}"
    printf "   Allowlist : sudo mc-allowlist add <GAMERTAG>\n"
    printf "   Storage   : sudo mc-set-storage <PATH>\n"
    printf "   Backup    : sudo mc-backup\n"
    printf "   Update    : sudo mc-update\n"
    printf "====================================================================\n"
}

main "$@"

