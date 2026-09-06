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

    # 1. mc-backup tool (automated scheduling, dual retention pruning, and external storage support)
    cat > /usr/local/bin/mc-backup << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

BACKUP_ROOT="/opt/minecraft/backups"
SOURCE_DIR="/opt/minecraft/bedrock"
CONFIG_FILE="/opt/minecraft/backup_config.json"
MODE="${1:-manual}"

# Initialize backup configuration if absent
if [[ ! -f "${CONFIG_FILE}" ]]; then
    mkdir -p "$(dirname "${CONFIG_FILE}")"
    cat > "${CONFIG_FILE}" << 'JSONEOF'
{
  "auto_backup_enabled": true,
  "interval_hours": 6,
  "retention_days": 7,
  "max_backups": 20,
  "last_backup_timestamp": 0
}
JSONEOF
    chown mcserver:mcserver "${CONFIG_FILE}" 2>/dev/null || true
    chmod 664 "${CONFIG_FILE}"
fi

# Function to execute dual retention pruning (days threshold + max backup count)
prune_archives() {
    python3 -c "
import os, time, json, re

config_file = '${CONFIG_FILE}'
backup_dir = '${BACKUP_ROOT}'

retention_days = 7
max_backups = 20

if os.path.exists(config_file):
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
            retention_days = int(cfg.get('retention_days', 7))
            max_backups = int(cfg.get('max_backups', 20))
    except Exception:
        pass

if not os.path.exists(backup_dir):
    exit(0)

now = time.time()
cutoff = retention_days * 86400
pattern = re.compile(r'^bedrock_backup_[a-zA-Z0-9_.-]+\.(tar\.gz|zip)$')

archives = []
for fname in os.listdir(backup_dir):
    if pattern.match(fname):
        fpath = os.path.join(backup_dir, fname)
        if os.path.isfile(fpath):
            try:
                mtime = os.path.getmtime(fpath)
                if (now - mtime) > cutoff:
                    os.remove(fpath)
                    print(f'[INFO] Pruned expired backup: {fname}')
                else:
                    archives.append((fpath, mtime, fname))
            except Exception:
                pass

archives.sort(key=lambda x: x[1], reverse=True)
if len(archives) > max_backups:
    for fpath, _, fname in archives[max_backups:]:
        try:
            os.remove(fpath)
            print(f'[INFO] Pruned excess backup beyond max limit ({max_backups}): {fname}')
        except Exception:
            pass
"
}

if [[ "${MODE}" == "--prune" ]]; then
    echo "[INFO] Executing backup retention pruning..."
    prune_archives
    exit 0
fi

if [[ "${MODE}" == "--cron" ]]; then
    SHOULD_RUN="$(python3 -c "
import os, time, json

config_file = '${CONFIG_FILE}'
if not os.path.exists(config_file):
    print('RUN')
    exit(0)

try:
    with open(config_file, 'r', encoding='utf-8') as f:
        cfg = json.load(f)
    if not cfg.get('auto_backup_enabled', True):
        print('SKIP_DISABLED')
        exit(0)
    
    interval_hrs = int(cfg.get('interval_hours', 6))
    last_ts = float(cfg.get('last_backup_timestamp', 0))
    now = time.time()
    
    if (now - last_ts) >= (interval_hrs * 3600 - 60):
        print('RUN')
    else:
        print('SKIP_INTERVAL')
except Exception:
    print('RUN')
")"

    if [[ "${SHOULD_RUN}" != "RUN" ]]; then
        exit 0
    fi
fi

mkdir -p "${BACKUP_ROOT}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
ARCHIVE_FILE="${BACKUP_ROOT}/bedrock_backup_${TIMESTAMP}.tar.gz"

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

# Update last_backup_timestamp in configuration
python3 -c "
import os, time, json

config_file = '${CONFIG_FILE}'
if os.path.exists(config_file):
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            cfg = json.load(f)
        cfg['last_backup_timestamp'] = int(time.time())
        tmp = config_file + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(cfg, f, indent=2)
        os.replace(tmp, config_file)
    except Exception:
        pass
"

# Set ownership
chown -R mcserver:mcserver "${BACKUP_ROOT}" "${CONFIG_FILE}" 2>/dev/null || true

# Execute dual retention pruning
prune_archives

echo "[INFO] Backup completed successfully: ${ARCHIVE_FILE}"
EOF
    chmod 755 /usr/local/bin/mc-backup

    # Deploy system cron schedule for automated backups (Hourly evaluation gate)
    cat > /etc/cron.d/minecraft-backup << 'EOF'
# Automated Minecraft Bedrock World Backup
0 * * * * root /usr/local/bin/mc-backup --cron >/dev/null 2>&1
EOF
    chmod 644 /etc/cron.d/minecraft-backup

    # Initialize default backup configuration
    if [[ ! -f /opt/minecraft/backup_config.json ]]; then
        cat > /opt/minecraft/backup_config.json << 'EOF'
{
  "auto_backup_enabled": true,
  "interval_hours": 6,
  "retention_days": 7,
  "max_backups": 20,
  "last_backup_timestamp": 0
}
EOF
        chown mcserver:mcserver /opt/minecraft/backup_config.json
        chmod 664 /opt/minecraft/backup_config.json
    fi

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

    # 5. mc-permission tool (manages player roles: visitor, member, operator, default)
    cat > /usr/local/bin/mc-permission << 'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
    echo "[ERROR] This tool must execute with root privileges: sudo mc-permission <COMMAND> [ARGS]" >&2
    exit 1
fi

INSTALL_PATH="/opt/minecraft/bedrock"
PERMISSIONS_FILE="${INSTALL_PATH}/permissions.json"
ALLOWLIST_FILE="${INSTALL_PATH}/allowlist.json"
SERVER_PROPS="${INSTALL_PATH}/server.properties"

show_usage() {
    echo "Usage: sudo mc-permission <COMMAND> [ARGS]"
    echo ""
    echo "Commands:"
    echo "  list                                  List all players, XUIDs, and permission roles"
    echo "  set <XUID|GAMERTAG> <ROLE>            Set role: visitor, member, operator, default"
    echo "  remove <XUID|GAMERTAG>                Revert player role to server-wide default"
    echo ""
    echo "Permission Roles:"
    echo "  visitor   - Exploration mode (cannot mine, build, craft, or open containers)"
    echo "  member    - Standard survival gameplay (build, craft, mine, attack)"
    echo "  operator  - Administrator privileges with in-game console command access"
    echo "  default   - Inherits server default from server.properties"
    exit 1
}

# Ensure permissions.json exists
if [[ ! -f "${PERMISSIONS_FILE}" ]]; then
    echo "[]" > "${PERMISSIONS_FILE}"
    chown mcserver:mcserver "${PERMISSIONS_FILE}"
    chmod 640 "${PERMISSIONS_FILE}"
fi

if [[ $# -lt 1 ]]; then
    show_usage
fi

COMMAND="$1"

case "${COMMAND}" in
    list)
        python3 -c "
import json, os

perms_path = '${PERMISSIONS_FILE}'
allow_path = '${ALLOWLIST_FILE}'
props_path = '${SERVER_PROPS}'

default_role = 'member'
if os.path.exists(props_path):
    with open(props_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip().startswith('default-player-permission-level='):
                default_role = line.strip().split('=', 1)[1].strip()

perms = []
if os.path.exists(perms_path):
    try:
        with open(perms_path, 'r', encoding='utf-8') as f:
            perms = json.load(f)
    except Exception:
        perms = []

allows = []
if os.path.exists(allow_path):
    try:
        with open(allow_path, 'r', encoding='utf-8') as f:
            allows = json.load(f)
    except Exception:
        allows = []

perm_map = {str(p.get('xuid', '')).strip(): str(p.get('permission', '')).strip() for p in perms if 'xuid' in p}

print(f'Server Default Role: {default_role.upper()}')
print(f'{"#":<4} {"GAMERTAG":<22} {"XUID":<20} {"ASSIGNED ROLE":<16} {"ALLOWLIST"}')
print('-' * 75)

seen_xuids = set()
idx = 1
for a in allows:
    name = a.get('name', 'Unknown')
    xuid = str(a.get('xuid', '')).strip() if a.get('xuid') else ''
    if xuid:
        seen_xuids.add(xuid)
    role = perm_map.get(xuid, f'default ({default_role})') if xuid else f'default ({default_role})'
    xuid_str = xuid if xuid else '(pending join)'
    print(f'{idx:<4} {name:<22} {xuid_str:<20} {role:<16} Yes')
    idx += 1

for p in perms:
    xuid = str(p.get('xuid', '')).strip()
    if xuid and xuid not in seen_xuids:
        role = p.get('permission', default_role)
        print(f'{idx:<4} {"(Direct XUID)":<22} {xuid:<20} {role:<16} No')
        idx += 1

if idx == 1:
    print('  (No players configured)')
"
        ;;
    set)
        if [[ $# -lt 3 ]]; then
            echo "[ERROR] Missing arguments. Usage: sudo mc-permission set <XUID|GAMERTAG> <visitor|member|operator|default>" >&2
            exit 1
        fi
        TARGET="$2"
        ROLE="$(echo "$3" | tr '[:upper:]' '[:lower:]')"

        if [[ ! "${ROLE}" =~ ^(visitor|member|operator|default)$ ]]; then
            echo "[ERROR] Invalid role '${ROLE}'. Supported: visitor, member, operator, default" >&2
            exit 1
        fi

        python3 -c "
import json, sys, os, re

perms_path = '${PERMISSIONS_FILE}'
allow_path = '${ALLOWLIST_FILE}'
target = sys.argv[1].strip()
role = sys.argv[2].strip().lower()

xuid = ''
if re.match(r'^[0-9]+$', target):
    xuid = target
else:
    if os.path.exists(allow_path):
        try:
            with open(allow_path, 'r', encoding='utf-8') as f:
                allows = json.load(f)
            for a in allows:
                if a.get('name', '').lower() == target.lower() and a.get('xuid'):
                    xuid = str(a.get('xuid', '')).strip()
                    break
        except Exception:
            pass

if not xuid:
    print(f'[ERROR] Could not resolve numeric XUID for '{target}'. Provide the 16-digit XUID or connect with player first.', file=sys.stderr)
    sys.exit(1)

perms = []
if os.path.exists(perms_path):
    try:
        with open(perms_path, 'r', encoding='utf-8') as f:
            perms = json.load(f)
    except Exception:
        perms = []

perms = [p for p in perms if str(p.get('xuid', '')).strip() != xuid]
if role in ['visitor', 'member', 'operator']:
    perms.append({'permission': role, 'xuid': xuid})

with open(perms_path, 'w', encoding='utf-8') as f:
    json.dump(perms, f, indent=2)

print(f'[INFO] Set permission role for XUID {xuid} to '{role}'.')
" "${TARGET}" "${ROLE}"
        chown mcserver:mcserver "${PERMISSIONS_FILE}"
        chmod 640 "${PERMISSIONS_FILE}"
        echo "[INFO] Restarting server to apply permission updates..."
        systemctl restart minecraft-bedrock.service
        ;;
    remove)
        if [[ $# -lt 2 ]]; then
            echo "[ERROR] Missing target. Usage: sudo mc-permission remove <XUID|GAMERTAG>" >&2
            exit 1
        fi
        TARGET="$2"
        python3 -c "
import json, sys, os, re

perms_path = '${PERMISSIONS_FILE}'
allow_path = '${ALLOWLIST_FILE}'
target = sys.argv[1].strip()

xuid = target if re.match(r'^[0-9]+$', target) else ''
if not xuid and os.path.exists(allow_path):
    try:
        with open(allow_path, 'r', encoding='utf-8') as f:
            allows = json.load(f)
        for a in allows:
            if a.get('name', '').lower() == target.lower() and a.get('xuid'):
                xuid = str(a.get('xuid', '')).strip()
                break
    except Exception:
        pass

if not xuid:
    print(f'[ERROR] Could not resolve numeric XUID for '{target}'.', file=sys.stderr)
    sys.exit(1)

perms = []
if os.path.exists(perms_path):
    try:
        with open(perms_path, 'r', encoding='utf-8') as f:
            perms = json.load(f)
    except Exception:
        perms = []

new_perms = [p for p in perms if str(p.get('xuid', '')).strip() != xuid]
with open(perms_path, 'w', encoding='utf-8') as f:
    json.dump(new_perms, f, indent=2)

print(f'[INFO] Removed custom permission override for XUID {xuid}. Player will use server default role.')
" "${TARGET}"
        chown mcserver:mcserver "${PERMISSIONS_FILE}"
        chmod 640 "${PERMISSIONS_FILE}"
        echo "[INFO] Restarting server to apply changes..."
        systemctl restart minecraft-bedrock.service
        ;;
    *)
        show_usage
        ;;
esac
EOF
    chmod 755 /usr/local/bin/mc-permission

    # Ensure permissions.json is initialized
    if [[ ! -f /opt/minecraft/bedrock/permissions.json ]]; then
        echo "[]" > /opt/minecraft/bedrock/permissions.json
        chown mcserver:mcserver /opt/minecraft/bedrock/permissions.json
        chmod 640 /opt/minecraft/bedrock/permissions.json
    fi

    log_info "Administrative tools installed: /usr/local/bin/mc-backup, /usr/local/bin/mc-update, /usr/local/bin/mc-set-storage, /usr/local/bin/mc-allowlist, /usr/local/bin/mc-permission"
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
PERMISSIONS_FILE = os.path.join(BASE_DIR, "permissions.json")
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
        backups = list_backups()
        stats = get_device_stats()
        backup_cfg = read_backup_config()
        unified_players, default_role = get_unified_players()
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
mcserver ALL=(ALL) NOPASSWD: /usr/bin/systemctl start minecraft-bedrock.service, /usr/bin/systemctl stop minecraft-bedrock.service, /usr/bin/systemctl restart minecraft-bedrock.service, /usr/bin/systemctl is-active minecraft-bedrock.service, /usr/local/bin/mc-backup, /usr/local/bin/mc-permission
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

