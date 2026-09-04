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
    local download_page_html
    local download_url=""

    download_page_html="$(curl -s -L -A "${MOJANG_USER_AGENT}" "${MOJANG_DOWNLOAD_URL}" || true)"
    if [[ -n "${download_page_html}" ]]; then
        download_url="$(echo "${download_page_html}" | grep -oE 'https://[^"]+bin-linux/bedrock-server-[^"]+\.zip' | head -n 1 || true)"
    fi

    if [[ -z "${download_url}" ]]; then
        log_warn "Automated download URL extraction failed. Fetching fallback BDS link..."
        # Static verified fallback URL format
        download_url="https://minecraft.azureedge.net/bin-linux/bedrock-server-1.21.2.02.zip"
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
Environment="BOX64_NOBANNER=1"
Environment="BOX64_DYNAREC=1"
ExecStart=/usr/bin/box64 ${INSTALL_DIR}/bedrock_server
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
PAGE_URL="https://www.minecraft.net/en-us/download/server/bedrock"
INSTALL_PATH="/opt/minecraft/bedrock"

echo "[INFO] Checking for Bedrock server updates..."
HTML="$(curl -s -L -A "${MOJANG_UA}" "${PAGE_URL}" || true)"
DOWNLOAD_URL="$(echo "${HTML}" | grep -oE 'https://[^"]+bin-linux/bedrock-server-[^"]+\.zip' | head -n 1 || true)"

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

    log_info "Administrative tools installed: /usr/local/bin/mc-backup, /usr/local/bin/mc-update, /usr/local/bin/mc-set-storage"
}

# ------------------------------------------------------------------------------
# NETWORK AND FIREWALL CONFIGURATION
# ------------------------------------------------------------------------------
configure_firewall() {
    log_info "Configuring network firewall rules..."
    if command -v ufw >/dev/null 2>&1; then
        ufw allow 19132/udp comment "Minecraft Bedrock IPv4" || true
        ufw allow 19133/udp comment "Minecraft Bedrock IPv6" || true
        log_info "Firewall rules for UDP ports 19132 and 19133 applied."
    fi
}

# ------------------------------------------------------------------------------
# SERVICE INITIATION
# ------------------------------------------------------------------------------
start_server_service() {
    log_info "Starting ${SERVICE_NAME}..."
    systemctl start "${SERVICE_NAME}"
    sleep 3

    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        log_info "Service ${SERVICE_NAME} is active and running."
    else
        log_error "Service failed to start. Inspect logs using: journalctl -u ${SERVICE_NAME} -e"
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
    configure_firewall
    start_server_service

    local ip_addr
    ip_addr="$(hostname -I 2>/dev/null | awk '{print $1}' || echo '127.0.0.1')"

    printf "\n====================================================================\n"
    printf "  DEPLOYMENT COMPLETE                                               \n"
    printf "====================================================================\n"
    printf " Local Server IP Address : %s\n" "${ip_addr}"
    printf " Default Game Port       : 19132 (UDP)\n"
    printf " Server Directory        : %s\n" "${INSTALL_DIR}"
    printf " Backup Directory        : %s\n" "${BACKUP_DIR}"
    printf "\n"
    printf " Management Commands:\n"
    printf "   Status  : systemctl status %s\n" "${SERVICE_NAME}"
    printf "   Logs    : journalctl -u %s -f\n" "${SERVICE_NAME}"
    printf "   Stop    : sudo systemctl stop %s\n" "${SERVICE_NAME}"
    printf "   Start   : sudo systemctl start %s\n" "${SERVICE_NAME}"
    printf "   Storage : sudo mc-set-storage <PATH>\n"
    printf "   Backup  : sudo mc-backup\n"
    printf "   Update  : sudo mc-update\n"
    printf "====================================================================\n"
}

main "$@"

