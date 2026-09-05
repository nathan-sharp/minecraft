# Minecraft Bedrock Dedicated Server on Raspberry Pi: Engineering Guide

This document defines the architecture, deployment procedure, and maintenance protocols for hosting a Minecraft Bedrock Dedicated Server (BDS) on 64-bit ARM (aarch64) Raspberry Pi hardware.

---

## 1. System Architecture and Theoretical Foundation

Mojang distributes the official Minecraft Bedrock Dedicated Server exclusively as an `x86_64` ELF (Executable and Linkable Format) binary for Linux. Raspberry Pi hardware utilizes ARMv8-A or ARMv9-A (64-bit ARM / `aarch64`) architecture. Direct execution of `x86_64` machine code on ARM hardware is mathematically impossible without dynamic binary translation.

This implementation utilizes `box64`, a dynamic binary translator and userspace recompiler for Linux `x86_64` applications executing on 64-bit ARM platforms.

```
+-------------------------------------------------------------+
|               Minecraft Bedrock Clients                     |
|           (iOS, Android, Windows 10/11, Xbox)               |
+-------------------------------------------------------------+
                              |
                              | UDP Port 19132 (IPv4)
                              | UDP Port 19133 (IPv6)
                              v
+-------------------------------------------------------------+
|              Raspberry Pi (aarch64 / ARM64)                 |
|                                                             |
|  +-------------------------------------------------------+  |
|  | systemd Process Supervisor                            |  |
|  | (minecraft-bedrock.service, User: mcserver)           |  |
|  +-------------------------------------------------------+  |
|                             |                               |
|  +-------------------------------------------------------+  |
|  | box64 (Dynamic User-Space Binary Translator)          |  |
|  +-------------------------------------------------------+  |
|                             |                               |
|  +-------------------------------------------------------+  |
|  | bedrock_server (Official Mojang x86_64 ELF Binary)    |  |
|  +-------------------------------------------------------+  |
|                             |                               |
|  +-------------------------------------------------------+  |
|  | File System Storage: /opt/minecraft/bedrock           |  |
|  +-------------------------------------------------------+  |
+-------------------------------------------------------------+
```

---

## 2. ISO/IEC 25010 Quality Characteristics Evaluation

| Criterion | Technical Implementation | Operational Outcome |
| :--- | :--- | :--- |
| **Maintainability** | Standard POSIX shell scripts, explicit directory tree (`/opt/minecraft`), separate configuration state. | Streamlined upgrades without modifying world state. |
| **Reliability** | `systemd` daemon management with `Restart=on-failure` and `RestartSec=10s`. 2048 MiB swap protection. | Automatic recovery from process crashes; mitigation of out-of-memory (OOM) termination. |
| **Performance Efficiency** | Direct userspace re-compilation via `box64` without full operating system virtualization overhead. | Stable 20 TPS (Ticks Per Second) under nominal player concurrency (1–8 players). |
| **Security** | Process executes under dedicated system user `mcserver` with `nologin` shell. Access permissions set to `0750`. | Strict isolation prevents privilege escalation to the host operating system. |

---

## 3. Hardware and Software Specifications

### 3.1 Hardware Requirements

| Component | Minimum Specification | Recommended Specification |
| :--- | :--- | :--- |
| **SBC Model** | Raspberry Pi 4 Model B (4 GB RAM) | Raspberry Pi 5 (8 GB RAM) |
| **Processor Architecture** | ARMv8-A (64-bit `aarch64`) | ARMv8.2-A / ARMv9-A (64-bit `aarch64`) |
| **Primary Storage** | 16 GB MicroSD (UHS-I Class 10) | 64 GB USB 3.0 Solid-State Drive (SSD) |
| **Network Interface** | 100 Mbps Ethernet / 2.4 GHz Wi-Fi | 1000 Mbps Full-Duplex Gigabit Ethernet |
| **Cooling** | Passive Heat Sink | Active Cooling Fan / Armor Enclosure |

### 3.2 Operating System Prerequisites

| Component | Specification | Requirement Rationale |
| :--- | :--- | :--- |
| **Operating System** | Raspberry Pi OS 64-bit (Debian 12 Bookworm) or Ubuntu Server 64-bit | 64-bit kernel and userspace required by `box64`. |
| **Swap Space** | 2048 MiB minimum | Prevents memory allocation failure during chunk generation. |
| **Network Protocol** | Static local IPv4 address | Guarantees deterministic router port-forwarding target. |

---

## 4. Supply Chain and Security Warning

> [!WARNING]
> **Dependency and Supply Chain Verification (OWASP LLM Top 10 / ASVS V5)**
>
> This deployment integrates third-party software repositories:
> 1. `box64-debs` maintained by Ryan Fortner (`https://ryanfortner.github.io/box64-debs/`).
> 2. Official Mojang binary download servers (`https://minecraft.azureedge.net/`).
>
> You must independently verify package signatures, repository keys, and network origins before production deployment.

---

## 5. Automated Installation Procedure

### 5.1 Prerequisites and Assumptions
- Hardware platform is booted into a 64-bit Debian/Ubuntu/Raspberry Pi OS environment (`aarch64`).
- Administrative `sudo` or root privileges are available.
- Outbound network connectivity via HTTPS is functional.

### 5.2 Method 1: Single-Command Quick Installation (Recommended)

Execute this single command in your Raspberry Pi terminal session:

```bash
sudo bash -c "$(curl -sSL https://raw.githubusercontent.com/nathan-sharp/minecraft/main/pi-rock/setup_bedrock_server.sh)"
```

> [!NOTE]
> This command downloads the script directly to memory and runs it through `sudo bash`. It requires zero git operations or file permission adjustments.

### 5.3 Method 2: Manual Git Clone and Execution

1. Log into your Raspberry Pi terminal session.
2. Clone the repository to your Raspberry Pi:
   ```bash
   git clone https://github.com/nathan-sharp/minecraft.git
   cd minecraft/pi-rock
   ```
3. Grant executable permissions to the installation script:
   ```bash
   chmod +x setup_bedrock_server.sh
   ```
4. Execute the installation script:
   ```bash
   sudo ./setup_bedrock_server.sh
   ```
5. Verify the completion summary displays active service status.

---

## 6. Network Configuration and Port Forwarding

To allow external players to connect over the Wide Area Network (WAN), configure your gateway router.

### 6.1 Network Port Allocation

| Protocol | Port Number | Direction | Purpose |
| :--- | :--- | :--- | :--- |
| **UDP** | `19132` | Inbound | Minecraft Bedrock IPv4 Client Connections |
| **UDP** | `19133` | Inbound | Minecraft Bedrock IPv6 Client Connections |

### 6.2 Router Port Forwarding Procedure

1. Access your router administration interface using your web browser (typically `http://192.168.1.1` or `http://192.168.0.1`).
2. Navigate to the **Port Forwarding**, **Virtual Server**, or **NAT** configuration section.
3. Create a new Port Forwarding rule.
4. Set the **Service Name** to `MinecraftBedrock`.
5. Set the **Protocol** to `UDP`.
6. Set the **External Port** to `19132`.
7. Set the **Internal Port** to `19132`.
8. Set the **Internal IP Address** to the static IP address of your Raspberry Pi.
9. Save and apply the configuration.

### 6.3 Custom Domain Configuration via Cloudflare DNS

Standard Cloudflare Tunnels (`cloudflared`) do not support inbound User Datagram Protocol (UDP) game traffic for public players. Minecraft Bedrock Edition uses UDP exclusively (port 19132).

To connect a custom domain to your Minecraft server, use **Cloudflare DNS** with an unproxied `A` record combined with standard router port forwarding.

#### Procedure: Configuring Cloudflare DNS

1. Log in to the [Cloudflare Dashboard](https://dash.cloudflare.com/).
2. Select your registered domain name.
3. Navigate to **DNS** -> **Records**.
4. Click **Add record**.
5. Set **Type** to `A`.
6. Set **Name** to `bedrock` (or your preferred subdomain, e.g., `mc`).
7. Set **IPv4 address** to your public WAN IPv4 address.
8. Set **Proxy status** to **DNS only** (Grey Cloud icon).
9. Set **TTL** to `Auto`.
10. Click **Save**.

Players can now join the server by entering `bedrock.yourdomain.com` and port `19132`.

```
+----------------------------------------------------------------+
| Minecraft Bedrock Client                                       |
| Server Address: bedrock.yourdomain.com | Port: 19132           |
+----------------------------------------------------------------+
                               |
                               | 1. DNS Query: Resolves public IP via Cloudflare DNS
                               v
+----------------------------------------------------------------+
| Gateway Router (Public IP)                                     |
| Port Forwarding Rule: UDP 19132 -> 192.168.0.36:19132          |
+----------------------------------------------------------------+
                               |
                               | 2. Direct UDP Packets
                               v
+----------------------------------------------------------------+
| Raspberry Pi (192.168.0.36)                                    |
| Service: minecraft-bedrock.service (UDP 19132)                 |
+----------------------------------------------------------------+
```

### 6.4 Alternative: UDP Tunneling for CGNAT (Playit.gg)

If your Internet Service Provider (ISP) uses Carrier-Grade NAT (CGNAT) and prevents router port forwarding, Cloudflare Tunnel cannot route Bedrock UDP. Use `playit.gg`, which natively tunnels UDP:

1. Install the Playit CLI agent on your Raspberry Pi:
   ```bash
   curl -SsL https://playit-cloud.github.io/ppa/key.gpg | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/playit.gpg >/dev/null
   echo "deb [signed-by=/etc/apt/trusted.gpg.d/playit.gpg] https://playit-cloud.github.io/ppa/data ./" | sudo tee /etc/apt/sources.list.d/playit.list
   sudo apt-get update && sudo apt-get install -y playit
   ```
2. Start the Playit agent:
   ```bash
   sudo playit
   ```
3. Follow the claim URL displayed in the terminal to bind the agent to your account.
4. Add a tunnel configured for **Minecraft Bedrock (UDP)** pointing to local port `19132`.
5. Link your custom domain in the Playit web dashboard using a `CNAME` or `A` record.

### 6.5 Port Forwarding Verification Procedure

> [!WARNING]
> **TCP vs. UDP Port Checking Tool Warning**
>
> Standard web port checking tools (e.g., CanYouSeeMe, YouGetSignal) only test Transmission Control Protocol (TCP). Minecraft Bedrock communicates over User Datagram Protocol (UDP). TCP checkers will report UDP port 19132 as "CLOSED" even when port forwarding operates correctly.

#### Step 1: Verify Local Service Port Binding

Execute this command on your Raspberry Pi to confirm `bedrock_server` listens on UDP port 19132:

```bash
sudo ss -ulnp | grep 19132
```

*Expected Output*: Displays an active UDP socket bound to `0.0.0.0:19132` or `*:19132`.

#### Step 2: Test External Reachability via Bedrock Ping

Use a specialized Minecraft Bedrock protocol scanner that transmits genuine RakNet UDP ping packets:

1. Open a browser and visit [mcsrvstat.us Bedrock Checker](https://mcsrvstat.us/).
2. Enter your public IP address or custom domain (e.g., `bedrock.yourdomain.com:19132`).
3. Click **Get server status**.
4. Verify the scanner returns **Online**, server version (`1.26.45.1`), and player slots.

#### Step 3: Test Direct Connection via Cellular Network

1. Disconnect a mobile smartphone from your local Wi-Fi network.
2. Enable 4G/5G mobile cellular data.
3. Open the Minecraft Bedrock application.
4. Navigate to **Play** -> **Servers** -> **Add Server**.
5. Set **Server Address** to your public IP or custom domain (`bedrock.yourdomain.com`).
6. Set **Port** to `19132`.
7. Join the server and confirm world generation.

---

## 7. Operations and System Management

### 7.1 Service Lifecycle Commands

| Action | Command | Description |
| :--- | :--- | :--- |
| **Check Status** | `sudo systemctl status minecraft-bedrock.service` | Displays current daemon state, uptime, and memory usage. |
| **View Live Logs** | `sudo journalctl -u minecraft-bedrock.service -f` | Streams live game server console output. |
| **Stop Server** | `sudo systemctl stop minecraft-bedrock.service` | Halts the server process gracefully. |
| **Start Server** | `sudo systemctl start minecraft-bedrock.service` | Launches the server process. |
| **Restart Server** | `sudo systemctl restart minecraft-bedrock.service` | Reinitializes the server process. |

### 7.2 Backup and Recovery Procedures

The installer provisions an automated backup utility at `/usr/local/bin/mc-backup` and configures an hourly cron evaluation gate at `/etc/cron.d/minecraft-backup`.

#### 1. Backup Configuration and Schedule
Backup parameters reside in `/opt/minecraft/backup_config.json`:
- `auto_backup_enabled`: Enable or disable automated scheduled execution (`true`/`false`).
- `interval_hours`: Interval between automated backups in hours (`1`, `3`, `6`, `12`, `24`, `168`).
- `retention_days`: Maximum age in days before a backup archive is pruned (default: `7`).
- `max_backups`: Maximum total backup archives to retain on disk (default: `20`).

#### 2. Manual Backup and Prune Commands
- **Trigger Immediate Backup**:
  ```bash
  sudo mc-backup
  ```
  *Creates `/opt/minecraft/backups/bedrock_backup_<TIMESTAMP>.tar.gz` and enforces retention policy.*

- **Execute Retention Pruning Only**:
  ```bash
  sudo mc-backup --prune
  ```
  *Removes archives exceeding configured age or count without creating a new backup.*

- **Automated Cron Execution Gate**:
  ```bash
  sudo mc-backup --cron
  ```
  *Evaluates elapsed time against `interval_hours`. Executes backup only when due.*

#### 3. Restore from Backup
1. Stop the Minecraft service:
   ```bash
   sudo systemctl stop minecraft-bedrock.service
   ```
2. Extract the backup archive to the server directory:
   ```bash
   sudo tar -xzf /opt/minecraft/backups/bedrock_backup_YYYYMMDD_HHMMSS.tar.gz -C /opt/minecraft/bedrock
   ```
3. Set file ownership to `mcserver`:
   ```bash
   sudo chown -R mcserver:mcserver /opt/minecraft
   ```
4. Start the Minecraft service:
   ```bash
   sudo systemctl start minecraft-bedrock.service
   ```

### 7.3 Server Upgrades

The installer provisions an automated upgrade utility at `/usr/local/bin/mc-update`.

1. Execute the update utility:
   ```bash
   sudo mc-update
   ```
2. The utility stops the service, performs a safety backup, downloads new binaries, preserves server configuration files, and restarts the service.

### 7.4 External USB Storage Management

The installer provisions a dedicated utility at `/usr/local/bin/mc-set-storage` to manage world data storage locations.

#### Method A: Relocate Storage to an External USB Drive

1. Insert your USB storage drive into a USB 3.0 port on the Raspberry Pi.
2. Identify the filesystem block device identifier and UUID:
   ```bash
   sudo blkid
   ```
3. Create a permanent mount directory:
   ```bash
   sudo mkdir -p /media/minecraft-usb
   ```
4. Configure persistent auto-mounting in `/etc/fstab` (replace `UUID_VALUE` with your drive UUID):
   ```text
   UUID=UUID_VALUE /media/minecraft-usb ext4 defaults,nofail 0 2
   ```
5. Mount the USB filesystem:
   ```bash
   sudo mount -a
   ```
6. Relocate world data to the USB drive using the storage utility:
   ```bash
   sudo mc-set-storage /media/minecraft-usb/worlds
   ```
7. Verify active storage mapping:
   ```bash
   sudo mc-set-storage
   ```

### 7.5 Allowlist and Access Control Management

The server includes an allowlist to restrict access to approved Xbox Gamertags.

#### Method 1: Using the Automated Helper Tool (`mc-allowlist`)

The installer provisions `/usr/local/bin/mc-allowlist` to manage player access:

1. Enable allowlist enforcement:
   ```bash
   sudo mc-allowlist on
   ```
2. Add an authorized Xbox Gamertag:
   ```bash
   sudo mc-allowlist add "YourGamertag"
   ```
3. View all currently allowlisted players:
   ```bash
   sudo mc-allowlist list
   ```
4. Remove a player from the allowlist:
   ```bash
   sudo mc-allowlist remove "YourGamertag"
   ```
5. Disable allowlist enforcement (allows all players):
   ```bash
   sudo mc-allowlist off
   ```

#### Method 2: Manual JSON Configuration

1. Open `/opt/minecraft/bedrock/allowlist.json` in a text editor:
   ```bash
   sudo nano /opt/minecraft/bedrock/allowlist.json
   ```
2. Add player objects with exact Xbox Gamertags:
   ```json
   [
     {
       "name": "PlayerOneGamertag",
       "ignoresPlayerLimit": false
     },
     {
       "name": "PlayerTwoGamertag",
       "ignoresPlayerLimit": false
     }
   ]
   ```
3. Save the file and restart the server daemon:
   ```bash
   sudo systemctl restart minecraft-bedrock.service
   ```

### 7.6 Web Administration Interface

The toolkit deploys a lightweight, browser-based administration interface running via Python 3 on TCP port 8080.

#### Features:
- **Service Monitoring & Lifecycle**: Real-time daemon status with Start, Stop, Restart, and Backup triggers.
- **Hardware & System Telemetry**:
  - Primary root filesystem storage capacity, consumed space, free space, and utilization percentage.
  - World storage filesystem capacity, consumed space, free space, and mount path (identifies USB storage).
  - RAM memory metrics (total, used, available, and percentage utilized).
  - Linux swap memory metrics (total, used, free, and percentage utilized).
  - System on Chip (SoC) temperature in degrees Celsius (°C).
  - Linux load averages (1-minute, 5-minute, and 15-minute intervals) and total system uptime.
- **Automated Backup & Retention Controls**:
  - Configure automated backup schedules (Every 1h, 3h, 6h, 12h, 24h, 168h).
  - Define retention thresholds in days (e.g. 7 days) and maximum archive counts (e.g. 20 archives).
  - Trigger on-demand retention pruning to remove expired or excess archives.
- **World & Backup Archive Management**:
  - Download the active live world as an `.mcworld` package directly to your computer.
  - Upload existing worlds (`.mcworld`, `.zip`, `.tar.gz`) with automatic pre-import safety backups.
  - Multi-select batch deletion of backup archives with safety confirmation.
  - Individual archive downloads, one-click restoration, and deletion.
  - Dedicated "Delete All Backups" action with confirmation dialog.
- **Configuration Editor**: Modify `server.properties` parameters with visual form controls.
- **Allowlist Controls**: Add or remove authorized Xbox Gamertags.
- **Security**: Protected with HTTP Basic Authentication and positive input validation.

#### Procedure: Accessing the Web UI

1. Open a web browser on any device on your local network.
2. Navigate to:
   ```text
   http://<YOUR_RASPBERRY_PI_IP>:8080
   ```
3. Enter credentials when prompted:
   - **Username**: `admin`
   - **Password**: Found in `/opt/minecraft/webui/auth.json` (printed during setup).
4. Manage worlds, edit configuration, or update allowlists directly from the interface.

---

## 8. Server Configuration Reference

Configuration parameters reside in `/opt/minecraft/bedrock/server.properties`.

| Key | Default Value | Recommended Pi Optimization | Description |
| :--- | :--- | :--- | :--- |
| `server-name` | `Dedicated Server` | `My Raspberry Pi Server` | Display name shown in Bedrock server browser list. |
| `gamemode` | `survival` | `survival` | Default game mode (`survival`, `creative`, `adventure`). |
| `difficulty` | `easy` | `normal` | World difficulty (`peaceful`, `easy`, `normal`, `hard`). |
| `max-players` | `10` | `4` (Pi 4 4GB) / `8` (Pi 5 8GB) | Maximum concurrent connected player slots. |
| `server-port` | `19132` | `19132` | IPv4 listening UDP port. |
| `server-portv6` | `19133` | `19133` | IPv6 listening UDP port. |
| `view-distance` | `32` | `10` | Chunk render distance. Lower values reduce memory and CPU load. |
| `tick-distance` | `4` | `4` | World simulation distance in chunks. |
| `player-idle-timeout`| `30` | `15` | Disconnect inactive players after defined minutes. |
| `max-threads` | `8` | `4` | Maximum worker threads. Set to match physical CPU core count. |

---

## 9. Troubleshooting and Diagnostic Matrix

| Symptom / Error | Root Cause | Corrective Action |
| :--- | :--- | :--- |
| `box64: command not found` | Box64 binary translation package missing. | Re-run Box64 installation step or run `sudo apt-get install -y box64`. |
| `Unsupported architecture: armv7l` | 32-bit operating system installed. | Flash a 64-bit Raspberry Pi OS image (`aarch64`) to the storage drive. |
| Server process terminated by `SIGKILL` | Linux Out-Of-Memory (OOM) killer invoked. | Reduce `view-distance` to `10` in `server.properties` and verify 2048 MiB swap space. |
| USB drive fails to mount at boot | Missing `nofail` flag in `/etc/fstab`. | Append `,nofail` to the mount options in `/etc/fstab`. |
| LAN players cannot discover server | UDP broadcast blocked by local firewall. | Execute `sudo ufw allow 19132/udp` and ensure client is on identical subnet. |
| External players cannot connect | Missing or misdirected NAT router port forwarding. | Verify public IP and ensure UDP port `19132` points to static Raspberry Pi internal IP. |

