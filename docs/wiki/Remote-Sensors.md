# Remote Sensors

Remote sensors extend leetha's visibility to network segments it can't capture on directly. A sensor is a lightweight binary that runs on a remote device, captures raw packets, and streams them back to leetha over an encrypted WebSocket connection. Packets from remote sensors flow through the same fingerprinting pipeline as local capture -- same parsers, same processors, same verdict engine.

---

## How It Works

```
Remote Device                          Leetha Server
+-------------------+                  +-------------------+
| leetha-sensor     |   WSS (mTLS)     | Sensor Listener   |
|                   | ===============> | (:8443)           |
| - pcap capture    |   binary frames  |                   |
| - per-interface   |   + heartbeats   | -> _classify()    |
|   threads         |   + discovery    | -> packet_queue   |
| - heartbeat 30s   |                  | -> pipeline       |
+-------------------+  <============== | -> store / UI     |
                        control msgs    +-------------------+
                        (capture_start,
                         capture_stop)
```

1. **Sensor connects** to leetha over WebSocket with mutual TLS (mTLS). Both sides authenticate using certificates signed by leetha's internal CA.
2. **Discovery** -- the sensor reports all available network interfaces with IP addresses and link state.
3. **Idle by default** -- the sensor starts idle and waits for the user to select interfaces from the dashboard.
4. **Capture start** -- the user selects interfaces in the UI; the server sends a `capture_start` command. The sensor spawns one capture thread per interface.
5. **Packet streaming** -- captured frames are serialized (16-byte header + raw L2 frame) and sent as WebSocket binary messages.
6. **Heartbeat** -- every 30 seconds, the sensor sends per-interface packet and byte counts. If the server doesn't hear from a sensor for 90 seconds, it emits a `sensor_disconnect` finding.
7. **Reconnect** -- if the connection drops, the sensor reconnects with exponential backoff. The server re-sends the previously saved interface selection so capture resumes automatically.

---

## Prerequisites

### For building sensors (on the leetha server)

- **Rust toolchain** -- `rustc` and `cargo`. Install via [rustup](https://rustup.rs):
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  ```

- **For cross-compilation** (ARM64, ARM, MIPS targets):
  - **cross** -- `cargo install cross`
  - **Docker** -- required by `cross` for containerized toolchains. [Install Docker](https://docs.docker.com/engine/install/)

### For running sensors (on the remote device)

- Linux with raw socket access (root, sudo, or `CAP_NET_RAW`)
- Network connectivity to the leetha server on port 8443

---

## Building a Sensor

### From the Web Dashboard

1. Navigate to **Adapters > Remote Sensors** tab
2. Click **Build Sensor**
3. Fill in the build form:
   - **Sensor Name** -- a unique identifier (e.g., `dmz-sensor`, `iot-vlan`)
   - **Server Address** -- the IP and port the sensor will connect back to (auto-populated from the server's interfaces)
   - **Target Platform** -- select the architecture matching the remote device:
     - **Linux x86_64** -- standard servers, VMs, desktops
     - **Linux ARM64** -- Ubiquiti Dream Machine Pro/SE, Raspberry Pi 4/5, modern ARM servers
     - **Linux ARM (32-bit)** -- Raspberry Pi 2/3, older ARM devices
     - **Linux MIPS** -- embedded devices, some routers
     - **Windows x86_64** -- Windows servers
   - **Buffer (MB)** -- ring buffer size for offline packet storage during connection loss (default: 100 MB)
4. Click **Build** -- the build log streams in real-time
5. **Download** the binary when the build completes

### From the CLI

```bash
leetha remote ca init              # initialize the certificate authority (first time only)
leetha remote ca issue my-sensor   # issue a certificate for the sensor
```

Then compile the sensor manually:
```bash
cd sensor/
cargo build --release --target x86_64-unknown-linux-musl
```

---

## Deploying a Sensor

### Generic Linux

```bash
scp leetha-sensor user@remote-host:/opt/leetha/
ssh user@remote-host
chmod +x /opt/leetha/leetha-sensor
sudo /opt/leetha/leetha-sensor -v
```

The sensor connects to the server, reports its interfaces, and waits for capture instructions.

### Ubiquiti Dream Machine Pro / SE

The UDM Pro runs ARM64 Linux with SSH access:

```bash
# Build for ARM64 in the dashboard, then:
scp leetha-sensor root@<udm-ip>:/data/leetha-sensor
ssh root@<udm-ip>
chmod +x /data/leetha-sensor
/data/leetha-sensor -v -i br0
```

- `/data/` persists across firmware updates
- `br0` is the main LAN bridge -- sees all inter-VLAN and broadcast traffic

To run on boot, create `/data/on_boot.d/10-leetha-sensor.sh`:
```bash
#!/bin/sh
nohup /data/leetha-sensor -i br0 -d &
```

### Ubiquiti Switches

Switches don't support running binaries directly. Use **port mirroring** instead:

1. In the UniFi controller: **Settings > Traffic Management > Mirror**
2. Set the mirror source to the target port or VLAN
3. Set the mirror destination to a port connected to a sensor host
4. Run the sensor on that host, capturing on the mirrored interface

### Raspberry Pi

Build for **Linux ARM64** (Pi 4/5) or **Linux ARM** (Pi 2/3):

```bash
scp leetha-sensor pi@raspberrypi:/home/pi/
ssh pi@raspberrypi
chmod +x leetha-sensor
sudo ./leetha-sensor -v
```

### Proxmox Host

Deploy directly on the Proxmox host to capture on virtual bridges (`vmbr0`, `vmbr1`):

```bash
scp leetha-sensor root@proxmox:/opt/leetha-sensor
ssh root@proxmox
chmod +x /opt/leetha-sensor
/opt/leetha-sensor -v -i vmbr0
```

This gives visibility into LXC container and VM traffic that stays on the bridge.

---

## Managing Sensors

### Selecting Interfaces

Once a sensor connects and appears in the **Remote Sensors** tab:

1. Each discovered interface is listed with its name, IP addresses, and UP/DOWN status
2. Toggle the switch next to each interface you want to capture on
3. Click **Start Capture**
4. The sensor starts capturing and reports per-interface packet counts via heartbeat

Interface selections are persisted -- if the sensor reconnects, capture resumes automatically on the previously selected interfaces.

### Stopping Capture

Click **Stop Capture** in the sensor card. The sensor stops all capture threads and returns to idle.

### Disconnecting

Click **Disconnect** to forcibly close the sensor connection. The sensor will attempt to reconnect.

---

## Sensor CLI Reference

```
leetha-sensor [OPTIONS]

Options:
  -s, --server <IP:PORT>    Override embedded server address
  -i, --interface <NAME>    Override interface (bypasses server control, captures immediately)
  -d, --daemon              Run as background daemon (Linux only)
  -v, --verbose             Increase verbosity (-v for info, -vv for debug)
  -V, --version             Show version and embedded config
  -h, --help                Show help
```

### Examples

```bash
# Default: connect to server, wait for interface selection
sudo ./leetha-sensor -v

# Override interface (legacy mode, captures immediately)
sudo ./leetha-sensor -v -i eth0

# Override server address
sudo ./leetha-sensor -v -s 10.0.0.5:8443

# Run as daemon
sudo ./leetha-sensor -d
```

When using `-i`, the sensor starts capturing immediately without waiting for server instructions. This is useful for quick testing or when you want a specific interface without using the dashboard.

---

## Security

### Mutual TLS (mTLS)

All sensor connections use mutual TLS:

- **Server certificate** -- auto-generated and signed by leetha's internal CA. Includes all server IP addresses in the SAN.
- **Client certificate** -- issued per sensor during the build process. Embedded in the binary at compile time.
- **CA verification** -- the sensor verifies the server's certificate against the embedded CA, and the server verifies the sensor's certificate. Unknown or revoked certificates are rejected.

### Certificate Revocation

When rebuilding a sensor with the same name, the old certificate is automatically revoked. A sensor with a revoked certificate cannot connect.

---

## Troubleshooting

### Sensor can't connect

- Verify the server address is correct: `./leetha-sensor -V` to see embedded config
- Check that port 8443 is reachable: `nc -zv <server-ip> 8443`
- Ensure leetha is running with the sensor listener active (check logs for "sensor listener started")

### TLS handshake fails

- If the server's IP changed, delete the old server cert and restart leetha:
  ```bash
  rm ~/.leetha/ca/server.crt ~/.leetha/ca/server.key
  ```
  The server cert regenerates automatically with current IP addresses.

### Sensor connects but no packets appear

- Ensure the process thread is running (check leetha logs for "Process thread initialized")
- Verify you've selected interfaces and clicked **Start Capture** in the dashboard
- Check the sensor's heartbeat in the UI for per-interface packet counts
- If using the `any` interface, note that promiscuous mode is not supported -- use a specific interface for full visibility

### Sensor disconnects repeatedly

- Check for certificate revocation: rebuild the sensor if the cert was revoked
- Check the heartbeat interval -- the server expects a heartbeat every 90 seconds
- Ensure the network path between sensor and server is stable

### Cross-compilation fails

- Ensure Docker is running: `docker info`
- Ensure `cross` is installed: `cargo install cross`
- For ARM64: the first build may take longer as Docker pulls the cross-compilation image

---

## Alerts

Leetha generates findings for sensor lifecycle events:

| Finding | Severity | When |
|---------|----------|------|
| `sensor_connect` | INFO | A remote sensor establishes a connection |
| `sensor_disconnect` | WARNING | A sensor disconnects or fails to send a heartbeat within 90 seconds |

These findings appear in the **Detections** page and trigger notifications if configured.
