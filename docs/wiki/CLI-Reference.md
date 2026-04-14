# CLI Reference

```
leetha [FLAGS] [SUBCOMMAND]
```

Invoking `leetha` without arguments drops into an interactive console with guided setup.

---

## Top-Level Flags

**Adapter selection**

| Flag | Purpose |
|------|---------|
| `-i, --interface SPEC` | Attach to a network adapter. Repeatable. Spec format: `name[:type[:label]]` |

**Mode selection**

| Flag | Purpose |
|------|---------|
| `start web` | Open the React web dashboard (replaced the older `initialize` command) |
| `start cli` | Stream live packets to the terminal (replaced the older `initialize` command) |
| `--decode` | Expand full protocol fields in `start cli` output |
| `--filter EXPR` | Limit displayed packets by protocol name or `mac=XX:XX:XX` prefix |
| `--on IFACE` | Restrict display output to a single adapter |
| `--probe` | Run ServiceProbe plugins alongside passive capture. Enables active probing for deeper service enumeration on discovered endpoints |

**Web dashboard tuning**

| Flag | Purpose |
|------|---------|
| `--host ADDR` | Dashboard listen address (default `0.0.0.0`) |
| `--port NUM` | Dashboard listen port (default `443`) |
| `--no-tls` | Disable TLS and serve over plain HTTP |
| `--tls-cert PATH` | Path to a custom TLS certificate file |
| `--tls-key PATH` | Path to a custom TLS private key file |

### Example Invocations

```bash
# React dashboard on the default adapter
leetha start web

# Dashboard bound to a specific adapter and port
leetha start web -i enp3s0 --port 9090

# Live CLI output with verbose decoding
leetha start cli --decode -i wlan0

# Multi-adapter capture with one VPN tunnel
leetha start web -i eth0 -i tun0:vpn:lab

# Protocol-filtered live view
leetha start cli --filter dhcpv4 -i tap0

# MAC-prefix filtered live view
leetha start cli --filter mac=00:1A:2B
```

---

## Subcommands

### `sync` -- Refresh Fingerprint Databases

```bash
leetha sync                        # pull all 12 sources
leetha sync --list                 # display each source with age and record count
leetha sync --source ja4           # update one source only
```

### `probe` -- Interrogate a Single Endpoint

```bash
leetha probe 172.16.0.10:22       # identify the service on port 22
leetha probe 10.10.10.5:8443      # identify HTTPS variant
```

The probe subcommand creates a `ServiceConnection`, invokes the matching `ServiceProbe.identify(conn)`, and prints the resulting `ServiceIdentity`.

### `override` -- Pin Device Attributes Manually

```bash
leetha override show 00:11:22:33:44:55

leetha override set 00:11:22:33:44:55 \
    --device-type firewall \
    --manufacturer Fortinet \
    --os-family FortiOS \
    --os-version "7.4.1"

leetha override clear 00:11:22:33:44:55
```

Overrides are stored in the `Store` and take precedence over all automated verdicts.

### `patterns` -- Manage Custom Fingerprint Patterns

```bash
leetha patterns list

# Match hostnames beginning with "PLC-"
leetha patterns add hostname \
    --pattern "^PLC-.*" \
    --device-type plc \
    --manufacturer "Allen-Bradley" \
    --confidence 90

# Match a DHCP vendor class string
leetha patterns add dhcp_opt60 \
    --key "Cisco AP" \
    --device-type access_point \
    --os-family IOS

# Match a MAC OUI prefix
leetha patterns add mac_prefix \
    --key "DC:A6:32" \
    --device-type sbc \
    --manufacturer "Raspberry Pi"

leetha patterns remove hostname 0

# Bulk export / import
leetha patterns export > custom_rules.json
leetha patterns import < custom_rules.json
```

Custom patterns are loaded by `PatternLoader` alongside the built-in JSON files in `patterns/data/`.

### `validate` -- Check Data Integrity

```bash
leetha validate                    # execute every check
leetha validate --check oui        # verify OUI prefix accuracy
leetha validate --check manufacturer # cross-check vendor names
leetha validate --check stale      # flag outdated sources
leetha validate --verbose          # include per-host breakdown
```

### `interfaces` -- Adapter Management

```bash
leetha interfaces list             # run scan_adapters and print results
leetha interfaces add wlan0        # persist adapter choice
leetha interfaces add tun0:vpn     # persist with classification
leetha interfaces remove wlan0     # drop from saved set
leetha interfaces show wlan0       # details for one adapter
```

---

## Console Commands (Interactive Mode)

After launching `leetha -i <adapter>`, the REPL accepts:

| Input | Shortcut | What It Does |
|-------|----------|--------------|
| `help` | `h` / `?` | Print command listing |
| `devices` | `d` / `dev` | Tabulate discovered hosts from HostRepository |
| `alerts` | `a` | Display active findings and advisories |
| `start web` | `w` | Launch the React dashboard in-process |
| `start cli` | `l` | Switch to live packet streaming |
| `sync` | `s` | Trigger a database refresh |
| `sources` | `src` | Show each source with sync timestamp |
| `status` | `st` | Print adapter state, Store stats, and uptime |
| `clear` | `cls` | Wipe the terminal |
| `exit` | `quit` / `q` | Shut down Leetha |

The console supports readline history and tab completion. Press Ctrl+C to break out of sub-modes.
