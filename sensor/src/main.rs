mod buffer;
mod embedded;
mod protocol;

use buffer::RingBuffer;
use protocol::serialize_frame;

use clap::Parser;
use log::{debug, error, info, warn, LevelFilter};
use pcap::Capture;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc;

#[derive(Parser, Debug)]
#[command(
    name = "leetha-sensor",
    about = "Remote packet capture sensor for leetha",
    long_about = "Captures raw network packets and streams them to a central leetha instance \
                  over WebSocket/TLS.\n\n\
                  Config and certificates are embedded at build time. Use CLI flags to override \
                  the server address or capture interface.\n\n\
                  Examples:\n  \
                  leetha-sensor                        Run with embedded config\n  \
                  leetha-sensor -v                     Verbose output\n  \
                  leetha-sensor -s 10.0.0.5:9443       Override server\n  \
                  leetha-sensor -i wlan0 -vv           Override interface, extra verbose\n  \
                  leetha-sensor -d                     Run as daemon (Linux only)"
)]
struct Args {
    /// Override embedded server address (IP:PORT)
    #[arg(short, long)]
    server: Option<String>,

    /// Override embedded capture interface (disables server-controlled selection)
    #[arg(short, long)]
    interface: Option<String>,

    /// Run as background daemon (Linux only)
    #[arg(short, long)]
    daemon: bool,

    /// Increase verbosity (-v, -vv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Show version and embedded config
    #[arg(short = 'V', long)]
    version: bool,
}

fn effective_server(args: &Args) -> String {
    args.server
        .clone()
        .unwrap_or_else(|| embedded::SERVER_ADDR.to_string())
}

fn print_version_info(args: &Args) {
    let server = effective_server(args);
    eprintln!("leetha-sensor v{}", env!("CARGO_PKG_VERSION"));
    eprintln!("  Sensor name:  {}", embedded::SENSOR_NAME);
    eprintln!("  Server:       {}", server);
    if let Some(ref iface) = args.interface {
        eprintln!("  Interface:    {} (CLI override)", iface);
    } else {
        eprintln!("  Interface:    server-controlled (idle until selected)");
    }
    eprintln!("  Buffer:       {} MB", embedded::BUFFER_SIZE_MB);
}

// --- Control messages ---

#[derive(Deserialize, Debug)]
#[serde(tag = "type")]
enum ControlMessage {
    #[serde(rename = "capture_start")]
    CaptureStart { interfaces: Vec<String> },
    #[serde(rename = "capture_stop")]
    CaptureStop,
}

#[derive(Serialize)]
struct DiscoveryInterface {
    name: String,
    desc: String,
    addrs: Vec<String>,
    up: bool,
}

#[derive(Serialize)]
struct DiscoveryMessage {
    #[serde(rename = "type")]
    msg_type: String,
    sensor: String,
    interfaces: Vec<DiscoveryInterface>,
}

#[derive(Serialize)]
struct HeartbeatMessage {
    #[serde(rename = "type")]
    msg_type: String,
    sensor: String,
    stats: HashMap<String, InterfaceStats>,
}

#[derive(Serialize, Clone, Default)]
struct InterfaceStats {
    packets: u64,
    bytes: u64,
}

#[derive(Serialize)]
struct CaptureStatusMessage {
    #[serde(rename = "type")]
    msg_type: String,
    interfaces: Vec<String>,
    state: String,
}

#[derive(Serialize)]
struct CaptureErrorMessage {
    #[serde(rename = "type")]
    msg_type: String,
    interface: String,
    error: String,
}

// --- Capture thread handle ---

struct CaptureHandle {
    stop_flag: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
    packets: Arc<AtomicU64>,
    bytes: Arc<AtomicU64>,
}

fn spawn_capture_thread(
    iface: &str,
    tx: mpsc::Sender<Vec<u8>>,
    verbose: u8,
) -> Result<CaptureHandle, String> {
    let stop_flag = Arc::new(AtomicBool::new(false));
    let packets = Arc::new(AtomicU64::new(0));
    let bytes_count = Arc::new(AtomicU64::new(0));

    let iface_name = iface.to_string();
    let flag = stop_flag.clone();
    let pkts = packets.clone();
    let byts = bytes_count.clone();

    let cap_device = Capture::from_device(iface_name.as_str())
        .map_err(|e| format!("{}", e))?;

    let use_promisc = iface_name != "any";
    let mut cap = cap_device
        .promisc(use_promisc)
        .snaplen(65535)
        .timeout(1000)
        .open()
        .map_err(|e| format!("{}", e))?;

    let thread = std::thread::spawn(move || {
        if use_promisc {
            info!("capture started on {} (promiscuous)", iface_name);
        } else {
            info!("capture started on {} (non-promiscuous)", iface_name);
        }

        loop {
            if flag.load(Ordering::Relaxed) {
                info!("capture stopped on {}", iface_name);
                break;
            }
            match cap.next_packet() {
                Ok(packet) => {
                    let ts_ns = packet.header.ts.tv_sec as i64 * 1_000_000_000
                        + packet.header.ts.tv_usec as i64 * 1_000;
                    let frame = serialize_frame(packet.data, ts_ns, 0);
                    pkts.fetch_add(1, Ordering::Relaxed);
                    byts.fetch_add(packet.data.len() as u64, Ordering::Relaxed);

                    if verbose >= 2 {
                        debug!("[{}] packet: {} bytes", iface_name, packet.data.len());
                    }

                    if tx.blocking_send(frame).is_err() {
                        warn!("[{}] channel full, dropping packet", iface_name);
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    error!("capture error on {}: {}", iface_name, e);
                    break;
                }
            }
        }
    });

    Ok(CaptureHandle {
        stop_flag,
        thread: Some(thread),
        packets,
        bytes: bytes_count,
    })
}

fn stop_captures(handles: &mut HashMap<String, CaptureHandle>) {
    for (name, handle) in handles.iter() {
        info!("stopping capture on {}", name);
        handle.stop_flag.store(true, Ordering::Relaxed);
    }
    for (_, handle) in handles.iter_mut() {
        if let Some(t) = handle.thread.take() {
            let _ = t.join();
        }
    }
    handles.clear();
}

fn get_discovery_interfaces() -> Vec<DiscoveryInterface> {
    pcap::Device::list()
        .map(|devs| {
            devs.into_iter()
                .filter(|d| d.name != "lo" && d.name != "any")
                .map(|d| {
                    let addrs: Vec<String> = d
                        .addresses
                        .iter()
                        .filter_map(|a| {
                            if let std::net::IpAddr::V4(v4) = a.addr {
                                Some(v4.to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    let up = !addrs.is_empty();
                    DiscoveryInterface {
                        name: d.name,
                        desc: d.desc.unwrap_or_default(),
                        addrs,
                        up,
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let level = match args.verbose {
        0 => LevelFilter::Error,
        1 => LevelFilter::Info,
        _ => LevelFilter::Debug,
    };
    env_logger::Builder::new()
        .filter_level(level)
        .format_timestamp_secs()
        .init();

    if args.version {
        print_version_info(&args);
        return Ok(());
    }

    let server = effective_server(&args);
    print_version_info(&args);

    #[cfg(unix)]
    if args.daemon {
        use daemonize::Daemonize;
        let daemonize = Daemonize::new().working_directory("/tmp");
        match daemonize.start() {
            Ok(_) => info!("daemonized successfully"),
            Err(e) => {
                error!("failed to daemonize: {}", e);
                std::process::exit(1);
            }
        }
    }

    #[cfg(not(unix))]
    if args.daemon {
        error!("daemon mode is not supported on Windows — use sc.exe or NSSM");
        std::process::exit(1);
    }

    // If -i flag is set, run in legacy mode (immediate capture, no server control)
    if let Some(ref iface) = args.interface {
        return run_legacy_mode(&server, iface, args.verbose).await;
    }

    // Server-controlled mode: connect idle, wait for commands
    run_controlled_mode(&server, args.verbose).await
}

/// Legacy mode: capture immediately on a specific interface (for -i flag)
async fn run_legacy_mode(
    server: &str,
    iface: &str,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(10_000);
    let ring = Arc::new(Mutex::new(RingBuffer::new(
        embedded::BUFFER_SIZE_MB * 1024 * 1024,
    )));

    let iface_name = iface.to_string();
    let tx_clone = tx.clone();
    std::thread::spawn(move || {
        let cap_device = match Capture::from_device(iface_name.as_str()) {
            Ok(c) => c,
            Err(e) => {
                error!("capture interface '{}' not found: {}", iface_name, e);
                std::process::exit(1);
            }
        };
        let use_promisc = iface_name != "any";
        let mut cap = match cap_device.promisc(use_promisc).snaplen(65535).timeout(1000).open() {
            Ok(c) => c,
            Err(e) => {
                error!("cannot open {}: {}", iface_name, e);
                std::process::exit(1);
            }
        };
        info!("capture started on {}", iface_name);
        loop {
            match cap.next_packet() {
                Ok(packet) => {
                    let ts_ns = packet.header.ts.tv_sec as i64 * 1_000_000_000
                        + packet.header.ts.tv_usec as i64 * 1_000;
                    let frame = serialize_frame(packet.data, ts_ns, 0);
                    if tx_clone.blocking_send(frame).is_err() {
                        warn!("channel full, dropping");
                    }
                }
                Err(pcap::Error::TimeoutExpired) => continue,
                Err(e) => {
                    error!("capture error: {}", e);
                    break;
                }
            }
        }
    });
    drop(tx);

    let ring_ws = ring.clone();
    let mut backoff_secs = 1u64;
    loop {
        info!("connecting to {}...", server);
        match connect_legacy(server, &mut rx, &ring_ws, verbose).await {
            Ok(()) => {
                info!("connection closed normally");
                break;
            }
            Err(e) => {
                error!("cannot reach {} — retrying in {}s ({})", server, backoff_secs, e);
                while let Ok(frame) = rx.try_recv() {
                    ring_ws.lock().unwrap().push(frame);
                }
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }
    Ok(())
}

/// Server-controlled mode: connect idle, wait for capture_start/capture_stop
async fn run_controlled_mode(
    server: &str,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut backoff_secs = 1u64;

    loop {
        info!("connecting to {}...", server);
        match connect_controlled(server, verbose).await {
            Ok(()) => {
                info!("connection closed normally, reconnecting...");
                backoff_secs = 1;
            }
            Err(e) => {
                error!("cannot reach {} — retrying in {}s ({})", server, backoff_secs, e);
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }
}

async fn connect_controlled(
    server: &str,
    verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let (mut write, mut read) = establish_ws(server).await?;

    info!("TLS handshake complete, cert: {}", embedded::SENSOR_NAME);

    // Send enhanced discovery
    let discovery = DiscoveryMessage {
        msg_type: "discovery".into(),
        sensor: embedded::SENSOR_NAME.into(),
        interfaces: get_discovery_interfaces(),
    };
    write
        .send(Message::Text(serde_json::to_string(&discovery)?.into()))
        .await?;
    info!("reported {} interfaces to central", discovery.interfaces.len());

    // Shared state for capture threads
    let (pkt_tx, mut pkt_rx) = mpsc::channel::<Vec<u8>>(10_000);
    let captures: Arc<Mutex<HashMap<String, CaptureHandle>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Channel for control messages from the read task
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<ControlMessage>(16);

    // Read task: handle control messages from server
    let mut read_task = tokio::spawn(async move {
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Text(text)) => {
                    match serde_json::from_str::<ControlMessage>(&text) {
                        Ok(ctrl) => {
                            if ctrl_tx.send(ctrl).await.is_err() {
                                break;
                            }
                        }
                        Err(e) => debug!("unknown control message: {}", e),
                    }
                }
                Ok(Message::Close(_)) => break,
                Err(_) => break,
                _ => {}
            }
        }
    });

    // Heartbeat ticker
    let mut heartbeat_interval = tokio::time::interval(Duration::from_secs(30));
    heartbeat_interval.tick().await; // Skip first immediate tick

    info!("idle — waiting for capture instructions from server");

    loop {
        tokio::select! {
            // Forward captured packets
            Some(frame) = pkt_rx.recv() => {
                write.send(Message::Binary(frame.into())).await?;
            }

            // Handle control messages
            Some(ctrl) = ctrl_rx.recv() => {
                match ctrl {
                    ControlMessage::CaptureStart { interfaces } => {
                        info!("received capture_start for: {:?}", interfaces);
                        // Stop existing captures
                        stop_captures(&mut captures.lock().unwrap());

                        // Start new captures
                        let mut started = Vec::new();
                        for iface in &interfaces {
                            match spawn_capture_thread(iface, pkt_tx.clone(), verbose) {
                                Ok(handle) => {
                                    captures.lock().unwrap().insert(iface.clone(), handle);
                                    started.push(iface.clone());
                                }
                                Err(e) => {
                                    error!("failed to start capture on {}: {}", iface, e);
                                    let err_msg = CaptureErrorMessage {
                                        msg_type: "capture_error".into(),
                                        interface: iface.clone(),
                                        error: e,
                                    };
                                    write.send(Message::Text(
                                        serde_json::to_string(&err_msg)?.into()
                                    )).await?;
                                }
                            }
                        }

                        // Confirm status
                        let status = CaptureStatusMessage {
                            msg_type: "capture_status".into(),
                            interfaces: started,
                            state: "capturing".into(),
                        };
                        write.send(Message::Text(
                            serde_json::to_string(&status)?.into()
                        )).await?;
                    }
                    ControlMessage::CaptureStop => {
                        info!("received capture_stop");
                        stop_captures(&mut captures.lock().unwrap());
                        let status = CaptureStatusMessage {
                            msg_type: "capture_status".into(),
                            interfaces: vec![],
                            state: "idle".into(),
                        };
                        write.send(Message::Text(
                            serde_json::to_string(&status)?.into()
                        )).await?;
                        info!("idle — waiting for capture instructions from server");
                    }
                }
            }

            // Send heartbeat
            _ = heartbeat_interval.tick() => {
                let caps = captures.lock().unwrap();
                let mut stats: HashMap<String, InterfaceStats> = HashMap::new();
                for (name, handle) in caps.iter() {
                    stats.insert(name.clone(), InterfaceStats {
                        packets: handle.packets.load(Ordering::Relaxed),
                        bytes: handle.bytes.load(Ordering::Relaxed),
                    });
                }
                drop(caps);

                let hb = HeartbeatMessage {
                    msg_type: "heartbeat".into(),
                    sensor: embedded::SENSOR_NAME.into(),
                    stats,
                };
                write.send(Message::Text(
                    serde_json::to_string(&hb)?.into()
                )).await?;
            }

            // Read task ended = connection lost
            _ = &mut read_task => {
                break;
            }
        }
    }

    // Cleanup captures on disconnect
    stop_captures(&mut captures.lock().unwrap());

    Ok(())
}

async fn establish_ws(
    server: &str,
) -> Result<
    (
        futures_util::stream::SplitSink<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
            tokio_tungstenite::tungstenite::Message,
        >,
        futures_util::stream::SplitStream<
            tokio_tungstenite::WebSocketStream<
                tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
            >,
        >,
    ),
    Box<dyn std::error::Error>,
> {
    use futures_util::StreamExt;

    let certs: Vec<_> = rustls_pemfile::certs(&mut &embedded::CERT_PEM[..])
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut &embedded::KEY_PEM[..])?
        .ok_or("no private key found in embedded PEM")?;
    let mut root_store = rustls::RootCertStore::empty();
    for ca in rustls_pemfile::certs(&mut &embedded::CA_PEM[..]) {
        root_store.add(ca?)?;
    }

    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = tokio_tungstenite::Connector::Rustls(Arc::new(tls_config));

    let ws_url = format!(
        "wss://{}/api/v1/capture/remote?name={}",
        server, embedded::SENSOR_NAME
    );

    let (ws_stream, _) = tokio_tungstenite::connect_async_tls_with_config(
        &ws_url,
        None,
        false,
        Some(connector),
    )
    .await?;

    Ok(ws_stream.split())
}

/// Legacy connection (for -i flag): just streams packets, no control
async fn connect_legacy(
    server: &str,
    rx: &mut mpsc::Receiver<Vec<u8>>,
    ring: &Arc<Mutex<RingBuffer>>,
    _verbose: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::SinkExt;
    use tokio_tungstenite::tungstenite::Message;

    let (mut write, mut read) = establish_ws(server).await?;

    info!("TLS handshake complete, cert: {}", embedded::SENSOR_NAME);

    // Spawn read task for ping handling
    tokio::spawn(async move {
        use futures_util::StreamExt;
        while let Some(msg) = read.next().await {
            match msg {
                Ok(Message::Close(_)) | Err(_) => break,
                _ => {}
            }
        }
    });

    // Send discovery
    let discovery = DiscoveryMessage {
        msg_type: "discovery".into(),
        sensor: embedded::SENSOR_NAME.into(),
        interfaces: get_discovery_interfaces(),
    };
    write
        .send(Message::Text(serde_json::to_string(&discovery)?.into()))
        .await?;
    info!("reported interfaces to central");

    // Drain ring buffer
    let buffered = ring.lock().unwrap().drain();
    if !buffered.is_empty() {
        info!("draining {} buffered frames", buffered.len());
        for frame in &buffered {
            write.send(Message::Binary(frame.clone().into())).await?;
        }
    }

    // Stream live packets
    while let Some(frame) = rx.recv().await {
        write.send(Message::Binary(frame.into())).await?;
    }

    Ok(())
}
