#[cfg(test)]
mod tests;

use std::{
    collections::HashMap,
    str::FromStr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, SystemTime},
};

use tokio::{
    sync::{mpsc, oneshot, watch},
    task::JoinSet,
    time::interval,
};
use tonic::Status;
use tracing::instrument;
use xguard_wireguard_rs::{WireguardInterfaceApi, net::IpAddrMask};

use crate::{
    config::Config,
    error::GatewayError,
    gateway_server::GatewayServer,
    proto::{
        common::LogEntry,
        gateway::{Configuration, CoreRequest, Peer, Update, UpdateType, core_request, update},
    },
    setup::run_setup,
};

fn cleanup_on_quit(config: &Config, gateway: &Arc<Mutex<Gateway>>) {
    if config.clean_on_quit {
        gateway.lock().unwrap().purge();
    }
}

/// Runs initial setup and keeps the gRPC server available until shutdown.
pub async fn run_gateway_loop(
    config: Config,
    gateway: Arc<Mutex<Gateway>>,
    logs_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<LogEntry>>>,
    tls_config: Option<TlsConfig>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut tls_config = match tls_config {
        Some(tls_config) => {
            log::info!(
                "Using existing gRPC TLS certificates from {}",
                config.cert_dir.display()
            );
            tls_config
        }
        None => {
            log::info!(
                "gRPC TLS certificates not found in {}. They will be generated during setup.",
                config.cert_dir.display()
            );
            tokio::select! {
                biased;
                _ = shutdown.changed() => {
                    cleanup_on_quit(&config, &gateway);
                    return;
                }
                result = run_setup(&config, Arc::clone(&logs_rx)) => match result {
                    Ok(tls_config) => tls_config,
                    Err(err) => {
                        error!("Failed to run setup: {err}");
                        return;
                    }
                }
            }
        }
    };

    loop {
        let (reset_tx, mut reset_rx) = oneshot::channel();
        let mut gateway_server =
            GatewayServer::new(Arc::clone(&gateway), config.cert_dir.clone(), reset_tx);
        gateway_server.set_tls_config(tls_config.clone());
        let mut server_tasks = JoinSet::new();
        server_tasks.spawn(gateway_server.start(config.clone()));

        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                server_tasks.abort_all();
                while server_tasks.join_next().await.is_some() {}
                cleanup_on_quit(&config, &gateway);
                return;
            }
            // The purge RPC requested setup mode.
            reset = &mut reset_rx => {
                if reset.is_err() {
                    match server_tasks.join_next().await {
                        Some(Ok(Ok(()))) | None => (),
                        Some(Ok(Err(err))) => {
                            error!("gRPC server task failed: {err}");
                            return;
                        }
                        Some(Err(err)) => {
                            error!("gRPC server task failed: {err}");
                            return;
                        }
                    }
                    break;
                }

                server_tasks.abort_all();
                while server_tasks.join_next().await.is_some() {}

                log::info!("Restarting setup server after purge request");
                tls_config = tokio::select! {
                    biased;
                    _ = shutdown.changed() => {
                        cleanup_on_quit(&config, &gateway);
                        return;
                    }
                    result = run_setup(&config, Arc::clone(&logs_rx)) => match result {
                        Ok(tls_config) => tls_config,
                        Err(err) => {
                            error!("Failed to run setup {err}");
                            return;
                        }
                    }
                };
            }
            result = server_tasks.join_next() => {
                match result {
                    Some(Ok(Ok(()))) | None => (),
                    Some(Ok(Err(err))) => {
                        error!("gRPC server task failed: {err}");
                        return;
                    }
                    Some(Err(err)) => {
                        error!("gRPC server task failed: {err}");
                        return;
                    }
                }
                break;
            }
        }
    }
}

// Helper struct which stores just the interface config without peers.
#[derive(Clone, PartialEq)]
struct InterfaceConfiguration {
    name: String,
    private_key: String,
    addresses: Vec<IpAddrMask>,
    port: u16,
    mtu: u32,
    fwmark: u32,
}

impl From<Configuration> for InterfaceConfiguration {
    fn from(config: Configuration) -> Self {
        // Try to convert an array of `String`s to `IpAddrMask`, leaving out the failed ones.
        let addresses = config
            .addresses
            .into_iter()
            .filter_map(|s| IpAddrMask::from_str(&s).ok())
            .collect();
        Self {
            name: config.name,
            private_key: config.private_key,
            addresses,
            port: config.port as u16,
            mtu: config.mtu,
            fwmark: config.fwmark,
        }
    }
}

type PubKey = String;

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub grpc_cert_pem: String,
    pub grpc_key_pem: String,
    /// PEM-encoded CA certificate used to verify Core's mTLS client certificate chain.
    pub grpc_ca_cert_pem: String,
    /// DER-encoded Core client certificate; used to extract and pin the expected serial.
    pub core_client_cert_der: Vec<u8>,
}

pub struct Gateway {
    config: Config,
    interface_configuration: Option<InterfaceConfiguration>,
    peers: HashMap<PubKey, Peer>,
    pub(crate) wgapi: Arc<Mutex<dyn WireguardInterfaceApi + Send + Sync + 'static>>,
    pub connected: Arc<AtomicBool>,
    // Transmission channel. Important: allows only one connected client.
    pub(crate) client_tx: Option<mpsc::UnboundedSender<Result<CoreRequest, Status>>>,
    pub(crate) tls_config: Option<TlsConfig>,
}

impl Gateway {
    pub fn new(
        config: Config,
        wgapi: impl WireguardInterfaceApi + Send + Sync + 'static,
    ) -> Result<Self, GatewayError> {
        if config.masquerade {
            warn!(
                "masquerade is enabled, but XGuard gateways do not manage NAT rules yet. \
                Configure masquerading on the host (nftables/iptables) for this interface."
            );
        }
        Ok(Self {
            config,
            interface_configuration: None,
            peers: HashMap::new(),
            wgapi: Arc::new(Mutex::new(wgapi)),
            connected: Arc::new(AtomicBool::new(false)),
            client_tx: None,
            tls_config: None,
        })
    }

    /// Purge the `Gateway` and prepare to enter setup mode.
    pub(crate) fn purge(&mut self) {
        // Drop the interface.
        if let Err(err) = self
            .wgapi
            .lock()
            .expect("Failed to lock Gateway::wgapi")
            .remove_interface()
        {
            error!("Gateway purge failed to drop the interface: {err}");
        }
        // Reset connection state.
        self.interface_configuration = None;
        self.peers.clear();
        self.client_tx = None;
        self.connected.store(false, Ordering::Relaxed);
    }

    /// Grace period to wait after a Core disconnect before purging the interface.
    /// Zero means purge immediately (no grace).
    pub(crate) fn disconnect_grace_period(&self) -> Duration {
        Duration::from_secs(self.config.core_disconnect_grace_period)
    }

    // Replace current peer map with a new list of peers.
    fn replace_peers(&mut self, new_peers: Vec<Peer>) {
        debug!("Replacing stored peers with {} new peers", new_peers.len());
        let peers = new_peers
            .into_iter()
            .map(|peer| (peer.pubkey.clone(), peer))
            .collect();
        self.peers = peers;
    }

    // Check if new received configuration is different than current one.
    fn is_interface_config_changed(
        &self,
        new_interface_configuration: &InterfaceConfiguration,
        new_peers: &[Peer],
    ) -> bool {
        if let Some(current_configuration) = &self.interface_configuration {
            return current_configuration != new_interface_configuration
                || self.is_peer_list_changed(new_peers);
        }
        true
    }

    // Check if new peers are the same as the stored ones.
    fn is_peer_list_changed(&self, new_peers: &[Peer]) -> bool {
        // check if number of peers is different
        if self.peers.len() != new_peers.len() {
            return true;
        }

        // check if all pubkeys are the same
        if !new_peers
            .iter()
            .map(|peer| &peer.pubkey)
            .all(|k| self.peers.contains_key(k))
        {
            return true;
        }

        // Check if all IP addresses are the same.
        !new_peers.iter().all(|peer| {
            self.peers
                .get(&peer.pubkey)
                .is_some_and(|p| peer.allowed_ips == p.allowed_ips)
        })
    }

    /// Performs complete interface reconfiguration based on `configuration` object.
    /// Called when gateway (re)connects to gRPC endpoint and retrieves complete
    /// network and peers data.
    pub(crate) fn configure(
        &mut self,
        new_configuration: Configuration,
    ) -> Result<(), GatewayError> {
        debug!(
            "Received configuration, reconfiguring WireGuard interface {} (addresses: {:?})",
            new_configuration.name, new_configuration.addresses
        );

        trace!("Received configuration: {new_configuration:?}");

        // configure() is the sole owner of interface existence; recreate it if
        // it was removed (e.g. by purge during a disconnect).
        {
            let mut wgapi = self.wgapi.lock().expect("Failed to lock Gateway::wgapi");
            if wgapi.read_interface_data().is_err() {
                info!(
                    "WireGuard interface {} is not present, creating it",
                    new_configuration.name
                );
                wgapi.create_interface()?;
            }
        }

        // check if new configuration is different than current one
        let new_interface_configuration = new_configuration.clone().into();

        if self.is_interface_config_changed(&new_interface_configuration, &new_configuration.peers)
        {
            debug!(
                "Received configuration is different than the current one. Reconfiguring interface."
            );
            let config =
                xguard_wireguard_rs::InterfaceConfiguration::from(new_configuration.clone());

            self.wgapi.lock().unwrap().configure_interface(&config)?;
            info!(
                "Reconfigured WireGuard interface {} (addresses: {:?})",
                new_configuration.name, new_configuration.addresses
            );
            trace!("Reconfigured WireGuard interface. Configuration: {new_configuration:?}");
            // store new configuration and peers
            self.interface_configuration = Some(new_interface_configuration);
            self.replace_peers(new_configuration.peers);
        } else {
            debug!(
                "Received configuration is identical to the current one. Skipping interface \
                reconfiguration."
            );
        }

        Ok(())
    }

    /// Send message to the connected client.
    fn send_to_client(&self, message: &CoreRequest) {
        if let Some(tx) = &self.client_tx
            && tx.send(Ok(message.clone())).is_err()
        {
            warn!("Failed to send message to Core.");
        }
    }

    #[instrument(skip_all)]
    pub(crate) fn handle_updates(&mut self, update: Update) {
        debug!("Received update: {update:?}");
        match update.update {
            Some(update::Update::Network(configuration)) => {
                if let Err(err) = self.configure(configuration) {
                    error!("Failed to update network configuration: {err}");
                }
            }
            Some(update::Update::Peer(peer_config)) => {
                debug!("Applying peer configuration: {peer_config:?}");
                if UpdateType::try_from(update.update_type) == Ok(UpdateType::Delete) {
                    debug!("Deleting peer {peer_config:?}");
                    self.peers.remove(&peer_config.pubkey);
                    match peer_config.pubkey.as_str().try_into() {
                        Ok(key) => {
                            if let Err(err) = self.wgapi.lock().unwrap().remove_peer(&key) {
                                error!("Failed to delete peer: {err}");
                            }
                        }
                        Err(err) => {
                            error!(
                                "Failed to parse public key of peer {} to delete: {err}",
                                peer_config.pubkey
                            );
                        }
                    }
                }
                // UpdateType::Create, UpdateType::Modify
                else {
                    debug!(
                        "Updating peer {peer_config:?}, update type: {}",
                        update.update_type
                    );
                    self.peers
                        .insert(peer_config.pubkey.clone(), peer_config.clone());
                    if let Err(err) = self
                        .wgapi
                        .lock()
                        .unwrap()
                        .configure_peer(&peer_config.into())
                    {
                        error!("Failed to update peer: {err}");
                    }
                }
            }
            Some(update::Update::DisableFirewall(())) => {
                // XGuard gateways do not manage firewall rules (Defguard enterprise code removed).
                debug!("Ignoring firewall disable request: firewall management is not supported");
            }
            _ => warn!("Unsupported kind of update: {update:?}"),
        }
    }
}

/// Gather WireGuard statistics and send them to Core through gRPC.
pub async fn run_stats(gateway: Arc<Mutex<Gateway>>, period: Duration) {
    // Helper map to track if peer data is actually changing to avoid sending duplicate stats.
    let mut peer_map = HashMap::new();
    let mut interval = interval(period);
    let mut id = 1;
    loop {
        // Wait until next iteration.
        interval.tick().await;

        // FIXME: the whole thread should only run when core is connected
        // Skip stats if not connected.
        if !gateway
            .lock()
            .expect("Stats thread failed to lock gateway")
            .connected
            .load(Ordering::Relaxed)
        {
            debug!("Gateway disconnected, skipping stats collection");
            continue;
        }

        debug!("Obtaining peer statistics from WireGuard");
        let result = gateway
            .lock()
            .expect("gateway mutex poison")
            .wgapi
            .lock()
            .expect("wgapi mutex poison")
            .read_interface_data();
        match result {
            Ok(host) => {
                let peers = host.peers;
                debug!(
                    "Found {} peers configured on WireGuard interface",
                    peers.len()
                );
                // Filter out never connected peers.
                for peer in peers.into_values().filter(|p| {
                    p.last_handshake
                        .is_some_and(|last_hs| last_hs != SystemTime::UNIX_EPOCH)
                }) {
                    let has_changed = match peer_map.get(&peer.public_key) {
                        Some(last_peer) => *last_peer != peer,
                        None => true,
                    };
                    if has_changed {
                        peer_map.insert(peer.public_key.clone(), peer.clone());
                        let payload = core_request::Payload::PeerStats((&peer).into());
                        let message = CoreRequest {
                            id,
                            payload: Some(payload),
                        };
                        id += 1;
                        gateway
                            .lock()
                            .expect("gateway mutex poison")
                            .send_to_client(&message);
                        debug!("Sent statistics for peer {}", peer.public_key);
                    } else {
                        debug!(
                            "Statistics for peer {} have not changed. Skipping.",
                            peer.public_key
                        );
                    }
                }
            }
            Err(err) => error!("Failed to retrieve WireGuard interface statistics: {err}"),
        }
    }
}
