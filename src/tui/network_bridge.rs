//! Bridges the TUI's synchronous event loop to the async `net` layer, so
//! a vault can actually serve connected peers while it's open in the
//! app -- without ever giving a second thread its own `Vault` handle on
//! the same file (see `cli::commands::network::Serve` docs for why that
//! matters).
//!
//! The design: a background thread runs its own small Tokio runtime that
//! owns the TCP listener and does the handshake for each incoming
//! connection -- none of which needs the vault. Once a connection tells
//! us its chain state, the background thread *asks the main thread* what
//! to send back (via a plain `std::sync::mpsc` channel) and waits for the
//! answer on a `tokio::sync::oneshot` channel. The main thread answers
//! using the same `Vault` + `PatchJournal` it already owns, on its own
//! schedule (`UnlockedState::poll_network`, called once per TUI tick) --
//! so the vault is only ever touched from the one thread that already
//! has it open.

use std::net::SocketAddr;
use std::sync::mpsc as std_mpsc;
use std::thread;

use tokio::sync::oneshot;

use crate::core::identity::{Identity, PeerId};
use crate::net::{SecureChannel, SyncMessage};

/// Sent from the background network thread to the main thread when a
/// peer has connected and reported where their replica is.
pub enum SyncRequest {
    Incoming { peer_id: PeerId, next_seq: u64, respond_to: oneshot::Sender<SyncResponse> },
}

pub enum SyncResponse {
    NotGranted,
    Message(SyncMessage),
}

/// Sent from the background thread to the main thread purely for
/// display (log lines, status messages) -- never anything the main
/// thread needs to act on synchronously.
pub enum BridgeEvent {
    Synced(PeerId),
    Failed(String),
}

pub struct NetworkBridge {
    pub listen_addr: SocketAddr,
    pub request_rx: std_mpsc::Receiver<SyncRequest>,
    pub event_rx: std_mpsc::Receiver<BridgeEvent>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    _handle: thread::JoinHandle<()>,
}

impl NetworkBridge {
    /// Starts listening in a background thread. `identity_bytes` is a
    /// plain byte copy of the local identity (`Identity::to_bytes`) --
    /// passed across the thread boundary this way because `Identity`
    /// itself is deliberately not `Clone` (to discourage casual copies
    /// of key material), so each side reconstructs its own instance from
    /// the same bytes instead of sharing one.
    pub fn start(listen_addr: SocketAddr, identity_bytes: [u8; 64]) -> std::io::Result<Self> {
        let (request_tx, request_rx) = std_mpsc::channel();
        let (event_tx, event_rx) = std_mpsc::channel();
        let (shutdown_tx, mut shutdown_rx) = oneshot::channel::<()>();
        let (ready_tx, ready_rx) = std_mpsc::channel::<std::io::Result<()>>();

        let handle = thread::Builder::new().name("revault-net".to_string()).spawn(move || {
            let runtime = match tokio::runtime::Runtime::new() {
                Ok(rt) => rt,
                Err(e) => {
                    let _ = ready_tx.send(Err(e));
                    return;
                }
            };
            runtime.block_on(async move {
                let listener = match tokio::net::TcpListener::bind(listen_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        let _ = ready_tx.send(Err(e));
                        return;
                    }
                };
                let _ = ready_tx.send(Ok(()));

                loop {
                    tokio::select! {
                        _ = &mut shutdown_rx => {
                            break;
                        }
                        accept_result = listener.accept() => {
                            let (stream, _addr) = match accept_result {
                                Ok(x) => x,
                                Err(e) => {
                                    let _ = event_tx.send(BridgeEvent::Failed(format!("accept error: {e}")));
                                    continue;
                                }
                            };
                            let identity = Identity::from_bytes(&identity_bytes);
                            let request_tx = request_tx.clone();
                            let event_tx = event_tx.clone();
                            tokio::spawn(async move {
                                match handle_connection(stream, &identity, &request_tx).await {
                                    Ok(peer_id) => {
                                        let _ = event_tx.send(BridgeEvent::Synced(peer_id));
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(BridgeEvent::Failed(e));
                                    }
                                }
                            });
                        }
                    }
                }
            });
        })?;

        // Surface a bind failure synchronously to the caller instead of
        // only via the event channel, so `serve`-from-the-TUI can show
        // an immediate error rather than silently doing nothing.
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(std::io::Error::new(std::io::ErrorKind::Other, "network thread exited before starting")),
        }

        Ok(NetworkBridge { listen_addr, request_rx, event_rx, shutdown_tx: Some(shutdown_tx), _handle: handle })
    }

    /// Signals the background thread to stop accepting new connections.
    /// Fire-and-forget: does not block waiting for the thread to exit,
    /// since the TUI shouldn't freeze on shutdown.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Drop for NetworkBridge {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn handle_connection(
    stream: tokio::net::TcpStream,
    identity: &Identity,
    request_tx: &std_mpsc::Sender<SyncRequest>,
) -> Result<PeerId, String> {
    let (mut channel, peer_id) = SecureChannel::responder(stream, identity).await.map_err(|e| e.to_string())?;

    let their_state_bytes = channel.recv().await.map_err(|e| e.to_string())?;
    let next_seq = match SyncMessage::decode(&their_state_bytes).map_err(|e| e.to_string())? {
        SyncMessage::ChainState { next_seq, .. } => next_seq,
        _ => return Err("peer did not send ChainState first".to_string()),
    };

    let (respond_to, response_rx) = oneshot::channel();
    request_tx
        .send(SyncRequest::Incoming { peer_id, next_seq, respond_to })
        .map_err(|_| "the app is no longer listening for sync requests".to_string())?;

    let response = response_rx.await.map_err(|_| "the app dropped this sync request".to_string())?;
    match response {
        SyncResponse::NotGranted => {
            let _ = channel
                .send(&SyncMessage::Error { message: "not granted access to this vault".to_string() }.encode())
                .await;
            Err(format!("{} is not granted access", peer_id.fingerprint()))
        }
        SyncResponse::Message(msg) => {
            channel.send(&msg.encode()).await.map_err(|e| e.to_string())?;
            Ok(peer_id)
        }
    }
}
