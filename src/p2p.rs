// src/p2p.rs - Enterprise-grade P2P networking for Pali Coin
use crate::types::{Block, Transaction, Hash, Address};
use crate::network::{SecureNetworkClient, NetworkMessage, MessagePriority, NodeInfo};
use crate::security::SecurityManager;
use crate::blockchain::Blockchain;
use crate::error::{PaliError, Result};
use crate::config::PaliConfig;
use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, IpAddr, ToSocketAddrs};
use std::sync::{Arc, RwLock, Mutex, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::thread::{self, JoinHandle};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, broadcast, Semaphore};
use tokio::time::{timeout, sleep};
use log::{info, warn, error, debug};
use serde::{Serialize, Deserialize};
use rand::{seq::SliceRandom, thread_rng, Rng};
use futures::future::join_all;

// P2P networking constants for Bitcoin-level connectivity
const MAX_OUTBOUND_CONNECTIONS: usize = 8;
const MAX_INBOUND_CONNECTIONS: usize = 125;
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);
const PING_INTERVAL: Duration = Duration::from_secs(60);
const SYNC_TIMEOUT: Duration = Duration::from_secs(300);
const PEER_DISCOVERY_INTERVAL: Duration = Duration::from_secs(300);
const MAX_ADDR_PER_MESSAGE: usize = 1000;
const MAX_INV_PER_MESSAGE: usize = 50000;
const STALE_CONNECTION_TIMEOUT: Duration = Duration::from_secs(900); // 15 minutes
const BLOCK_DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_BLOCKS_IN_FLIGHT: usize = 16;

/// P2P network service types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceFlags {
    None = 0,
    Network = 1,        // Full node with complete blockchain
    GetUtxo = 2,        // Supports UTXO queries
    Bloom = 4,          // Supports bloom filtering
    Witness = 8,        // Supports segregated witness
    NetworkLimited = 1024, // Pruned node with limited blockchain
}

/// Connection state tracking
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    Connecting,
    Connected,
    Handshaking,
    Active,
    Syncing,
    Stale,
    Disconnecting,
    Banned,
}

/// Peer information and statistics
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: SocketAddr,
    pub node_id: String,
    pub user_agent: String,
    pub version: u32,
    pub services: u64,
    pub height: u64,
    pub last_seen: Instant,
    pub connected_at: Instant,
    pub state: ConnectionState,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub ping_time: Option<Duration>,
    pub ban_score: u32,
    pub is_outbound: bool,
    pub relay_transactions: bool,
    pub last_block_received: Option<Instant>,
    pub blocks_requested: HashSet<Hash>,
    pub transactions_requested: HashSet<Hash>,
}

/// Block synchronization state
#[derive(Debug)]
pub struct SyncState {
    pub is_syncing: bool,
    pub sync_peer: Option<SocketAddr>,
    pub start_height: u64,
    pub current_height: u64,
    pub target_height: u64,
    pub blocks_in_flight: HashMap<Hash, (SocketAddr, Instant)>,
    pub last_progress: Instant,
    pub sync_start_time: Instant,
}

/// Inventory item for efficient data synchronization
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InventoryItem {
    Error,
    Transaction(Hash),
    Block(Hash),
    CompactBlock(Hash),
    WitnessTransaction(Hash),
    WitnessBlock(Hash),
}

/// Message filtering and relay policies
#[derive(Debug, Clone)]
pub struct RelayPolicy {
    pub min_fee_rate: u64,
    pub max_tx_size: usize,
    pub bloom_filter: Option<BloomFilter>,
    pub relay_priority: MessagePriority,
}

#[derive(Debug, Clone)]
pub struct BloomFilter {
    pub filter: Vec<u8>,
    pub hash_functions: u32,
    pub tweak: u32,
    pub flags: u8,
}

/// Peer discovery and address management
#[derive(Debug)]
pub struct AddressManager {
    known_addresses: HashMap<SocketAddr, AddressInfo>,
    tried_addresses: HashMap<SocketAddr, AddressInfo>,
    new_addresses: VecDeque<SocketAddr>,
    banned_addresses: HashMap<SocketAddr, Instant>,
    dns_seeds: Vec<String>,
    last_discovery: Instant,
}

#[derive(Debug, Clone)]
pub struct AddressInfo {
    pub addr: SocketAddr,
    pub services: u64,
    pub last_seen: u64,
    pub last_attempt: Option<Instant>,
    pub attempts: u32,
    pub success_count: u32,
    pub source: AddressSource,
}

#[derive(Debug, Clone)]
pub enum AddressSource {
    DnsSeed,
    PeerAdvertisement,
    ManualAdd,
    Config,
}

/// Main P2P network manager
pub struct P2PNetwork {
    config: PaliConfig,
    blockchain: Arc<RwLock<Blockchain>>,
    security_manager: Arc<SecurityManager>,
    
    // Connection management
    peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
    connections: Arc<RwLock<HashMap<SocketAddr, SecureNetworkClient>>>,
    address_manager: Arc<RwLock<AddressManager>>,
    
    // Synchronization state
    sync_state: Arc<RwLock<SyncState>>,
    
    // Communication channels
    peer_tx: broadcast::Sender<NetworkMessage>,
    peer_rx: broadcast::Receiver<NetworkMessage>,
    command_tx: mpsc::Sender<P2PCommand>,
    command_rx: mpsc::Receiver<P2PCommand>,
    
    // Service state
    is_running: Arc<AtomicBool>,
    local_services: u64,
    user_agent: String,
    version: u32,
    
    // Performance metrics
    stats: Arc<RwLock<P2PStats>>,
    
    // Connection limiting
    connection_semaphore: Arc<Semaphore>,
    
    // Background tasks
    task_handles: Vec<JoinHandle<()>>,
}

/// P2P command interface
#[derive(Debug)]
pub enum P2PCommand {
    Connect(SocketAddr),
    Disconnect(SocketAddr),
    Ban(SocketAddr, Duration),
    Broadcast(NetworkMessage),
    SendToPeer(SocketAddr, NetworkMessage),
    RequestBlocks(Vec<Hash>),
    RequestTransactions(Vec<Hash>),
    AddAddress(SocketAddr),
    GetPeerInfo,
    GetSyncState,
}

/// P2P network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct P2PStats {
    pub connected_peers: usize,
    pub outbound_connections: usize,
    pub inbound_connections: usize,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub blocks_downloaded: u64,
    pub transactions_relayed: u64,
    pub connection_attempts: u64,
    pub failed_connections: u64,
    pub banned_peers: u64,
    pub uptime: Duration,
}

impl PeerInfo {
    pub fn new(addr: SocketAddr, is_outbound: bool) -> Self {
        let now = Instant::now();
        
        PeerInfo {
            addr,
            node_id: String::new(),
            user_agent: String::new(),
            version: 0,
            services: 0,
            height: 0,
            last_seen: now,
            connected_at: now,
            state: ConnectionState::Connecting,
            bytes_sent: 0,
            bytes_received: 0,
            ping_time: None,
            ban_score: 0,
            is_outbound,
            relay_transactions: true,
            last_block_received: None,
            blocks_requested: HashSet::new(),
            transactions_requested: HashSet::new(),
        }
    }
    
    pub fn update_activity(&mut self) {
        self.last_seen = Instant::now();
    }
    
    pub fn is_stale(&self) -> bool {
        self.last_seen.elapsed() > STALE_CONNECTION_TIMEOUT
    }
    
    pub fn increase_ban_score(&mut self, points: u32) {
        self.ban_score = self.ban_score.saturating_add(points);
    }
    
    pub fn should_be_banned(&self) -> bool {
        self.ban_score >= 100
    }
}

impl SyncState {
    pub fn new() -> Self {
        let now = Instant::now();
        
        SyncState {
            is_syncing: false,
            sync_peer: None,
            start_height: 0,
            current_height: 0,
            target_height: 0,
            blocks_in_flight: HashMap::new(),
            last_progress: now,
            sync_start_time: now,
        }
    }
    
    pub fn start_sync(&mut self, peer: SocketAddr, start_height: u64, target_height: u64) {
        self.is_syncing = true;
        self.sync_peer = Some(peer);
        self.start_height = start_height;
        self.current_height = start_height;
        self.target_height = target_height;
        self.sync_start_time = Instant::now();
        self.last_progress = Instant::now();
        
        info!("Started blockchain sync with {} from height {} to {}", peer, start_height, target_height);
    }
    
    pub fn update_progress(&mut self, height: u64) {
        self.current_height = height;
        self.last_progress = Instant::now();
    }
    
    pub fn finish_sync(&mut self) {
        let duration = self.sync_start_time.elapsed();
        let blocks_synced = self.current_height - self.start_height;
        
        info!("Blockchain sync completed: {} blocks in {:?}", blocks_synced, duration);
        
        self.is_syncing = false;
        self.sync_peer = None;
        self.blocks_in_flight.clear();
    }
    
    pub fn is_stuck(&self) -> bool {
        self.is_syncing && self.last_progress.elapsed() > SYNC_TIMEOUT
    }
    
    pub fn sync_progress(&self) -> f64 {
        if self.target_height > self.start_height {
            (self.current_height - self.start_height) as f64 / (self.target_height - self.start_height) as f64
        } else {
            1.0
        }
    }
}

impl AddressManager {
    pub fn new(dns_seeds: Vec<String>) -> Self {
        AddressManager {
            known_addresses: HashMap::new(),
            tried_addresses: HashMap::new(),
            new_addresses: VecDeque::new(),
            banned_addresses: HashMap::new(),
            dns_seeds,
            last_discovery: Instant::now() - PEER_DISCOVERY_INTERVAL, // Allow immediate discovery
        }
    }
    
    pub fn add_address(&mut self, addr: SocketAddr, source: AddressSource) {
        let services = ServiceFlags::Network as u64;
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        
        let addr_info = AddressInfo {
            addr,
            services,
            last_seen: now,
            last_attempt: None,
            attempts: 0,
            success_count: 0,
            source,
        };
        
        if !self.known_addresses.contains_key(&addr) && !self.is_banned(&addr) {
            self.known_addresses.insert(addr, addr_info);
            self.new_addresses.push_back(addr);
            debug!("Added new address: {}", addr);
        }
    }
    
    pub fn get_addresses_to_try(&mut self, count: usize) -> Vec<SocketAddr> {
        let mut addresses = Vec::new();
        
        // Prefer new addresses
        while addresses.len() < count && !self.new_addresses.is_empty() {
            if let Some(addr) = self.new_addresses.pop_front() {
                if !self.is_banned(&addr) {
                    addresses.push(addr);
                }
            }
        }
        
        // Fill with tried addresses if needed
        if addresses.len() < count {
            let mut tried: Vec<_> = self.tried_addresses.keys().cloned().collect();
            tried.shuffle(&mut thread_rng());
            
            for addr in tried.into_iter().take(count - addresses.len()) {
                if !self.is_banned(&addr) {
                    addresses.push(addr);
                }
            }
        }
        
        addresses
    }
    
    pub fn mark_attempt(&mut self, addr: SocketAddr) {
        if let Some(info) = self.known_addresses.get_mut(&addr) {
            info.attempts += 1;
            info.last_attempt = Some(Instant::now());
        }
    }
    
    pub fn mark_success(&mut self, addr: SocketAddr) {
        if let Some(info) = self.known_addresses.remove(&addr) {
            let mut updated_info = info;
            updated_info.success_count += 1;
            updated_info.last_seen = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
            self.tried_addresses.insert(addr, updated_info);
        }
    }
    
    pub fn mark_failure(&mut self, addr: SocketAddr) {
        if let Some(info) = self.known_addresses.get_mut(&addr) {
            info.attempts += 1;
            
            // Ban after too many failures
            if info.attempts > 10 {
                self.ban_address(addr, Duration::from_secs(3600));
            }
        }
    }
    
    pub fn ban_address(&mut self, addr: SocketAddr, duration: Duration) {
        self.banned_addresses.insert(addr, Instant::now() + duration);
        self.known_addresses.remove(&addr);
        self.tried_addresses.remove(&addr);
        warn!("Banned address {} for {:?}", addr, duration);
    }
    
    pub fn is_banned(&self, addr: &SocketAddr) -> bool {
        if let Some(&ban_until) = self.banned_addresses.get(addr) {
            Instant::now() < ban_until
        } else {
            false
        }
    }
    
    pub fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        self.banned_addresses.retain(|_, &mut ban_until| now < ban_until);
    }
    
    pub fn should_discover(&self) -> bool {
        self.last_discovery.elapsed() > PEER_DISCOVERY_INTERVAL && 
        self.new_addresses.len() < 100
    }
    
    pub async fn discover_peers(&mut self) -> Result<()> {
        if !self.should_discover() {
            return Ok(());
        }
        
        info!("Starting peer discovery...");
        
        for seed in &self.dns_seeds {
            match self.resolve_dns_seed(seed).await {
                Ok(addresses) => {
                    for addr in addresses {
                        self.add_address(addr, AddressSource::DnsSeed);
                    }
                }
                Err(e) => {
                    warn!("Failed to resolve DNS seed {}: {}", seed, e);
                }
            }
        }
        
        self.last_discovery = Instant::now();
        Ok(())
    }
    
    async fn resolve_dns_seed(&self, seed: &str) -> Result<Vec<SocketAddr>> {
        let full_address = if seed.contains(':') {
            seed.to_string()
        } else {
            format!("{}:8333", seed) // Default Pali Coin port
        };
        
        match full_address.to_socket_addrs() {
            Ok(addrs) => Ok(addrs.collect()),
            Err(e) => Err(PaliError::network(format!("DNS resolution failed: {}", e))),
        }
    }
}

impl P2PNetwork {
    pub fn new(
        config: PaliConfig,
        blockchain: Arc<RwLock<Blockchain>>,
        security_manager: Arc<SecurityManager>,
    ) -> Result<Self> {
        let (peer_tx, peer_rx) = broadcast::channel(1000);
        let (command_tx, command_rx) = mpsc::channel(100);
        
        let dns_seeds = vec![
            "seed1.palicoin.org".to_string(),
            "seed2.palicoin.org".to_string(),
            "seed3.palicoin.org".to_string(),
        ];
        
        let local_services = ServiceFlags::Network as u64;
        let user_agent = format!("PaliCoin/{}", env!("CARGO_PKG_VERSION"));
        let version = 1;
        
        Ok(P2PNetwork {
            config,
            blockchain,
            security_manager,
            peers: Arc::new(RwLock::new(HashMap::new())),
            connections: Arc::new(RwLock::new(HashMap::new())),
            address_manager: Arc::new(RwLock::new(AddressManager::new(dns_seeds))),
            sync_state: Arc::new(RwLock::new(SyncState::new())),
            peer_tx,
            peer_rx,
            command_tx,
            command_rx,
            is_running: Arc::new(AtomicBool::new(false)),
            local_services,
            user_agent,
            version,
            stats: Arc::new(RwLock::new(P2PStats::new())),
            connection_semaphore: Arc::new(Semaphore::new(MAX_OUTBOUND_CONNECTIONS + MAX_INBOUND_CONNECTIONS)),
            task_handles: Vec::new(),
        })
    }
    
    pub async fn start(&mut self) -> Result<()> {
        if self.is_running.load(Ordering::Relaxed) {
            return Err(PaliError::network("P2P network already running"));
        }
        
        info!("🌐 Starting P2P network...");
        
        self.is_running.store(true, Ordering::Relaxed);
        
        // Start listening for incoming connections
        self.start_listener().await?;
        
        // Start peer discovery
        self.start_peer_discovery();
        
        // Start connection manager
        self.start_connection_manager();
        
        // Start sync manager
        self.start_sync_manager();
        
        // Start message relay
        self.start_message_relay();
        
        // Start maintenance tasks
        self.start_maintenance_tasks();
        
        // Start command processor
        self.start_command_processor();
        
        // Initial peer discovery
        {
            let mut addr_mgr = self.address_manager.write().unwrap();
            if let Err(e) = addr_mgr.discover_peers().await {
                warn!("Initial peer discovery failed: {}", e);
            }
        }
        
        // Connect to initial peers
        self.connect_to_initial_peers().await?;
        
        info!("✅ P2P network started successfully");
        Ok(())
    }
    
    pub async fn stop(&mut self) {
        if !self.is_running.load(Ordering::Relaxed) {
            return;
        }
        
        info!("🛑 Stopping P2P network...");
        
        self.is_running.store(false, Ordering::Relaxed);
        
        // Disconnect all peers
        self.disconnect_all_peers().await;
        
        // Wait for all tasks to complete
        while let Some(handle) = self.task_handles.pop() {
            let _ = handle.join();
        }
        
        info!("✅ P2P network stopped");
    }
    
    async fn start_listener(&self) -> Result<()> {
        let listen_addr = format!("0.0.0.0:{}", self.config.network.port);
        let listener = TcpListener::bind(&listen_addr).await
            .map_err(|e| PaliError::network(format!("Failed to bind to {}: {}", listen_addr, e)))?;
        
        info!("🎧 Listening for P2P connections on {}", listen_addr);
        
        let is_running = Arc::clone(&self.is_running);
        let security_manager = Arc::clone(&self.security_manager);
        let connection_semaphore = Arc::clone(&self.connection_semaphore);
        let peers = Arc::clone(&self.peers);
        let connections = Arc::clone(&self.connections);
        let stats = Arc::clone(&self.stats);
        
        tokio::spawn(async move {
            while is_running.load(Ordering::Relaxed) {
                match listener.accept().await {
                    Ok((stream, addr)) => {
                        // Check security first
                        if !security_manager.check_connection(addr).unwrap_or(false) {
                            continue;
                        }
                        
                        // Check connection limit
                        if connection_semaphore.try_acquire().is_err() {
                            warn!("Connection limit reached, rejecting {}", addr);
                            continue;
                        }
                        
                        info!("📞 Incoming connection from {}", addr);
                        
                        // Handle connection in background
                        let security_manager = Arc::clone(&security_manager);
                        let peers = Arc::clone(&peers);
                        let connections = Arc::clone(&connections);
                        let stats = Arc::clone(&stats);
                        let semaphore = Arc::clone(&connection_semaphore);
                        
                        tokio::spawn(async move {
                            let _permit = semaphore.acquire().await;
                            
                            if let Err(e) = Self::handle_incoming_connection(
                                stream,
                                addr,
                                security_manager,
                                peers,
                                connections,
                                stats,
                            ).await {
                                error!("Error handling incoming connection from {}: {}", addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        error!("Failed to accept connection: {}", e);
                        sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });
        
        Ok(())
    }
    
    async fn handle_incoming_connection(
        stream: TcpStream,
        addr: SocketAddr,
        security_manager: Arc<SecurityManager>,
        peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        connections: Arc<RwLock<HashMap<SocketAddr, SecureNetworkClient>>>,
        stats: Arc<RwLock<P2PStats>>,
    ) -> Result<()> {
        let rate_limiter = Arc::new(Mutex::new(
            crate::network::RateLimiter::new()
        ));
        
        let mut client = SecureNetworkClient::connect_with_stream(stream, addr, rate_limiter).await?;
        
        // Perform handshake
        let node_id = match timeout(CONNECTION_TIMEOUT, client.handle_incoming_handshake("pali-node", 0)).await {
            Ok(Ok(id)) => id,
            Ok(Err(e)) => {
                warn!("Handshake failed with {}: {}", addr, e);
                return Err(e);
            }
            Err(_) => {
                warn!("Handshake timeout with {}", addr);
                return Err(PaliError::network("Handshake timeout"));
            }
        };
        
        // Create peer info
        let mut peer_info = PeerInfo::new(addr, false);
        peer_info.node_id = node_id;
        peer_info.state = ConnectionState::Active;
        
        // Store peer and connection
        {
            let mut peers = peers.write().unwrap();
            peers.insert(addr, peer_info);
        }
        
        {
            let mut connections = connections.write().unwrap();
            connections.insert(addr, client);
        }
        
        // Update stats
        {
            let mut stats = stats.write().unwrap();
            stats.inbound_connections += 1;
            stats.connected_peers += 1;
        }
        
        info!("✅ Established inbound connection with {}", addr);
        Ok(())
    }
    
    fn start_peer_discovery(&mut self) {
        let address_manager = Arc::clone(&self.address_manager);
        let is_running = Arc::clone(&self.is_running);
        
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            
            while is_running.load(Ordering::Relaxed) {
                rt.block_on(async {
                    {
                        let mut addr_mgr = address_manager.write().unwrap();
                        if let Err(e) = addr_mgr.discover_peers().await {
                            warn!("Peer discovery failed: {}", e);
                        }
                    }
                    
                    sleep(PEER_DISCOVERY_INTERVAL).await;
                });
            }
        });
        
        self.task_handles.push(handle);
    }
    
    fn start_connection_manager(&mut self) {
        let address_manager = Arc::clone(&self.address_manager);
        let peers = Arc::clone(&self.peers);
        let connections = Arc::clone(&self.connections);
        let security_manager = Arc::clone(&self.security_manager);
        let connection_semaphore = Arc::clone(&self.connection_semaphore);
        let stats = Arc::clone(&self.stats);
        let is_running = Arc::clone(&self.is_running);
        
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            
            while is_running.load(Ordering::Relaxed) {
                rt.block_on(async {
                    // Check current connection count
                    let (outbound_count, total_count) = {
                        let peers = peers.read().unwrap();
                        let outbound = peers.values().filter(|p| p.is_outbound && p.state == ConnectionState::Active).count();
                        (outbound, peers.len())
                    };
                    
                    // Connect to more peers if needed
                    if outbound_count < MAX_OUTBOUND_CONNECTIONS {
                        let needed = MAX_OUTBOUND_CONNECTIONS - outbound_count;
                        let addresses = {
                            let mut addr_mgr = address_manager.write().unwrap();
                            addr_mgr.get_addresses_to_try(needed)
                        };
                        
                        for addr in addresses {
                            if connection_semaphore.try_acquire().is_ok() {
                                let security_manager = Arc::clone(&security_manager);
                                let address_manager = Arc::clone(&address_manager);
                                let peers = Arc::clone(&peers);
                                let connections = Arc::clone(&connections);
                                let stats = Arc::clone(&stats);
                                let semaphore = Arc::clone(&connection_semaphore);
                                
                                tokio::spawn(async move {
                                    let _permit = semaphore.acquire().await;
                                    
                                    if let Err(e) = Self::connect_to_peer(
                                        addr,
                                        security_manager,
                                        address_manager,
                                        peers,
                                        connections,
                                        stats,
                                    ).await {
                                        debug!("Failed to connect to {}: {}", addr, e);
                                    }
                                });
                            }
                        }
                    }
                    
                    // Clean up stale connections
                    Self::cleanup_stale_connections(&peers, &connections).await;
                    
                    sleep(Duration::from_secs(30)).await;
                });
            }
        });
        
        self.task_handles.push(handle);
    }
    
    async fn connect_to_peer(
        addr: SocketAddr,
        security_manager: Arc<SecurityManager>,
        address_manager: Arc<RwLock<AddressManager>>,
        peers: Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        connections: Arc<RwLock<HashMap<SocketAddr, SecureNetworkClient>>>,
        stats: Arc<RwLock<P2PStats>>,
    ) -> Result<()> {
        // Check if already connected
        {
            let peers = peers.read().unwrap();
            if peers.contains_key(&addr) {
                return Ok(());
            }
        }
        
        // Check security
        if !security_manager.check_connection(addr)? {
            return Err(PaliError::security("Connection blocked by security manager"));
        }
        
        // Mark attempt
        {
            let mut addr_mgr = address_manager.write().unwrap();
            addr_mgr.mark_attempt(addr);
        }
        
        debug!("Attempting to connect to {}", addr);
        
        // Attempt connection
        let rate_limiter = Arc::new(Mutex::new(
            crate::network::RateLimiter::new()
        ));
        
        let mut client = match timeout(CONNECTION_TIMEOUT, SecureNetworkClient::connect(&addr.to_string(), rate_limiter)).await {
            Ok(Ok(client)) => client,
            Ok(Err(e)) => {
                let mut addr_mgr = address_manager.write().unwrap();
                addr_mgr.mark_failure(addr);
                return Err(e);
            }
            Err(_) => {
                let mut addr_mgr = address_manager.write().unwrap();
                addr_mgr.mark_failure(addr);
                return Err(PaliError::network("Connection timeout"));
            }
        };
        
        // Perform handshake
        let node_id = match timeout(CONNECTION_TIMEOUT, client.handshake("pali-node", 0)).await {
            Ok(Ok(id)) => id,
            Ok(Err(e)) => {
                let mut addr_mgr = address_manager.write().unwrap();
                addr_mgr.mark_failure(addr);
                return Err(e);
            }
            Err(_) => {
                let mut addr_mgr = address_manager.write().unwrap();
                addr_mgr.mark_failure(addr);
                return Err(PaliError::network("Handshake timeout"));
            }
        };
        
        // Create peer info
        let mut peer_info = PeerInfo::new(addr, true);
        peer_info.node_id = node_id;
        peer_info.state = ConnectionState::Active;
        
        // Store peer and connection
        {
            let mut peers = peers.write().unwrap();
            peers.insert(addr, peer_info);
        }
        
        {
            let mut connections = connections.write().unwrap();
            connections.insert(addr, client);
        }
        
        // Mark success
        {
            let mut addr_mgr = address_manager.write().unwrap();
            addr_mgr.mark_success(addr);
        }
        
        // Update stats
        {
            let mut stats = stats.write().unwrap();
            stats.outbound_connections += 1;
            stats.connected_peers += 1;
            stats.connection_attempts += 1;
        }
        
        info!("✅ Connected to peer {}", addr);
        Ok(())
    }
    
    async fn cleanup_stale_connections(
        peers: &Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        connections: &Arc<RwLock<HashMap<SocketAddr, SecureNetworkClient>>>,
    ) {
        let stale_peers: Vec<SocketAddr> = {
            let peers = peers.read().unwrap();
            peers.values()
                .filter(|peer| peer.is_stale() || peer.should_be_banned())
                .map(|peer| peer.addr)
                .collect()
        };
        
        for addr in stale_peers {
            warn!("Disconnecting stale/banned peer {}", addr);
            
            {
                let mut peers = peers.write().unwrap();
                peers.remove(&addr);
            }
            
            {
                let mut connections = connections.write().unwrap();
                connections.remove(&addr);
            }
        }
    }
    
    fn start_sync_manager(&mut self) {
        let blockchain = Arc::clone(&self.blockchain);
        let peers = Arc::clone(&self.peers);
        let connections = Arc::clone(&self.connections);
        let sync_state = Arc::clone(&self.sync_state);
        let is_running = Arc::clone(&self.is_running);
        
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            
            while is_running.load(Ordering::Relaxed) {
                rt.block_on(async {
                    let should_sync = {
                        let sync_state = sync_state.read().unwrap();
                        !sync_state.is_syncing
                    };
                    
                    if should_sync {
                        if let Err(e) = Self::check_and_start_sync(
                            &blockchain,
                            &peers,
                            &connections,
                            &sync_state,
                        ).await {
                            debug!("Sync check failed: {}", e);
                        }
                    } else {
                        // Check if sync is stuck
                        let is_stuck = {
                            let sync_state = sync_state.read().unwrap();
                            sync_state.is_stuck()
                        };
                        
                        if is_stuck {
                            warn!("Blockchain sync appears stuck, restarting...");
                            let mut sync_state = sync_state.write().unwrap();
                            sync_state.finish_sync();
                        }
                    }
                    
                    sleep(Duration::from_secs(10)).await;
                });
            }
        });
        
        self.task_handles.push(handle);
    }
    
    async fn check_and_start_sync(
        blockchain: &Arc<RwLock<Blockchain>>,
        peers: &Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        connections: &Arc<RwLock<HashMap<SocketAddr, SecureNetworkClient>>>,
        sync_state: &Arc<RwLock<SyncState>>,
    ) -> Result<()> {
        let our_height = {
            let blockchain = blockchain.read().unwrap();
            blockchain.get_best_block_height()
        };
        
        // Find the best peer to sync with
        let sync_peer = {
            let peers = peers.read().unwrap();
            peers.values()
                .filter(|peer| peer.state == ConnectionState::Active && peer.height > our_height)
                .max_by_key(|peer| peer.height)
                .map(|peer| (peer.addr, peer.height))
        };
        
        if let Some((peer_addr, peer_height)) = sync_peer {
            if peer_height > our_height + 1 {
                info!("Starting sync with {} (our height: {}, peer height: {})", peer_addr, our_height, peer_height);
                
                let mut sync_state = sync_state.write().unwrap();
                sync_state.start_sync(peer_addr, our_height, peer_height);
                
                // Request headers from peer
                if let Some(mut connection) = connections.write().unwrap().get_mut(&peer_addr) {
                    let get_headers = NetworkMessage::GetHeaders {
                        start_hash: {
                            let blockchain = blockchain.read().unwrap();
                            blockchain.get_best_block_hash()
                        },
                        end_hash: [0; 32], // Request all available
                        max_headers: 2000,
                    };
                    
                    let _ = connection.send_message(&get_headers).await;
                }
            }
        }
        
        Ok(())
    }
    
    fn start_message_relay(&mut self) {
        let peer_rx = self.peer_rx.resubscribe();
        let connections = Arc::clone(&self.connections);
        let peers = Arc::clone(&self.peers);
        let security_manager = Arc::clone(&self.security_manager);
        let is_running = Arc::clone(&self.is_running);
        
        let handle = thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().unwrap();
            
            rt.block_on(async {
                let mut rx = peer_rx;
                
                while is_running.load(Ordering::Relaxed) {
                    match rx.recv().await {
                        Ok(message) => {
                            Self::relay_message_to_peers(
                                &message,
                                &connections,
                                &peers,
                                &security_manager,
                            ).await;
                        }
                        Err(broadcast::error::RecvError::Lagged(_)) => {
                            warn!("Message relay lagged, some messages may have been dropped");
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            break;
                        }
                    }
                }
            });
        });
        
        self.task_handles.push(handle);
    }
    
    async fn relay_message_to_peers(
        message: &NetworkMessage,
        connections: &Arc<RwLock<HashMap<SocketAddr, SecureNetworkClient>>>,
        peers: &Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        security_manager: &Arc<SecurityManager>,
    ) {
        let eligible_peers: Vec<SocketAddr> = {
            let peers = peers.read().unwrap();
            peers.values()
                .filter(|peer| {
                    peer.state == ConnectionState::Active &&
                    peer.relay_transactions &&
                    !security_manager.is_banned(peer.addr.ip())
                })
                .map(|peer| peer.addr)
                .collect()
        };
        
        let relay_tasks: Vec<_> = eligible_peers.into_iter().map(|addr| {
            let message = message.clone();
            let connections = Arc::clone(connections);
            
            async move {
                if let Some(mut connection) = connections.write().unwrap().get_mut(&addr) {
                    if let Err(e) = connection.send_message(&message).await {
                        debug!("Failed to relay message to {}: {}", addr, e);
                    }
                }
            }
        }).collect();
        
        // Execute all relay tasks concurrently
        join_all(relay_tasks).await;
    }
    
    fn start_maintenance_tasks(&mut self) {
        let address_manager = Arc::clone(&self.address_manager);
        let peers = Arc::clone(&self.peers);
        let connections = Arc::clone(&self.connections);
        let stats = Arc::clone(&self.stats);
        let is_running = Arc::clone(&self.is_running);
        let start_time = Instant::now();
        
        let handle = thread::spawn(move || {
            while is_running.load(Ordering::Relaxed) {
                // Clean up expired bans
                {
                    let mut addr_mgr = address_manager.write().unwrap();
                    addr_mgr.cleanup_expired_bans();
                }
                
                // Send pings to peers
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    Self::send_pings_to_peers(&peers, &connections).await;
                });
                
                // Update statistics
                {
                    let mut stats = stats.write().unwrap();
                    stats.uptime = start_time.elapsed();
                    
                    let peers = peers.read().unwrap();
                    stats.connected_peers = peers.len();
                    stats.outbound_connections = peers.values().filter(|p| p.is_outbound).count();
                    stats.inbound_connections = peers.values().filter(|p| !p.is_outbound).count();
                }
                
                thread::sleep(Duration::from_secs(60));
            }
        });
        
        self.task_handles.push(handle);
    }
    
    async fn send_pings_to_peers(
        peers: &Arc<RwLock<HashMap<SocketAddr, PeerInfo>>>,
        connections: &Arc<RwLock<HashMap<SocketAddr, SecureNetworkClient>>>,
    ) {
        let peer_addrs: Vec<SocketAddr> = {
            let peers = peers.read().unwrap();
            peers.keys().cloned().collect()
        };
        
        for addr in peer_addrs {
            if let Some(mut connection) = connections.write().unwrap().get_mut(&addr) {
                if let Err(e) = connection.send_ping().await {
                    debug!("Failed to ping {}: {}", addr, e);
                }
            }
        }
    }
    
    fn start_command_processor(&mut self) {
        // This would be implemented to handle P2P commands
        // For now, we'll create a placeholder
        let is_running = Arc::clone(&self.is_running);
        
        let handle = thread::spawn(move || {
            while is_running.load(Ordering::Relaxed) {
                thread::sleep(Duration::from_secs(1));
                // Process commands from self.command_rx
            }
        });
        
        self.task_handles.push(handle);
    }
    
    async fn connect_to_initial_peers(&self) -> Result<()> {
        // Add some hardcoded seed nodes for initial connectivity
        let bootstrap_nodes = vec![
            "127.0.0.1:8333",
            "localhost:8334",
        ];
        
        for node in bootstrap_nodes {
            if let Ok(addr) = node.parse::<SocketAddr>() {
                let mut addr_mgr = self.address_manager.write().unwrap();
                addr_mgr.add_address(addr, AddressSource::Config);
            }
        }
        
        Ok(())
    }
    
    async fn disconnect_all_peers(&self) {
        let peer_addrs: Vec<SocketAddr> = {
            let peers = self.peers.read().unwrap();
            peers.keys().cloned().collect()
        };
        
        for addr in peer_addrs {
            info!("Disconnecting from peer {}", addr);
            
            {
                let mut peers = self.peers.write().unwrap();
                peers.remove(&addr);
            }
            
            {
                let mut connections = self.connections.write().unwrap();
                connections.remove(&addr);
            }
        }
    }
    
    pub fn get_stats(&self) -> P2PStats {
        self.stats.read().unwrap().clone()
    }
    
    pub fn get_connected_peers(&self) -> Vec<PeerInfo> {
        self.peers.read().unwrap().values().cloned().collect()
    }
    
    pub fn get_sync_state(&self) -> SyncState {
        self.sync_state.read().unwrap().clone()
    }
    
    pub async fn broadcast_transaction(&self, tx: Transaction) -> Result<()> {
        let message = NetworkMessage::NewTransaction {
            transaction: tx,
            priority: MessagePriority::Normal,
        };
        
        self.peer_tx.send(message)
            .map_err(|e| PaliError::network(format!("Failed to broadcast transaction: {}", e)))?;
        
        Ok(())
    }
    
    pub async fn broadcast_block(&self, block: Block) -> Result<()> {
        let message = NetworkMessage::NewBlock {
            block,
            priority: MessagePriority::High,
        };
        
        self.peer_tx.send(message)
            .map_err(|e| PaliError::network(format!("Failed to broadcast block: {}", e)))?;
        
        Ok(())
    }
}

impl P2PStats {
    pub fn new() -> Self {
        P2PStats {
            connected_peers: 0,
            outbound_connections: 0,
            inbound_connections: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            blocks_downloaded: 0,
            transactions_relayed: 0,
            connection_attempts: 0,
            failed_connections: 0,
            banned_peers: 0,
            uptime: Duration::new(0, 0),
        }
    }
}

// Additional helper implementations would be added here for SecureNetworkClient extensions

impl Drop for P2PNetwork {
    fn drop(&mut self) {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            self.stop().await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    
    #[test]
    fn test_peer_info_creation() {
        let addr = "127.0.0.1:8333".parse().unwrap();
        let peer = PeerInfo::new(addr, true);
        
        assert_eq!(peer.addr, addr);
        assert!(peer.is_outbound);
        assert_eq!(peer.state, ConnectionState::Connecting);
        assert!(!peer.is_stale());
    }
    
    #[test]
    fn test_sync_state() {
        let mut sync = SyncState::new();
        assert!(!sync.is_syncing);
        
        let peer_addr = "127.0.0.1:8333".parse().unwrap();
        sync.start_sync(peer_addr, 100, 200);
        
        assert!(sync.is_syncing);
        assert_eq!(sync.sync_peer, Some(peer_addr));
        assert_eq!(sync.start_height, 100);
        assert_eq!(sync.target_height, 200);
        
        sync.update_progress(150);
        assert_eq!(sync.current_height, 150);
        assert_eq!(sync.sync_progress(), 0.5);
        
        sync.finish_sync();
        assert!(!sync.is_syncing);
    }
    
    #[test]
    fn test_address_manager() {
        let mut addr_mgr = AddressManager::new(vec![]);
        let addr = "127.0.0.1:8333".parse().unwrap();
        
        addr_mgr.add_address(addr, AddressSource::ManualAdd);
        assert!(addr_mgr.known_addresses.contains_key(&addr));
        
        let addresses = addr_mgr.get_addresses_to_try(1);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0], addr);
        
        addr_mgr.mark_success(addr);
        assert!(addr_mgr.tried_addresses.contains_key(&addr));
        assert!(!addr_mgr.known_addresses.contains_key(&addr));
    }
    
    #[test]
    fn test_p2p_stats() {
        let stats = P2PStats::new();
        assert_eq!(stats.connected_peers, 0);
        assert_eq!(stats.uptime, Duration::new(0, 0));
    }
}
