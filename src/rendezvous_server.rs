use crate::common::*;
use crate::peer::*;
use hbb_common::{
    allow_err, bail,
    bytes::{Bytes, BytesMut},
    bytes_codec::BytesCodec,
    config,
    futures::future::join_all,
    futures_util::{
        sink::SinkExt,
        stream::{SplitSink, StreamExt},
    },
    log,
    protobuf::{Message as _, MessageField},
    rendezvous_proto::{
        register_pk_response::Result::{TOO_FREQUENT, UUID_MISMATCH},
        *,
    },
    tcp::{listen_any, FramedStream},
    timeout,
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{mpsc, Mutex},
        time::{interval, Duration},
    },
    tokio_util::codec::Framed,
    try_into_v4,
    udp::{is_sendable_udp_addr, FramedSocket},
    AddrMangle, ResultType,
};
use ipnetwork::Ipv4Network;
use sodiumoxide::crypto::sign;
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
    sync::Arc,
    time::Instant,
};

#[derive(Clone, Debug)]
enum Data {
    Msg(Box<RendezvousMessage>, SocketAddr),
    RelayServers0(String),
    RelayServers(RelayServers),
}

const REG_TIMEOUT: i32 = 30_000;
/// Errores de recepcion seguidos que hacen falta para dar el socket UDP por
/// muerto y recrearlo. Un solo error nunca alcanza.
const MAX_CONSECUTIVE_UDP_RECV_ERRORS: u32 = 10;
type TcpStreamSink = SplitSink<Framed<TcpStream, BytesCodec>, Bytes>;
type WsSink = SplitSink<tokio_tungstenite::WebSocketStream<TcpStream>, tungstenite::Message>;
enum Sink {
    TcpStream(TcpStreamSink),
    Ws(WsSink),
}
type Sender = mpsc::UnboundedSender<Data>;
type Receiver = mpsc::UnboundedReceiver<Data>;
static ROTATION_RELAY_SERVER: AtomicUsize = AtomicUsize::new(0);
static NEXT_WS_CONN: AtomicUsize = AtomicUsize::new(1);
type RelayServers = Vec<String>;
const CHECK_RELAY_TIMEOUT: u64 = 3_000;
static ALWAYS_USE_RELAY: AtomicBool = AtomicBool::new(false);

// Store punch hole requests
use once_cell::sync::Lazy;
use tokio::sync::Mutex as TokioMutex; // differentiate if needed
#[derive(Clone)]
struct PunchReqEntry { tm: Instant, from_ip: String, to_ip: String, to_id: String }
static PUNCH_REQS: Lazy<TokioMutex<Vec<PunchReqEntry>>> = Lazy::new(|| TokioMutex::new(Vec::new()));
const PUNCH_REQ_DEDUPE_SEC: u64 = 60;

#[derive(Clone)]
struct Inner {
    serial: i32,
    version: String,
    software_url: String,
    mask: Option<Ipv4Network>,
    local_ip: String,
    sk: Option<sign::SecretKey>,
}

#[derive(Clone)]
pub struct RendezvousServer {
    tcp_punch: Arc<Mutex<HashMap<SocketAddr, Sink>>>,
    ws_sinks: Arc<Mutex<HashMap<String, (usize, Sink)>>>,
    ws_conn_to_id: Arc<Mutex<HashMap<usize, String>>>,
    pm: PeerMap,
    tx: Sender,
    relay_servers: Arc<RelayServers>,
    relay_servers0: Arc<RelayServers>,
    rendezvous_servers: Arc<Vec<String>>,
    inner: Arc<Inner>,
}

enum LoopFailure {
    UdpSocket,
    Listener3,
    Listener2,
    Listener,
}

impl RendezvousServer {
    #[tokio::main(flavor = "multi_thread")]
    pub async fn start(port: i32, serial: i32, key: &str, rmem: usize) -> ResultType<()> {
        let (key, sk) = Self::get_server_sk(key);
        let nat_port = port - 1;
        let ws_port = port + 2;
        let pm = PeerMap::new().await?;
        log::info!("serial={}", serial);
        let rendezvous_servers = get_servers(&get_arg("rendezvous-servers"), "rendezvous-servers");
        log::info!("Listening on tcp/udp :{}", port);
        log::info!("Listening on tcp :{}, extra port for NAT test", nat_port);
        log::info!("Listening on websocket :{}", ws_port);
        let mut socket = create_udp_listener(port, rmem).await?;
        let (tx, mut rx) = mpsc::unbounded_channel::<Data>();
        let software_url = get_arg("software-url");
        let version = hbb_common::get_version_from_url(&software_url);
        if !version.is_empty() {
            log::info!("software_url: {}, version: {}", software_url, version);
        }
        let mask = get_arg("mask").parse().ok();
        let local_ip = if mask.is_none() {
            "".to_owned()
        } else {
            get_arg_or(
                "local-ip",
                local_ip_address::local_ip()
                    .map(|x| x.to_string())
                    .unwrap_or_default(),
            )
        };
        let mut rs = Self {
            tcp_punch: Arc::new(Mutex::new(HashMap::new())),
            ws_sinks: Arc::new(Mutex::new(HashMap::new())),
            ws_conn_to_id: Arc::new(Mutex::new(HashMap::new())),
            pm,
            tx: tx.clone(),
            relay_servers: Default::default(),
            relay_servers0: Default::default(),
            rendezvous_servers: Arc::new(rendezvous_servers),
            inner: Arc::new(Inner {
                serial,
                version,
                software_url,
                sk,
                mask,
                local_ip,
            }),
        };
        log::info!("mask: {:?}", rs.inner.mask);
        log::info!("local-ip: {:?}", rs.inner.local_ip);
        std::env::set_var("PORT_FOR_API", port.to_string());
        rs.parse_relay_servers(&get_arg("relay-servers"));
        let mut listener = create_tcp_listener(port).await?;
        let mut listener2 = create_tcp_listener(nat_port).await?;
        let mut listener3 = create_tcp_listener(ws_port).await?;
        let test_addr = std::env::var("TEST_HBBS").unwrap_or_default();
        if std::env::var("ALWAYS_USE_RELAY")
            .unwrap_or_default()
            .to_uppercase()
            == "Y"
        {
            ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
        }
        log::info!(
            "ALWAYS_USE_RELAY={}",
            if ALWAYS_USE_RELAY.load(Ordering::SeqCst) {
                "Y"
            } else {
                "N"
            }
        );
        if test_addr.to_lowercase() != "no" {
            let test_addr = if test_addr.is_empty() {
                listener.local_addr()?
            } else {
                test_addr.parse()?
            };
            tokio::spawn(async move {
                if let Err(err) = test_hbbs(test_addr).await {
                    if test_addr.is_ipv6() && test_addr.ip().is_unspecified() {
                        let mut test_addr = test_addr;
                        test_addr.set_ip(IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                        if let Err(err) = test_hbbs(test_addr).await {
                            log::error!("Failed to run hbbs test with {test_addr}: {err}");
                            std::process::exit(1);
                        }
                    } else {
                        log::error!("Failed to run hbbs test with {test_addr}: {err}");
                        std::process::exit(1);
                    }
                }
            });
        };
        let main_task = async move {
            loop {
                log::info!("Start");
                match rs
                    .io_loop(
                        &mut rx,
                        &mut listener,
                        &mut listener2,
                        &mut listener3,
                        &mut socket,
                        &key,
                    )
                    .await
                {
                    LoopFailure::UdpSocket => {
                        drop(socket);
                        socket = create_udp_listener(port, rmem).await?;
                    }
                    LoopFailure::Listener => {
                        drop(listener);
                        listener = create_tcp_listener(port).await?;
                    }
                    LoopFailure::Listener2 => {
                        drop(listener2);
                        listener2 = create_tcp_listener(nat_port).await?;
                    }
                    LoopFailure::Listener3 => {
                        drop(listener3);
                        listener3 = create_tcp_listener(ws_port).await?;
                    }
                }
            }
        };
        let listen_signal = listen_signal();
        tokio::select!(
            res = main_task => res,
            res = listen_signal => res,
        )
    }

    async fn io_loop(
        &mut self,
        rx: &mut Receiver,
        listener: &mut TcpListener,
        listener2: &mut TcpListener,
        listener3: &mut TcpListener,
        socket: &mut FramedSocket,
        key: &str,
    ) -> LoopFailure {
        let mut timer_check_relay = interval(Duration::from_millis(CHECK_RELAY_TIMEOUT));
        // Un datagrama que falla no es motivo para recrear el socket: recrearlo
        // corta la senializacion de toda la flota. Solo una racha de errores de
        // recepcion indica que el socket en si murio.
        let mut recv_errors: u32 = 0;
        loop {
            tokio::select! {
                _ = timer_check_relay.tick() => {
                    if self.relay_servers0.len() > 1 {
                        let rs = self.relay_servers0.clone();
                        let tx = self.tx.clone();
                        tokio::spawn(async move {
                            check_relay_servers(rs, tx).await;
                        });
                    }
                }
                Some(data) = rx.recv() => {
                    match data {
                        Data::Msg(msg, addr) => {
                            send_udp_to_peer(socket, msg.as_ref(), addr, "senializacion").await;
                        }
                        Data::RelayServers0(rs) => { self.parse_relay_servers(&rs); }
                        Data::RelayServers(rs) => { self.relay_servers = Arc::new(rs); }
                    }
                }
                res = socket.next() => {
                    match res {
                        Some(Ok((bytes, addr))) => {
                            recv_errors = 0;
                            let addr: SocketAddr = addr.into();
                            // Un fallo manejando un datagrama (incluido un envio
                            // que no sale) se registra y se sigue: el loop UDP es
                            // la senializacion de toda la flota y no puede caerse
                            // por un paquete suelto.
                            if let Err(err) = self.handle_udp(&bytes, addr, socket, key).await {
                                log::error!("udp handling failed for {}: {}", addr, err);
                            }
                        }
                        Some(Err(err)) => {
                            recv_errors += 1;
                            log::error!(
                                "udp recv failure ({}/{}): {}",
                                recv_errors,
                                MAX_CONSECUTIVE_UDP_RECV_ERRORS,
                                err
                            );
                            if recv_errors >= MAX_CONSECUTIVE_UDP_RECV_ERRORS {
                                log::error!("demasiados errores de recepcion seguidos, se recrea el socket udp");
                                return LoopFailure::UdpSocket;
                            }
                        }
                        None => {
                            // unreachable!() ?
                        }
                    }
                }
                res = listener2.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener2(stream, addr).await;
                        }
                        Err(err) => {
                           log::error!("listener2.accept failed: {}", err);
                           return LoopFailure::Listener2;
                        }
                    }
                }
                res = listener3.accept() => {
                    match res {
                        Ok((stream, addr))  => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, true).await;
                        }
                        Err(err) => {
                           log::error!("listener3.accept failed: {}", err);
                           return LoopFailure::Listener3;
                        }
                    }
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, addr)) => {
                            stream.set_nodelay(true).ok();
                            self.handle_listener(stream, addr, key, false).await;
                        }
                       Err(err) => {
                           log::error!("listener.accept failed: {}", err);
                           return LoopFailure::Listener;
                       }
                    }
                }
            }
        }
    }

    #[inline]
    async fn handle_udp(
        &mut self,
        bytes: &BytesMut,
        addr: SocketAddr,
        socket: &mut FramedSocket,
        key: &str,
    ) -> ResultType<()> {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            match msg_in.union {
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    // B registered
                    if !rp.id.is_empty() {
                        log::trace!("New peer registered: {:?} {:?}", &rp.id, &addr);
                        self.update_addr(rp.id, addr, socket).await?;
                        if self.inner.serial > rp.serial {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_configure_update(ConfigUpdate {
                                serial: self.inner.serial,
                                rendezvous_servers: (*self.rendezvous_servers).clone(),
                                ..Default::default()
                            });
                            socket.send(&msg_out, addr).await?;
                        }
                    }
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return Ok(());
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 {
                        return send_rk_res(socket, addr, UUID_MISMATCH).await;
                    } else if !self.check_ip_blocker(&ip, &id).await {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    let peer = self.pm.get_or(&id).await;
                    let (changed, ip_changed) = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            (true, false)
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    log::warn!(
                                        "Peer {} ip/pk mismatch: {}/{:?} vs {}/{:?}",
                                        id,
                                        ip,
                                        rk.pk,
                                        peer.info.ip,
                                        peer.pk,
                                    );
                                    drop(peer);
                                    return send_rk_res(socket, addr, UUID_MISMATCH).await;
                                }
                            } else {
                                log::warn!(
                                    "Peer {} uuid mismatch: {:?} vs {:?}",
                                    id,
                                    rk.uuid,
                                    peer.uuid
                                );
                                drop(peer);
                                return send_rk_res(socket, addr, UUID_MISMATCH).await;
                            }
                            let ip_changed = peer.info.ip != ip;
                            (
                                peer.uuid != rk.uuid || peer.pk != rk.pk || ip_changed,
                                ip_changed,
                            )
                        }
                    };
                    let mut req_pk = peer.read().await.reg_pk;
                    if req_pk.1.elapsed().as_secs() > 6 {
                        req_pk.0 = 0;
                    } else if req_pk.0 > 2 {
                        return send_rk_res(socket, addr, TOO_FREQUENT).await;
                    }
                    req_pk.0 += 1;
                    req_pk.1 = Instant::now();
                    peer.write().await.reg_pk = req_pk;
                    if ip_changed {
                        let mut lock = IP_CHANGES.lock().await;
                        if let Some((tm, ips)) = lock.get_mut(&id) {
                            if tm.elapsed().as_secs() > IP_CHANGE_DUR {
                                *tm = Instant::now();
                                ips.clear();
                                ips.insert(ip.clone(), 1);
                            } else if let Some(v) = ips.get_mut(&ip) {
                                *v += 1;
                            } else {
                                ips.insert(ip.clone(), 1);
                            }
                        } else {
                            lock.insert(
                                id.clone(),
                                (Instant::now(), HashMap::from([(ip.clone(), 1)])),
                            );
                        }
                    }
                    if changed {
                        self.pm.update_pk(id, peer, addr, rk.uuid, rk.pk, ip).await;
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: register_pk_response::Result::OK.into(),
                        ..Default::default()
                    });
                    socket.send(&msg_out, addr).await?
                }
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    if self.pm.is_in_memory(&ph.id).await {
                        self.handle_udp_punch_hole_request(addr, ph, key).await?;
                    } else {
                        // not in memory, fetch from db with spawn in case blocking me
                        let mut me = self.clone();
                        let key = key.to_owned();
                        tokio::spawn(async move {
                            allow_err!(me.handle_udp_punch_hole_request(addr, ph, &key).await);
                        });
                    }
                }
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    self.handle_hole_sent(phs, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    self.handle_local_addr(la, addr, Some(socket)).await?;
                }
                Some(rendezvous_message::Union::ConfigureUpdate(mut cu)) => {
                    if try_into_v4(addr).ip().is_loopback() && cu.serial > self.inner.serial {
                        let mut inner: Inner = (*self.inner).clone();
                        inner.serial = cu.serial;
                        self.inner = Arc::new(inner);
                        self.rendezvous_servers = Arc::new(
                            cu.rendezvous_servers
                                .drain(..)
                                .filter(|x| {
                                    !x.is_empty()
                                        && test_if_valid_server(x, "rendezvous-server").is_ok()
                                })
                                .collect(),
                        );
                        log::info!(
                            "configure updated: serial={} rendezvous-servers={:?}",
                            self.inner.serial,
                            self.rendezvous_servers
                        );
                    }
                }
                Some(rendezvous_message::Union::SoftwareUpdate(su)) => {
                    if !self.inner.version.is_empty() && su.url != self.inner.version {
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_software_update(SoftwareUpdate {
                            url: self.inner.software_url.clone(),
                            ..Default::default()
                        });
                        socket.send(&msg_out, addr).await?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    #[inline]
    async fn handle_tcp(
        &mut self,
        bytes: &[u8],
        sink: &mut Option<Sink>,
        addr: SocketAddr,
        key: &str,
        ws: bool,
        conn_serial: usize,
    ) -> bool {
        if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(bytes) {
            if ws {
                let id_opt = self
                    .ws_conn_to_id
                    .lock()
                    .await
                    .get(&conn_serial)
                    .cloned();
                if let Some(id) = id_opt {
                    self.pm.touch_by_id(&id).await;
                }
            }
            match msg_in.union {
                Some(rendezvous_message::Union::PunchHoleRequest(ph)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    allow_err!(self.handle_tcp_punch_hole_request(addr, ph, key, ws).await);
                    return true;
                }
                Some(rendezvous_message::Union::RequestRelay(mut rf)) => {
                    // there maybe several attempt, so sink can be none
                    if let Some(sink) = sink.take() {
                        self.tcp_punch.lock().await.insert(try_into_v4(addr), sink);
                    }
                    if let Some(peer) = self.pm.get_in_memory(&rf.id).await {
                        let peer_id = rf.id.clone();
                        let mut msg_out = RendezvousMessage::new();
                        rf.socket_addr = AddrMangle::encode(addr).into();
                        msg_out.set_request_relay(rf);
                        let (peer_addr, peer_ws_addr) = {
                            let r = peer.read().await;
                            (r.socket_addr, r.ws_addr)
                        };
                        if peer_ws_addr.is_some() {
                            self.send_to_ws_id(&peer_id, msg_out).await;
                        } else {
                            self.tx.send(Data::Msg(msg_out.into(), peer_addr)).ok();
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RelayResponse(mut rr)) => {
                    let addr_b = AddrMangle::decode(&rr.socket_addr);
                    rr.socket_addr = Default::default();
                    let id = rr.id();
                    if !id.is_empty() {
                        let pk = self.get_pk(&rr.version, id.to_owned()).await;
                        rr.set_pk(pk);
                    }
                    let mut msg_out = RendezvousMessage::new();
                    if !rr.relay_server.is_empty() {
                        if self.is_lan(addr_b) {
                            // https://github.com/rustdesk/rustdesk-server/issues/24
                            rr.relay_server = self.inner.local_ip.clone();
                        } else if rr.relay_server == self.inner.local_ip {
                            rr.relay_server = self.get_relay_server(addr.ip(), addr_b.ip());
                        }
                    }
                    rr.relay_server = relay_para_visor(&rr.relay_server);
                    msg_out.set_relay_response(rr);
                    allow_err!(self.send_to_tcp_sync(msg_out, addr_b).await);
                }
                // El agente abre un socket nuevo contra la central por cada
                // intento de conexion (rendezvous_mediator.rs, handle_punch_hole
                // y handle_intranet_): manda `PunchHoleSent` / `LocalAddr` por
                // ese socket y acto seguido se lo entrega a `accept_connection`
                // para montar la sesion encima. Sin `return true` estos brazos
                // caian al final de la funcion devolviendo `false`, y el loop de
                // `handle_listener_inner` hacia `break`, cerrando el socket sin
                // close handshake justo cuando el agente empezaba a usarlo. Del
                // otro lado eso se veia como "Connection reset without closing
                // handshake" en cada intento de conexion directa.
                //
                // No quedan conexiones colgadas: el loop ya corta solo por
                // inactividad (15s en WebSocket, 30s en TCP) y `ping_ws_conn`
                // devuelve `false` para un socket que nunca se registro, que
                // tambien termina en `break`.
                Some(rendezvous_message::Union::PunchHoleSent(phs)) => {
                    allow_err!(self.handle_hole_sent(phs, addr, None).await);
                    return true;
                }
                Some(rendezvous_message::Union::LocalAddr(la)) => {
                    allow_err!(self.handle_local_addr(la, addr, None).await);
                    return true;
                }
                Some(rendezvous_message::Union::TestNatRequest(tar)) => {
                    let mut msg_out = RendezvousMessage::new();
                    let mut res = TestNatResponse {
                        port: addr.port() as _,
                        ..Default::default()
                    };
                    if self.inner.serial > tar.serial {
                        let mut cu = ConfigUpdate::new();
                        cu.serial = self.inner.serial;
                        cu.rendezvous_servers = (*self.rendezvous_servers).clone();
                        res.cu = MessageField::from_option(Some(cu));
                    }
                    msg_out.set_test_nat_response(res);
                    Self::send_to_sink(sink, msg_out).await;
                }
                Some(rendezvous_message::Union::RegisterPeer(rp)) => {
                    if !rp.id.is_empty() {
                        if ws {
                            let id = rp.id.clone();
                            if let Some(s) = sink.take() {
                                self.ws_sinks
                                    .lock()
                                    .await
                                    .insert(id.clone(), (conn_serial, s));
                            }
                            self.ws_conn_to_id
                                .lock()
                                .await
                                .insert(conn_serial, id.clone());
                            self.update_addr_sink_ws(id, addr).await;
                        } else {
                            self.update_addr_sink(rp.id, addr, sink).await;
                        }
                    }
                    return true;
                }
                Some(rendezvous_message::Union::RegisterPk(rk)) => {
                    if rk.uuid.is_empty() || rk.pk.is_empty() {
                        return true;
                    }
                    let id = rk.id;
                    let ip = addr.ip().to_string();
                    if id.len() < 6 {
                        Self::send_rk_res_sink(sink, UUID_MISMATCH).await;
                        return true;
                    } else if !self.check_ip_blocker(&ip, &id).await {
                        Self::send_rk_res_sink(sink, TOO_FREQUENT).await;
                        return true;
                    }
                    let peer = self.pm.get_or(&id).await;
                    let changed = {
                        let peer = peer.read().await;
                        if peer.uuid.is_empty() {
                            true
                        } else {
                            if peer.uuid == rk.uuid {
                                if peer.info.ip != ip && peer.pk != rk.pk {
                                    drop(peer);
                                    Self::send_rk_res_sink(sink, UUID_MISMATCH).await;
                                    return true;
                                }
                            } else {
                                drop(peer);
                                Self::send_rk_res_sink(sink, UUID_MISMATCH).await;
                                return true;
                            }
                            peer.uuid != rk.uuid || peer.pk != rk.pk || peer.info.ip != ip
                        }
                    };
                    let mut req_pk = peer.read().await.reg_pk;
                    if req_pk.1.elapsed().as_secs() > 6 {
                        req_pk.0 = 0;
                    } else if req_pk.0 > 2 {
                        Self::send_rk_res_sink(sink, TOO_FREQUENT).await;
                        return true;
                    }
                    req_pk.0 += 1;
                    req_pk.1 = Instant::now();
                    peer.write().await.reg_pk = req_pk;
                    if changed {
                        self.pm
                            .update_pk(id.clone(), peer.clone(), addr, rk.uuid, rk.pk, ip)
                            .await;
                    }
                    if ws {
                        if let Some(s) = sink.take() {
                            self.ws_sinks
                                .lock()
                                .await
                                .insert(id.clone(), (conn_serial, s));
                        }
                        self.ws_conn_to_id
                            .lock()
                            .await
                            .insert(conn_serial, id.clone());
                        {
                            let mut w = peer.write().await;
                            w.ws_addr = Some(try_into_v4(addr));
                            w.last_reg_time = Instant::now();
                        }
                        log::info!("WS peer registrado y alcanzable: {} serial={}", id, conn_serial);
                        let mut msg_out = RendezvousMessage::new();
                        msg_out.set_register_pk_response(RegisterPkResponse {
                            result: register_pk_response::Result::OK.into(),
                            ..Default::default()
                        });
                        self.send_to_ws_id(&id, msg_out).await;
                        return true;
                    }
                    let mut msg_out = RendezvousMessage::new();
                    msg_out.set_register_pk_response(RegisterPkResponse {
                        result: register_pk_response::Result::OK.into(),
                        ..Default::default()
                    });
                    Self::send_to_sink(sink, msg_out).await;
                    return true;
                }
                _ => {}
            }
        }
        false
    }

    #[inline]
    async fn update_addr(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        socket: &mut FramedSocket,
    ) -> ResultType<()> {
        let (request_pk, ip_change) = if let Some(old) = self.pm.get_in_memory(&id).await {
            let mut old = old.write().await;
            let ip = socket_addr.ip();
            let ip_change = if old.socket_addr.port() != 0 {
                ip != old.socket_addr.ip()
            } else {
                ip.to_string() != old.info.ip
            } && !ip.is_loopback();
            let request_pk = old.pk.is_empty() || ip_change;
            if !request_pk {
                old.socket_addr = socket_addr;
                old.last_reg_time = Instant::now();
            }
            // El peer esta hablando por UDP: ya no es alcanzable por WS.
            // Si no se limpia, un peer que alguna vez uso WS queda marcado
            // para siempre y se lo sigue mandando por relay.
            if old.ws_addr.is_some() {
                log::info!("{} volvio a registrarse por UDP, se limpia ws_addr", id);
                old.ws_addr = None;
            }
            let ip_change = if ip_change && old.reg_pk.0 <= 2 {
                Some(if old.socket_addr.port() == 0 {
                    old.info.ip.clone()
                } else {
                    old.socket_addr.to_string()
                })
            } else {
                None
            };
            (request_pk, ip_change)
        } else {
            (true, None)
        };
        if let Some(old) = ip_change {
            log::info!("IP change of {} from {} to {}", id, old, socket_addr);
        }
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        socket.send(&msg_out, socket_addr).await
    }

    async fn update_addr_sink_ws(&mut self, id: String, socket_addr: SocketAddr) {
        let peer = self.pm.get_or(&id).await;
        let request_pk = {
            let mut w = peer.write().await;
            let ip = socket_addr.ip();
            let ip_change = if w.socket_addr.port() != 0 {
                ip != w.socket_addr.ip()
            } else {
                ip.to_string() != w.info.ip
            } && !ip.is_loopback();
            let request_pk = w.pk.is_empty() || ip_change;
            if !request_pk {
                w.socket_addr = socket_addr;
                w.last_reg_time = Instant::now();
            }
            w.ws_addr = Some(try_into_v4(socket_addr));
            request_pk
        };
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        self.send_to_ws_id(&id, msg_out).await;
    }

    async fn send_to_ws_id(&self, id: &str, msg: RendezvousMessage) {
        let mut map = self.ws_sinks.lock().await;
        if let Some((_, s)) = map.get_mut(id) {
            if let Ok(bytes) = msg.write_to_bytes() {
                let ok = match s {
                    Sink::TcpStream(st) => st.send(Bytes::from(bytes)).await.is_ok(),
                    Sink::Ws(ws) => ws.send(tungstenite::Message::Binary(bytes)).await.is_ok(),
                };
                if !ok {
                    map.remove(id);
                }
            }
        }
    }

    async fn ping_ws_conn(&self, conn_serial: usize) -> bool {
        let id_opt = self
            .ws_conn_to_id
            .lock()
            .await
            .get(&conn_serial)
            .cloned();
        let Some(id) = id_opt else {
            return false;
        };
        let mut map = self.ws_sinks.lock().await;
        match map.get_mut(&id) {
            Some((serial, s)) if *serial == conn_serial => {
                let ok = match s {
                    Sink::TcpStream(st) => st.send(Bytes::new()).await.is_ok(),
                    Sink::Ws(ws) => {
                        ws.send(tungstenite::Message::Binary(Vec::new())).await.is_ok()
                    }
                };
                if !ok {
                    map.remove(&id);
                }
                ok
            }
            _ => false,
        }
    }

    async fn update_addr_sink(
        &mut self,
        id: String,
        socket_addr: SocketAddr,
        sink: &mut Option<Sink>,
    ) {
        let peer = self.pm.get_or(&id).await;
        let request_pk = {
            let mut w = peer.write().await;
            let ip = socket_addr.ip();
            let ip_change = if w.socket_addr.port() != 0 {
                ip != w.socket_addr.ip()
            } else {
                ip.to_string() != w.info.ip
            } && !ip.is_loopback();
            let request_pk = w.pk.is_empty() || ip_change;
            if !request_pk {
                w.socket_addr = socket_addr;
                w.last_reg_time = Instant::now();
            }
            w.ws_addr = Some(try_into_v4(socket_addr));
            request_pk
        };
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_peer_response(RegisterPeerResponse {
            request_pk,
            ..Default::default()
        });
        Self::send_to_sink(sink, msg_out).await;
    }

    #[inline]
    async fn handle_hole_sent<'a>(
        &mut self,
        phs: PunchHoleSent,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // punch hole sent from B, tell A that B is ready to be connected
        let addr_a = AddrMangle::decode(&phs.socket_addr);
        log::debug!(
            "{} punch hole response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: AddrMangle::encode(addr).into(),
            pk: self.get_pk(&phs.version, phs.id).await,
            relay_server: relay_para_visor(&phs.relay_server),
            ..Default::default()
        };
        if let Ok(t) = phs.nat_type.enum_value() {
            p.set_nat_type(t);
        }
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            // addr_a sale de AddrMangle::decode sobre bytes que manda el par: si
            // vienen vacios o corruptos se decodifica basura, puerto 0 incluido.
            send_udp_to_peer(socket, &msg_out, addr_a, "punch hole response").await;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_local_addr<'a>(
        &mut self,
        la: LocalAddr,
        addr: SocketAddr,
        socket: Option<&'a mut FramedSocket>,
    ) -> ResultType<()> {
        // relay local addrs of B to A
        let addr_a = AddrMangle::decode(&la.socket_addr);
        log::debug!(
            "{} local addrs response to {:?} from {:?}",
            if socket.is_none() { "TCP" } else { "UDP" },
            &addr_a,
            &addr
        );
        let mut msg_out = RendezvousMessage::new();
        let mut p = PunchHoleResponse {
            socket_addr: la.local_addr.clone(),
            pk: self.get_pk(&la.version, la.id).await,
            relay_server: relay_para_visor(&la.relay_server),
            ..Default::default()
        };
        p.set_is_local(true);
        msg_out.set_punch_hole_response(p);
        if let Some(socket) = socket {
            send_udp_to_peer(socket, &msg_out, addr_a, "local addrs response").await;
        } else {
            self.send_to_tcp(msg_out, addr_a).await;
        }
        Ok(())
    }

    #[inline]
    async fn handle_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        _ws: bool,
    ) -> ResultType<(RendezvousMessage, Option<SocketAddr>)> {
        let mut ph = ph;
        if !key.is_empty() && ph.licence_key != key {
            log::warn!("Authentication failed from {} for peer {} - invalid key", addr, ph.id);
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::LICENSE_MISMATCH.into(),
                ..Default::default()
            });
            return Ok((msg_out, None));
        }
        let id = ph.id;
        // punch hole request from A, relay to B,
        // check if in same intranet first,
        // fetch local addrs if in same intranet.
        // because punch hole won't work if in the same intranet,
        // all routers will drop such self-connections.
        if let Some(peer) = self.pm.get(&id).await {
            let (elapsed, peer_addr, peer_ws_addr) = {
                let r = peer.read().await;
                (r.last_reg_time.elapsed().as_millis() as i32, r.socket_addr, r.ws_addr)
            };
            log::info!(
                "punch hole para {}: elapsed={}ms ws_addr={:?}",
                id,
                elapsed,
                peer_ws_addr
            );
            if peer_ws_addr.is_none() && !is_udp_peer_addr(&peer_addr) {
                // El par figura vivo pero no tiene por donde recibir: sin
                // WebSocket y con una direccion UDP inservible (tipico de un
                // agente que entro por WS sin X-Real-Port y despues perdio la
                // conexion, o de un par recien traido de la base). Se sigue igual:
                // el envio se descarta mas adelante y la sesion cae a relay.
                log::warn!(
                    "punch hole para {}: sin ws_addr y con socket_addr inservible ({}), no hay camino UDP",
                    id,
                    peer_addr
                );
            }
            if elapsed >= REG_TIMEOUT {
                let mut msg_out = RendezvousMessage::new();
                msg_out.set_punch_hole_response(PunchHoleResponse {
                    failure: punch_hole_response::Failure::OFFLINE.into(),
                    ..Default::default()
                });
                return Ok((msg_out, None));
            }
            
            // record punch hole request (from addr -> peer id/peer_addr)
            {
                let from_ip = try_into_v4(addr).ip().to_string();
                let to_ip = try_into_v4(peer_addr).ip().to_string();
                let to_id_clone = id.clone();
                let mut lock = PUNCH_REQS.lock().await;
                let mut dup = false;
                for e in lock.iter().rev().take(30) { // only check recent tail subset for speed
                    if e.from_ip == from_ip && e.to_id == to_id_clone {
                        if e.tm.elapsed().as_secs() < PUNCH_REQ_DEDUPE_SEC { dup = true; }
                        break;
                    }
                }
                if !dup { lock.push(PunchReqEntry { tm: Instant::now(), from_ip, to_ip, to_id: to_id_clone }); }
            }

            let mut msg_out = RendezvousMessage::new();
            let Topology {
                peer_eff,
                my_eff,
                peer_is_lan,
                is_lan,
                same_intranet,
            } = topology(self.inner.mask.as_ref(), peer_addr, peer_ws_addr, addr);
            let mut relay_server = self.get_relay_server(my_eff.ip(), peer_eff.ip());
            // El canal de senializacion (WebSocket o UDP/TCP) no debe decidir si se
            // intenta conexion directa: solo se fuerza relay si el NAT real es
            // simetrico (ph.nat_type ya viene del viewer), si el cliente lo pide
            // explicitamente con force_relay, o si el server esta en modo relay-only.
            let force_relay = ph.force_relay;
            let forzando_relay =
                ALWAYS_USE_RELAY.load(Ordering::SeqCst) || (peer_is_lan ^ is_lan) || force_relay;
            if forzando_relay {
                if peer_is_lan {
                    // https://github.com/rustdesk/rustdesk-server/issues/24
                    relay_server = self.inner.local_ip.clone()
                }
                ph.nat_type = NatType::SYMMETRIC.into(); // will force relay
            }
            let socket_addr = AddrMangle::encode(addr).into();
            // `same_intranet` nunca pisa un relay pedido explicitamente. Antes de
            // este cambio `same_intranet` era inalcanzable, asi que `force_relay`
            // y ALWAYS_USE_RELAY ganaban siempre; se mantiene ese contrato.
            if same_intranet && !forzando_relay {
                log::info!(
                    "punch hole para {}: misma intranet ({} <-> {}), pido FetchLocalAddr",
                    id,
                    peer_eff,
                    my_eff
                );
                msg_out.set_fetch_local_addr(FetchLocalAddr {
                    socket_addr,
                    relay_server,
                    ..Default::default()
                });
            } else {
                log::debug!(
                    "Punch hole {:?} {:?} request from {:?}",
                    id,
                    peer_addr,
                    addr
                );
                msg_out.set_punch_hole(PunchHole {
                    socket_addr,
                    nat_type: ph.nat_type,
                    relay_server,
                    // Se propagan tal cual vienen del viewer. Un viewer viejo no los
                    // manda: quedan en 0 / vacio y el agente se comporta como hoy.
                    udp_port: ph.udp_port,
                    force_relay: ph.force_relay,
                    socket_addr_v6: ph.socket_addr_v6,
                    ..Default::default()
                });
            }
            Ok((msg_out, Some(peer_ws_addr.unwrap_or(peer_addr))))
        } else {
            let mut msg_out = RendezvousMessage::new();
            msg_out.set_punch_hole_response(PunchHoleResponse {
                failure: punch_hole_response::Failure::ID_NOT_EXIST.into(),
                ..Default::default()
            });
            Ok((msg_out, None))
        }
    }

    #[inline]
    async fn handle_online_request(
        &mut self,
        stream: &mut FramedStream,
        peers: Vec<String>,
    ) -> ResultType<()> {
        let mut states = BytesMut::zeroed((peers.len() + 7) / 8);
        for (i, peer_id) in peers.iter().enumerate() {
            if let Some(peer) = self.pm.get_in_memory(peer_id).await {
                let elapsed = peer.read().await.last_reg_time.elapsed().as_millis() as i32;
                // bytes index from left to right
                let states_idx = i / 8;
                let bit_idx = 7 - i % 8;
                if elapsed < REG_TIMEOUT {
                    states[states_idx] |= 0x01 << bit_idx;
                }
            }
        }

        let mut msg_out = RendezvousMessage::new();
        msg_out.set_online_response(OnlineResponse {
            states: states.into(),
            ..Default::default()
        });
        stream.send(&msg_out).await?;

        Ok(())
    }

    #[inline]
    async fn send_to_tcp(&mut self, msg: RendezvousMessage, addr: SocketAddr) {
        let mut tcp = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        tokio::spawn(async move {
            Self::send_to_sink(&mut tcp, msg).await;
        });
    }

    #[inline]
    async fn send_to_sink(sink: &mut Option<Sink>, msg: RendezvousMessage) {
        if let Some(sink) = sink.as_mut() {
            if let Ok(bytes) = msg.write_to_bytes() {
                match sink {
                    Sink::TcpStream(s) => {
                        allow_err!(s.send(Bytes::from(bytes)).await);
                    }
                    Sink::Ws(ws) => {
                        allow_err!(ws.send(tungstenite::Message::Binary(bytes)).await);
                    }
                }
            }
        }
    }

    async fn send_rk_res_sink(sink: &mut Option<Sink>, res: register_pk_response::Result) {
        let mut msg_out = RendezvousMessage::new();
        msg_out.set_register_pk_response(RegisterPkResponse {
            result: res.into(),
            ..Default::default()
        });
        Self::send_to_sink(sink, msg_out).await;
    }

    async fn send_ws_ping(sink: &mut Option<Sink>) {
        if let Some(sink) = sink.as_mut() {
            match sink {
                Sink::TcpStream(s) => {
                    let _ = s.send(Bytes::new()).await;
                }
                Sink::Ws(ws) => {
                    let _ = ws.send(tungstenite::Message::Binary(Vec::new())).await;
                }
            }
        }
    }

    #[inline]
    async fn send_to_tcp_sync(
        &mut self,
        msg: RendezvousMessage,
        addr: SocketAddr,
    ) -> ResultType<()> {
        let mut sink = self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        Self::send_to_sink(&mut sink, msg).await;
        Ok(())
    }

    #[inline]
    async fn handle_tcp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let id = ph.id.clone();
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, ws).await?;
        if let Some(to) = to_addr {
            let peer_is_ws = if let Some(p) = self.pm.get_in_memory(&id).await {
                p.read().await.ws_addr.is_some()
            } else {
                false
            };
            if peer_is_ws {
                self.send_to_ws_id(&id, msg).await;
            } else {
                self.tx.send(Data::Msg(msg.into(), to))?;
            }
        } else {
            self.send_to_tcp_sync(msg, addr).await?;
        }
        Ok(())
    }

    #[inline]
    async fn handle_udp_punch_hole_request(
        &mut self,
        addr: SocketAddr,
        ph: PunchHoleRequest,
        key: &str,
    ) -> ResultType<()> {
        let (msg, to_addr) = self.handle_punch_hole_request(addr, ph, key, false).await?;
        self.tx.send(Data::Msg(
            msg.into(),
            match to_addr {
                Some(addr) => addr,
                None => addr,
            },
        ))?;
        Ok(())
    }

    async fn check_ip_blocker(&self, ip: &str, id: &str) -> bool {
        let mut lock = IP_BLOCKER.lock().await;
        let now = Instant::now();
        if let Some(old) = lock.get_mut(ip) {
            let counter = &mut old.0;
            if counter.1.elapsed().as_secs() > IP_BLOCK_DUR {
                counter.0 = 0;
            } else if counter.0 > 30 {
                return false;
            }
            counter.0 += 1;
            counter.1 = now;

            let counter = &mut old.1;
            let is_new = counter.0.get(id).is_none();
            if counter.1.elapsed().as_secs() > DAY_SECONDS {
                counter.0.clear();
            } else if counter.0.len() > 300 {
                return !is_new;
            }
            if is_new {
                counter.0.insert(id.to_owned());
            }
            counter.1 = now;
        } else {
            lock.insert(ip.to_owned(), ((0, now), (Default::default(), now)));
        }
        true
    }

    fn parse_relay_servers(&mut self, relay_servers: &str) {
        let rs = get_servers(relay_servers, "relay-servers");
        self.relay_servers0 = Arc::new(rs);
        self.relay_servers = self.relay_servers0.clone();
    }

    fn get_relay_server(&self, _pa: IpAddr, _pb: IpAddr) -> String {
        if self.relay_servers.is_empty() {
            return "".to_owned();
        } else if self.relay_servers.len() == 1 {
            return self.relay_servers[0].clone();
        }
        let i = ROTATION_RELAY_SERVER.fetch_add(1, Ordering::SeqCst) % self.relay_servers.len();
        self.relay_servers[i].clone()
    }

    async fn check_cmd(&self, cmd: &str) -> String {
        use std::fmt::Write as _;

        let mut res = "".to_owned();
        let mut fds = cmd.trim().split(' ');
        match fds.next() {
            Some("h") => {
                res = format!(
                    "{}\n{}\n{}\n{}\n{}\n{}\n{}\n",
                    "relay-servers(rs) <separated by ,>",
                    "reload-geo(rg)",
                    "ip-blocker(ib) [<ip>|<number>] [-]",
                    "ip-changes(ic) [<id>|<number>] [-]",
                    "punch-requests(pr) [<number>] [-]",
                    "always-use-relay(aur)",
                    "test-geo(tg) <ip1> <ip2>"
                )
            }
            Some("relay-servers" | "rs") => {
                if let Some(rs) = fds.next() {
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    for ip in self.relay_servers.iter() {
                        let _ = writeln!(res, "{ip}");
                    }
                }
            }
            Some("ip-blocker" | "ib") => {
                let mut lock = IP_BLOCKER.lock().await;
                lock.retain(|&_, (a, b)| {
                    a.1.elapsed().as_secs() <= IP_BLOCK_DUR
                        || b.1.elapsed().as_secs() <= DAY_SECONDS
                });
                res = format!("{}\n", lock.len());
                let ip = fds.next();
                let mut start = ip.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if start < 0 {
                    if let Some(ip) = ip {
                        if let Some((a, b)) = lock.get(ip) {
                            let _ = writeln!(
                                res,
                                "{}/{}s {}/{}s",
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                        if fds.next() == Some("-") {
                            lock.remove(ip);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((ip, (a, b))) = x {
                            let _ = writeln!(
                                res,
                                "{}: {}/{}s {}/{}s",
                                ip,
                                a.0,
                                a.1.elapsed().as_secs(),
                                b.0.len(),
                                b.1.elapsed().as_secs()
                            );
                        }
                    }
                }
            }
            Some("ip-changes" | "ic") => {
                let mut lock = IP_CHANGES.lock().await;
                lock.retain(|&_, v| v.0.elapsed().as_secs() < IP_CHANGE_DUR_X2 && v.1.len() > 1);
                res = format!("{}\n", lock.len());
                let id = fds.next();
                let mut start = id.map(|x| x.parse::<i32>().unwrap_or(-1)).unwrap_or(-1);
                if !(0..=10_000_000).contains(&start) {
                    if let Some(id) = id {
                        if let Some((tm, ips)) = lock.get(id) {
                            let _ = writeln!(res, "{}s {:?}", tm.elapsed().as_secs(), ips);
                        }
                        if fds.next() == Some("-") {
                            lock.remove(id);
                        }
                    } else {
                        start = 0;
                    }
                }
                if start >= 0 {
                    let mut it = lock.iter();
                    for i in 0..(start + 10) {
                        let x = it.next();
                        if x.is_none() {
                            break;
                        }
                        if i < start {
                            continue;
                        }
                        if let Some((id, (tm, ips))) = x {
                            let _ = writeln!(res, "{}: {}s {:?}", id, tm.elapsed().as_secs(), ips,);
                        }
                    }
                }
            }
            Some("punch-requests" | "pr") => {
                use std::fmt::Write as _;
                let mut lock = PUNCH_REQS.lock().await;
                let arg = fds.next();
                if let Some("-") = arg { lock.clear(); }
                else {
                    let mut start = arg.and_then(|x| x.parse::<usize>().ok()).unwrap_or(0);
                    let mut page_size = fds.next().and_then(|x| x.parse::<usize>().ok()).unwrap_or(10);
                    if page_size == 0 { page_size = 10; }
                    for (_, e) in lock.iter().enumerate().skip(start).take(page_size) {
                        let age = e.tm.elapsed();
                        let event_system = std::time::SystemTime::now() - age;
                        let event_iso = chrono::DateTime::<chrono::Utc>::from(event_system)
                            .to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
                        let _ = writeln!(res, "{} {} -> {}@{}", event_iso, e.from_ip, e.to_id, e.to_ip);
                    }
                }
            }
            Some("always-use-relay" | "aur") => {
                if let Some(rs) = fds.next() {
                    if rs.to_uppercase() == "Y" {
                        ALWAYS_USE_RELAY.store(true, Ordering::SeqCst);
                    } else {
                        ALWAYS_USE_RELAY.store(false, Ordering::SeqCst);
                    }
                    self.tx.send(Data::RelayServers0(rs.to_owned())).ok();
                } else {
                    let _ = writeln!(
                        res,
                        "ALWAYS_USE_RELAY: {:?}",
                        ALWAYS_USE_RELAY.load(Ordering::SeqCst)
                    );
                }
            }
            Some("test-geo" | "tg") => {
                if let Some(rs) = fds.next() {
                    if let Ok(a) = rs.parse::<IpAddr>() {
                        if let Some(rs) = fds.next() {
                            if let Ok(b) = rs.parse::<IpAddr>() {
                                res = format!("{:?}", self.get_relay_server(a, b));
                            }
                        } else {
                            res = format!("{:?}", self.get_relay_server(a, a));
                        }
                    }
                }
            }
            _ => {}
        }
        res
    }

    async fn handle_listener2(&self, stream: TcpStream, addr: SocketAddr) {
        let mut rs = self.clone();
        let ip = try_into_v4(addr).ip();
        if ip.is_loopback() {
            tokio::spawn(async move {
                let mut stream = stream;
                let mut buffer = [0; 1024];
                if let Ok(Ok(n)) = timeout(1000, stream.read(&mut buffer[..])).await {
                    if let Ok(data) = std::str::from_utf8(&buffer[..n]) {
                        let res = rs.check_cmd(data).await;
                        stream.write(res.as_bytes()).await.ok();
                    }
                }
            });
            return;
        }
        let stream = FramedStream::from(stream, addr);
        tokio::spawn(async move {
            let mut stream = stream;
            if let Some(Ok(bytes)) = stream.next_timeout(30_000).await {
                if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                    match msg_in.union {
                        Some(rendezvous_message::Union::TestNatRequest(_)) => {
                            let mut msg_out = RendezvousMessage::new();
                            msg_out.set_test_nat_response(TestNatResponse {
                                port: addr.port() as _,
                                ..Default::default()
                            });
                            stream.send(&msg_out).await.ok();
                        }
                        Some(rendezvous_message::Union::OnlineRequest(or)) => {
                            allow_err!(rs.handle_online_request(&mut stream, or.peers).await);
                        }
                        _ => {}
                    }
                }
            }
        });
    }

    async fn handle_listener(&self, stream: TcpStream, addr: SocketAddr, key: &str, ws: bool) {
        log::debug!("Tcp connection from {:?}, ws: {}", addr, ws);
        let mut rs = self.clone();
        let key = key.to_owned();
        tokio::spawn(async move {
            allow_err!(rs.handle_listener_inner(stream, addr, &key, ws).await);
        });
    }

    #[inline]
    async fn handle_listener_inner(
        &mut self,
        stream: TcpStream,
        mut addr: SocketAddr,
        key: &str,
        ws: bool,
    ) -> ResultType<()> {
        let mut sink;
        let conn_serial = NEXT_WS_CONN.fetch_add(1, Ordering::SeqCst);
        if ws {
            use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
            // Solo el proxy local puede reescribir la direccion de origen. Si la
            // conexion no viene de loopback, los headers son datos que controla
            // el propio cliente: se ignoran y se usa la direccion real del socket.
            // Asi el fix no depende de una regla de ufw para ser seguro.
            let trust_forwarded_headers = is_loopback(&addr);
            let callback = |req: &Request, response: Response| {
                if !trust_forwarded_headers {
                    let headers = req.headers();
                    if headers.contains_key("X-Real-IP") || headers.contains_key("X-Forwarded-For")
                    {
                        log::warn!(
                            "X-Real-IP/X-Forwarded-For ignorados: la conexion viene de {}, que no es loopback",
                            addr
                        );
                    }
                    return Ok(response);
                }
                let headers = req.headers();
                let real_ip = headers
                    .get("X-Real-IP")
                    .or_else(|| headers.get("X-Forwarded-For"))
                    .and_then(|header_value| header_value.to_str().ok());
                if let Some(ip) = real_ip {
                    // El puerto de origen real lo inyecta nginx con
                    // `proxy_set_header X-Real-Port $remote_port;`. Sin ese header
                    // (agente que entra directo al 21118, sin proxy delante) se
                    // mantiene 0, que es el comportamiento historico.
                    // El puerto importa: de este addr sale el socket_addr del
                    // PunchHoleResponse (handle_hole_sent) y el del PunchHole que
                    // se manda al agente, y con puerto 0 la conexion directa es
                    // imposible.
                    let real_port = headers
                        .get("X-Real-Port")
                        .and_then(|header_value| header_value.to_str().ok())
                        .and_then(|port| port.trim().parse::<u16>().ok())
                        .unwrap_or(0);
                    if let Some(forwarded) = addr_from_header(ip, real_port) {
                        addr = forwarded;
                    } else {
                        log::warn!("X-Real-IP invalido ({ip}), se mantiene {addr}");
                    }
                }
                Ok(response)
            };
            let ws_stream = tokio_tungstenite::accept_hdr_async(stream, callback).await?;
            let (a, mut b) = ws_stream.split();
            sink = Some(Sink::Ws(a));
            loop {
                match timeout(15_000, b.next()).await {
                    Ok(Some(Ok(msg))) => {
                        if let tungstenite::Message::Binary(bytes) = msg {
                            if bytes.is_empty() {
                                let id_opt = self
                                    .ws_conn_to_id
                                    .lock()
                                    .await
                                    .get(&conn_serial)
                                    .cloned();
                                if let Some(id) = id_opt {
                                    self.pm.touch_by_id(&id).await;
                                }
                                continue;
                            }
                            if !self
                                .handle_tcp(&bytes, &mut sink, addr, key, ws, conn_serial)
                                .await
                            {
                                break;
                            }
                        }
                    }
                    Ok(_) => break,
                    Err(_) => {
                        if sink.is_some() {
                            Self::send_ws_ping(&mut sink).await;
                        } else if !self.ping_ws_conn(conn_serial).await {
                            break;
                        }
                    }
                }
            }
        } else {
            let (a, mut b) = Framed::new(stream, BytesCodec::new()).split();
            sink = Some(Sink::TcpStream(a));
            while let Ok(Some(Ok(bytes))) = timeout(30_000, b.next()).await {
                if !self
                    .handle_tcp(&bytes, &mut sink, addr, key, ws, conn_serial)
                    .await
                {
                    break;
                }
            }
        }
        if sink.is_none() {
            self.tcp_punch.lock().await.remove(&try_into_v4(addr));
        }
        if ws {
            let id_opt = self.ws_conn_to_id.lock().await.remove(&conn_serial);
            if let Some(id) = id_opt {
                let mut sinks = self.ws_sinks.lock().await;
                let owned = sinks
                    .get(&id)
                    .map(|(serial, _)| *serial == conn_serial)
                    .unwrap_or(false);
                if owned {
                    sinks.remove(&id);
                    drop(sinks);
                    self.pm.clear_ws_addr_by_id(&id).await;
                }
            }
        }
        log::debug!("Tcp connection from {:?} closed", addr);
        Ok(())
    }

    #[inline]
    async fn get_pk(&mut self, version: &str, id: String) -> Bytes {
        if version.is_empty() || self.inner.sk.is_none() {
            Bytes::new()
        } else {
            match self.pm.get(&id).await {
                Some(peer) => {
                    let pk = peer.read().await.pk.clone();
                    sign::sign(
                        &hbb_common::message_proto::IdPk {
                            id,
                            pk,
                            ..Default::default()
                        }
                        .write_to_bytes()
                        .unwrap_or_default(),
                        self.inner.sk.as_ref().unwrap(),
                    )
                    .into()
                }
                _ => Bytes::new(),
            }
        }
    }

    #[inline]
    fn get_server_sk(key: &str) -> (String, Option<sign::SecretKey>) {
        let mut out_sk = None;
        let mut key = key.to_owned();
        if let Ok(sk) = base64::decode(&key) {
            if sk.len() == sign::SECRETKEYBYTES {
                log::info!("The key is a crypto private key");
                key = base64::encode(&sk[(sign::SECRETKEYBYTES / 2)..]);
                let mut tmp = [0u8; sign::SECRETKEYBYTES];
                tmp[..].copy_from_slice(&sk);
                out_sk = Some(sign::SecretKey(tmp));
            }
        }

        if key.is_empty() || key == "-" || key == "_" {
            let (pk, sk) = crate::common::gen_sk(0);
            out_sk = sk;
            if !key.is_empty() {
                key = pk;
            }
        }

        if !key.is_empty() {
            log::info!("Key: {}", key);
        }
        (key, out_sk)
    }

    #[inline]
    fn is_lan(&self, addr: SocketAddr) -> bool {
        is_lan_addr(self.inner.mask.as_ref(), addr)
    }
}

/// KairosLink: alias de relay para el lado del visor.
///
/// Un mismo hbbr se publica con dos nombres:
///   - relay.kairoslink.io  directo a la IP (TCP 21117 y WSS 443).
///   - wss.kairoslink.io    detras de Cloudflare (solo WSS 443).
///
/// El agente de una red que bloquea la IP del relay (caso SHD, 2026-10-23) usa
/// wss.kairoslink.io y, como no hay -r en hbbs, propone ese mismo host como
/// punto de encuentro del relay. El visor se conecta por TCP crudo, y por TCP
/// Cloudflare no deja pasar el 21117: la cita nunca se arma ("deadline has
/// elapsed"). Como los dos nombres llevan al MISMO hbbr, que empareja por uuid,
/// alcanza con traducirle al visor el alias al nombre directo. El agente sigue
/// entrando por Cloudflare y el visor por la IP, y se encuentran igual.
///
/// Solo se aplica a lo que va HACIA el visor (RelayResponse y PunchHoleResponse).
/// Un host que no figura en la lista pasa intacto, asi que el resto del parque
/// no cambia de comportamiento.
///
/// Configurable con la variable de entorno RELAY_ALIASES:
///   "wss.kairoslink.io=relay.kairoslink.io,otro=destino"
/// Sin la variable rige el alias de arriba. RELAY_ALIASES=- lo apaga.
fn relay_aliases() -> &'static Vec<(String, String)> {
    static ALIASES: std::sync::OnceLock<Vec<(String, String)>> = std::sync::OnceLock::new();
    ALIASES.get_or_init(|| {
        let raw = std::env::var("RELAY_ALIASES")
            .unwrap_or_else(|_| "wss.kairoslink.io=relay.kairoslink.io".to_owned());
        let lista: Vec<(String, String)> = raw
            .split(',')
            .filter_map(|par| {
                let (de, a) = par.split_once('=')?;
                let (de, a) = (de.trim().to_lowercase(), a.trim().to_owned());
                if de.is_empty() || a.is_empty() {
                    None
                } else {
                    Some((de, a))
                }
            })
            .collect();
        log::info!("relay aliases para el visor: {:?}", lista);
        lista
    })
}

fn relay_para_visor(relay_server: &str) -> String {
    traducir_alias(relay_server, relay_aliases())
}

fn traducir_alias(relay_server: &str, aliases: &[(String, String)]) -> String {
    if relay_server.is_empty() || aliases.is_empty() {
        return relay_server.to_owned();
    }
    // host o host:puerto. Un IPv6 (mas de un ':') nunca es un alias: pasa intacto.
    let (host, puerto) = match relay_server.rsplit_once(':') {
        Some((h, p)) if !h.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => {
            (h, Some(p))
        }
        Some(_) => return relay_server.to_owned(),
        None => (relay_server, None),
    };
    let host_lc = host.to_lowercase();
    for (de, a) in aliases {
        if *de == host_lc {
            let nuevo = match puerto {
                Some(p) => format!("{}:{}", a, p),
                None => a.clone(),
            };
            log::info!("relay para el visor: {} -> {}", relay_server, nuevo);
            return nuevo;
        }
    }
    relay_server.to_owned()
}

#[cfg(test)]
mod tests_relay_alias {
    use super::traducir_alias;

    fn al() -> Vec<(String, String)> {
        vec![("wss.kairoslink.io".to_owned(), "relay.kairoslink.io".to_owned())]
    }

    #[test]
    fn traduce_con_puerto() {
        assert_eq!(traducir_alias("wss.kairoslink.io:21117", &al()), "relay.kairoslink.io:21117");
    }

    #[test]
    fn traduce_sin_puerto_y_sin_importar_mayusculas() {
        assert_eq!(traducir_alias("WSS.kairoslink.io", &al()), "relay.kairoslink.io");
    }

    #[test]
    fn no_toca_otros_hosts() {
        assert_eq!(traducir_alias("relay.kairoslink.io:21117", &al()), "relay.kairoslink.io:21117");
        assert_eq!(traducir_alias("relay-eu.kairoslink.io", &al()), "relay-eu.kairoslink.io");
        assert_eq!(traducir_alias("10.0.0.5:21117", &al()), "10.0.0.5:21117");
        assert_eq!(traducir_alias("[::1]:21117", &al()), "[::1]:21117");
        assert_eq!(traducir_alias("", &al()), "");
    }

    #[test]
    fn sin_aliases_no_hace_nada() {
        assert_eq!(traducir_alias("wss.kairoslink.io:21117", &[]), "wss.kairoslink.io:21117");
    }
}

/// `true` si `addr` cae dentro del rango privado declarado con `--mask`.
#[inline]
fn is_lan_addr(mask: Option<&Ipv4Network>, addr: SocketAddr) -> bool {
    let Some(network) = mask else {
        return false;
    };
    match addr {
        SocketAddr::V4(v4_socket_addr) => network.contains(*v4_socket_addr.ip()),
        SocketAddr::V6(v6_socket_addr) => v6_socket_addr
            .ip()
            .to_ipv4()
            .map(|v4_addr| network.contains(v4_addr))
            .unwrap_or(false),
    }
}

/// `true` si la conexion entrante nace en la misma maquina, es decir si el
/// unico que pudo abrirla es el nginx local. Contempla 127.0.0.0/8, ::1 y la
/// forma mapeada ::ffff:127.0.0.1, porque con un listener dual-stack el kernel
/// entrega la v4 mapeada y nginx puede conectarse por cualquiera de las dos.
#[inline]
fn is_loopback(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip
                    .to_ipv4_mapped()
                    .map(|v4| v4.is_loopback())
                    .unwrap_or(false)
        }
    }
}

/// `true` si tiene sentido mandarle un datagrama a esta direccion de par.
///
/// Un par puede quedar en memoria con una direccion inservible: `Peer::default()`
/// nace en `0.0.0.0:0` (asi se carga un peer traido de la base, que no guarda
/// direccion), y un agente que entra por WebSocket sin `X-Real-Port` queda con
/// puerto 0. Cuando ese par pierde el WebSocket (`ws_addr = None`) pero sigue
/// "vivo" por `last_reg_time`, el punch hole cae al camino UDP y se intenta
/// enviar a esa direccion: `sendto` devuelve EINVAL.
///
/// Loopback tambien se descarta: un par nunca es el propio servidor, y mandarle
/// senalizacion a 127.0.0.1 solo puede ser una direccion mal derivada.
#[inline]
fn is_udp_peer_addr(addr: &SocketAddr) -> bool {
    is_sendable_udp_addr(addr) && !is_loopback(addr)
}

/// `true` si la IP sirve para razonar sobre topologia de red.
///
/// Descarta la no especificada (`0.0.0.0` / `::`, que es como nace un par
/// traido de la base, ver `Peer::default`) y loopback. Sin esta guarda dos
/// pares sin direccion util compararian iguales y se declararian en la misma
/// intranet.
#[inline]
fn has_routable_ip(addr: &SocketAddr) -> bool {
    !addr.ip().is_unspecified() && !is_loopback(addr)
}

/// Direccion efectiva de un par para decidir topologia de red.
///
/// `socket_addr` no sirve para un agente que solo habla WebSocket: `start_tcp`
/// del agente nunca manda `RegisterPeer`, y la rama WebSocket de `RegisterPk`
/// solo actualiza `ws_addr` y `last_reg_time`. `socket_addr` queda con lo que
/// haya dejado el ultimo `update_pk`, o en `0.0.0.0:0` si el par se cargo desde
/// la base. La direccion viva de ese par es `ws_addr`.
///
/// El resultado se normaliza con `try_into_v4` porque los dos extremos llegan a
/// hbbs por caminos distintos: el visor por TCP crudo al listener dual-stack
/// (`::ffff:a.b.c.d`) y el agente por nginx, donde `addr_from_header` ya
/// devuelve IPv4 nativa. Sin normalizar, cualquier comparacion entre ambos es
/// un `SocketAddr::V4` contra un `SocketAddr::V6` y nunca puede dar `true`.
fn peer_effective_addr(socket_addr: SocketAddr, ws_addr: Option<SocketAddr>) -> SocketAddr {
    let candidate = match ws_addr {
        Some(ws) if has_routable_ip(&ws) => ws,
        _ => socket_addr,
    };
    try_into_v4(candidate)
}

/// `true` si los dos extremos salen a internet por la misma IP publica, que es
/// la senial de que estan detras del mismo router.
///
/// Normaliza las dos puntas antes de comparar y exige que la IP sea utilizable:
/// un par sin direccion (`0.0.0.0:0`) nunca cuenta como vecino de nadie.
fn same_public_ip(a: SocketAddr, b: SocketAddr) -> bool {
    let a = try_into_v4(a);
    let b = try_into_v4(b);
    has_routable_ip(&a) && has_routable_ip(&b) && a.ip() == b.ip()
}

/// Lectura de la topologia entre los dos extremos de un punch hole.
pub(crate) struct Topology {
    /// Direccion efectiva del agente, ya normalizada.
    peer_eff: SocketAddr,
    /// Direccion efectiva del visor, ya normalizada.
    my_eff: SocketAddr,
    peer_is_lan: bool,
    is_lan: bool,
    /// `true` si los dos estan detras del mismo router y conviene el camino
    /// local (`FetchLocalAddr`) en vez del punch contra la IP publica.
    same_intranet: bool,
}

/// Decide la topologia de red entre agente y visor.
///
/// Es el reemplazo del calculo que estaba embebido en `handle_punch_hole_request`
/// y que no podia dar `same_intranet = true` en produccion por dos motivos
/// independientes: comparaba `SocketAddr` de familias distintas, y miraba
/// `socket_addr` en vez de `ws_addr`. Ver `peer_effective_addr` y `same_public_ip`.
fn topology(
    mask: Option<&Ipv4Network>,
    peer_socket_addr: SocketAddr,
    peer_ws_addr: Option<SocketAddr>,
    my_addr: SocketAddr,
) -> Topology {
    let peer_eff = peer_effective_addr(peer_socket_addr, peer_ws_addr);
    let my_eff = try_into_v4(my_addr);
    let peer_is_lan = is_lan_addr(mask, peer_eff);
    let is_lan = is_lan_addr(mask, my_eff);
    // Dos caminos para el mismo veredicto: los dos dentro del rango privado que
    // declara --mask (hbbs dentro de la LAN), o los dos saliendo por la misma IP
    // publica (hbbs en internet, que es nuestro despliegue).
    let same_intranet = (peer_is_lan && is_lan) || same_public_ip(peer_eff, my_eff);
    Topology {
        peer_eff,
        my_eff,
        peer_is_lan,
        is_lan,
        same_intranet,
    }
}

/// Envia un datagrama de senalizacion a un par. Nunca propaga error: si la
/// direccion no sirve o el envio falla, se registra y se sigue. El viewer no
/// recibe respuesta y cae solo al camino de relay, que es la degradacion
/// aceptable; tumbar el loop UDP no lo es.
async fn send_udp_to_peer(
    socket: &mut FramedSocket,
    msg: &RendezvousMessage,
    addr: SocketAddr,
    what: &str,
) -> bool {
    if !is_udp_peer_addr(&addr) {
        log::warn!(
            "{}: se omite el envio UDP a {}, direccion invalida; el par queda por relay",
            what,
            addr
        );
        return false;
    }
    if let Err(err) = socket.send(msg, addr).await {
        log::warn!("{}: fallo el envio UDP a {}: {}", what, addr, err);
        return false;
    }
    true
}

/// Arma el SocketAddr real a partir del valor del header.
///
/// El codigo anterior decidia la familia con `ip.contains('.')`, asi que una
/// direccion mapeada como `::ffff:190.245.223.51` caia en la rama IPv4, se
/// formateaba como `::ffff:190.245.223.51:0`, no parseaba y la direccion real
/// se perdia en silencio. Aca se parsea la IP primero y despues se arma el
/// addr, y las v4 mapeadas se normalizan a IPv4 nativa para que el resto del
/// server (is_lan, try_into_v4, AddrMangle) las vea igual que a las directas.
fn addr_from_header(value: &str, port: u16) -> Option<SocketAddr> {
    // X-Forwarded-For puede traer la cadena completa de proxies
    // ("cliente, proxy1, proxy2"): el origen real es el primer elemento.
    let raw = value.split(',').next()?.trim();
    // Tolerar la forma entre corchetes que usan algunos proxies para IPv6.
    let raw = raw
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(raw);
    let ip = match raw.parse::<IpAddr>().ok()? {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => IpAddr::V6(v6),
        },
        v4 => v4,
    };
    Some(SocketAddr::new(ip, port))
}

async fn check_relay_servers(rs0: Arc<RelayServers>, tx: Sender) {
    let mut futs = Vec::new();
    let rs = Arc::new(Mutex::new(Vec::new()));
    for x in rs0.iter() {
        let mut host = x.to_owned();
        if !host.contains(':') {
            host = format!("{}:{}", host, config::RELAY_PORT);
        }
        let rs = rs.clone();
        let x = x.clone();
        futs.push(tokio::spawn(async move {
            if FramedStream::new(&host, None, CHECK_RELAY_TIMEOUT)
                .await
                .is_ok()
            {
                rs.lock().await.push(x);
            }
        }));
    }
    join_all(futs).await;
    log::debug!("check_relay_servers");
    let rs = std::mem::take(&mut *rs.lock().await);
    if !rs.is_empty() {
        tx.send(Data::RelayServers(rs)).ok();
    }
}

// temp solution to solve udp socket failure
async fn test_hbbs(addr: SocketAddr) -> ResultType<()> {
    let mut addr = addr;
    if addr.ip().is_unspecified() {
        addr.set_ip(if addr.is_ipv4() {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        });
    }

    let mut socket = FramedSocket::new(config::Config::get_any_listen_addr(addr.is_ipv4())).await?;
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_peer(RegisterPeer {
        id: "(:test_hbbs:)".to_owned(),
        ..Default::default()
    });
    let mut last_time_recv = Instant::now();

    let mut timer = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
          _ = timer.tick() => {
              if last_time_recv.elapsed().as_secs() > 12 {
                  bail!("Timeout of test_hbbs");
              }
              socket.send(&msg_out, addr).await?;
          }
          Some(Ok((bytes, _))) = socket.next() => {
              if let Ok(msg_in) = RendezvousMessage::parse_from_bytes(&bytes) {
                 log::trace!("Recv {:?} of test_hbbs", msg_in);
                 last_time_recv = Instant::now();
              }
          }
        }
    }
}

#[inline]
async fn send_rk_res(
    socket: &mut FramedSocket,
    addr: SocketAddr,
    res: register_pk_response::Result,
) -> ResultType<()> {
    let mut msg_out = RendezvousMessage::new();
    msg_out.set_register_pk_response(RegisterPkResponse {
        result: res.into(),
        ..Default::default()
    });
    socket.send(&msg_out, addr).await
}

async fn create_udp_listener(port: i32, rmem: usize) -> ResultType<FramedSocket> {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), port as _);
    if let Ok(s) = FramedSocket::new_reuse(&addr, true, rmem).await {
        log::debug!("listen on udp {:?}", s.local_addr());
        return Ok(s);
    }
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), port as _);
    let s = FramedSocket::new_reuse(&addr, true, rmem).await?;
    log::debug!("listen on udp {:?}", s.local_addr());
    Ok(s)
}

#[inline]
async fn create_tcp_listener(port: i32) -> ResultType<TcpListener> {
    let s = listen_any(port as _).await?;
    log::debug!("listen on tcp {:?}", s.local_addr());
    Ok(s)
}

#[cfg(test)]
mod tests_same_intranet {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// El `--mask 192.168.0.0/16` con el que corre hbbs en produccion.
    fn mask() -> Ipv4Network {
        "192.168.0.0/16".parse().unwrap()
    }

    /// Como entra el visor: TCP crudo al 21116, listener dual-stack, por lo que
    /// el kernel entrega la IPv4 en forma mapeada.
    fn visor(ip: &str, port: u16) -> SocketAddr {
        sa(&format!("[::ffff:{ip}]:{port}"))
    }

    /// Como queda el agente: entra por nginx y `addr_from_header` ya normalizo
    /// la direccion a IPv4 nativa.
    fn agente_ws(ip: &str, port: u16) -> SocketAddr {
        sa(&format!("{ip}:{port}"))
    }

    #[test]
    fn misma_ip_publica_con_familias_distintas_es_misma_intranet() {
        // El caso real de produccion y la regresion que motivo el fix: dos
        // maquinas detras del mismo router. El visor llega v6-mapeado y el
        // agente v4 nativa, y antes el `match (peer_addr, addr)` caia en
        // `_ => false` sin comparar nada.
        let t = topology(
            Some(&mask()),
            sa("0.0.0.0:0"),
            Some(agente_ws("190.245.223.51", 51092)),
            visor("190.245.223.51", 64661),
        );
        assert!(t.same_intranet, "misma IP publica debe ser misma intranet");
        assert_eq!(t.peer_eff, sa("190.245.223.51:51092"));
        assert_eq!(t.my_eff, sa("190.245.223.51:64661"));
    }

    #[test]
    fn misma_ip_publica_ambas_v4_nativas() {
        // Mismo veredicto si los dos llegaran ya normalizados.
        let t = topology(
            Some(&mask()),
            agente_ws("190.245.223.51", 51092),
            None,
            agente_ws("190.245.223.51", 64661),
        );
        assert!(t.same_intranet);
    }

    #[test]
    fn ips_publicas_distintas_no_es_misma_intranet() {
        // Tecnico en su casa, equipo en la oficina: tiene que ir por punch
        // hole contra la IP publica, y si falla, por relay.
        let t = topology(
            Some(&mask()),
            Some(agente_ws("190.245.223.51", 51092)).unwrap(),
            Some(agente_ws("190.245.223.51", 51092)),
            visor("181.170.10.7", 64661),
        );
        assert!(!t.same_intranet);
        assert!(!t.peer_is_lan);
        assert!(!t.is_lan);
    }

    #[test]
    fn ambos_dentro_del_mask_es_misma_intranet() {
        // hbbs desplegado dentro de la LAN del cliente: los dos extremos caen
        // en 192.168.0.0/16 aunque sean IPs distintas.
        let t = topology(
            Some(&mask()),
            sa("192.168.0.50:21116"),
            None,
            visor("192.168.0.102", 64661),
        );
        assert!(t.same_intranet);
        assert!(t.peer_is_lan);
        assert!(t.is_lan);
    }

    #[test]
    fn peer_sin_socket_addr_usa_ws_addr() {
        // Un agente que solo habla WebSocket puede quedar con socket_addr en
        // 0.0.0.0:0 (peer traido de la base, `Peer::default`). La direccion
        // viva es ws_addr y es la que hay que mirar.
        let t = topology(
            Some(&mask()),
            sa("0.0.0.0:0"),
            Some(sa("192.168.0.50:21116")),
            visor("192.168.0.102", 64661),
        );
        assert_eq!(t.peer_eff, sa("192.168.0.50:21116"));
        assert!(t.peer_is_lan);
        assert!(t.same_intranet);
    }

    #[test]
    fn peer_sin_direccion_util_nunca_es_vecino() {
        // Sin ws_addr y con socket_addr inservible no se puede afirmar nada:
        // debe caer al camino de punch hole, que a su vez cae a relay.
        let t = topology(
            Some(&mask()),
            sa("0.0.0.0:0"),
            None,
            visor("190.245.223.51", 64661),
        );
        assert!(!t.same_intranet);
        assert_eq!(t.peer_eff, sa("0.0.0.0:0"));

        // Y dos pares sin direccion tampoco comparan iguales entre si.
        let t = topology(None, sa("0.0.0.0:0"), None, sa("0.0.0.0:0"));
        assert!(!t.same_intranet);
    }

    #[test]
    fn loopback_no_cuenta_como_vecino() {
        // Si por un error de derivacion los dos quedaran en loopback, no se
        // puede concluir que esten en la misma LAN.
        let t = topology(None, sa("127.0.0.1:21116"), None, sa("127.0.0.1:64661"));
        assert!(!t.same_intranet);
    }

    #[test]
    fn ws_addr_invalida_cae_a_socket_addr() {
        // ws_addr presente pero sin IP utilizable: se ignora y se usa lo que
        // haya en socket_addr, sin romper la deteccion.
        let t = topology(
            Some(&mask()),
            agente_ws("190.245.223.51", 51092),
            Some(sa("0.0.0.0:0")),
            visor("190.245.223.51", 64661),
        );
        assert_eq!(t.peer_eff, sa("190.245.223.51:51092"));
        assert!(t.same_intranet);
    }

    #[test]
    fn sin_mask_la_deteccion_por_ip_publica_sigue_viva() {
        // El camino de misma IP publica no depende de --mask.
        let t = topology(
            None,
            sa("0.0.0.0:0"),
            Some(agente_ws("190.245.223.51", 51092)),
            visor("190.245.223.51", 64661),
        );
        assert!(t.same_intranet);
        assert!(!t.peer_is_lan);
        assert!(!t.is_lan);
    }

    #[test]
    fn un_solo_extremo_en_el_mask_fuerza_relay_y_no_es_intranet() {
        // `peer_is_lan ^ is_lan` es la condicion que fuerza relay en
        // handle_punch_hole_request. Se comprueba que sigue distinguiendo.
        let t = topology(
            Some(&mask()),
            sa("192.168.0.50:21116"),
            None,
            visor("190.245.223.51", 64661),
        );
        assert!(t.peer_is_lan ^ t.is_lan, "debe forzar relay");
        assert!(!t.same_intranet);
    }
}

#[cfg(test)]
mod tests_forwarded_addr {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn loopback_reconocido_en_las_tres_formas() {
        assert!(is_loopback(&sa("127.0.0.1:33000")));
        assert!(is_loopback(&sa("127.0.0.53:33000")));
        assert!(is_loopback(&sa("[::1]:33000")));
        assert!(is_loopback(&sa("[::ffff:127.0.0.1]:33000")));
    }

    #[test]
    fn no_loopback_rechazado() {
        assert!(!is_loopback(&sa("190.245.223.51:33000")));
        assert!(!is_loopback(&sa("10.0.0.5:33000")));
        assert!(!is_loopback(&sa("[2800:810:1::1]:33000")));
        // ::ffff:0.0.0.0 y similares no son loopback aunque sean mapeadas.
        assert!(!is_loopback(&sa("[::ffff:190.245.223.51]:33000")));
    }

    #[test]
    fn header_ipv4_simple() {
        assert_eq!(
            addr_from_header("190.245.223.51", 54321),
            Some(sa("190.245.223.51:54321"))
        );
    }

    #[test]
    fn header_ipv4_mapeada_se_normaliza_a_v4() {
        // Este es el caso que antes se perdia: contiene '.', iba a la rama v4
        // y "::ffff:190.245.223.51:0" no parseaba.
        assert_eq!(
            addr_from_header("::ffff:190.245.223.51", 54321),
            Some(sa("190.245.223.51:54321"))
        );
        assert_eq!(
            addr_from_header("::ffff:1.2.3.4", 4444),
            Some(sa("1.2.3.4:4444"))
        );
    }

    #[test]
    fn header_ipv6_nativa() {
        assert_eq!(
            addr_from_header("2800:810:1::1", 54321),
            Some(sa("[2800:810:1::1]:54321"))
        );
        assert_eq!(
            addr_from_header("[2800:810:1::1]", 54321),
            Some(sa("[2800:810:1::1]:54321"))
        );
    }

    #[test]
    fn header_con_cadena_de_proxies_toma_el_primero() {
        assert_eq!(
            addr_from_header("190.245.223.51, 10.0.0.1, 10.0.0.2", 54321),
            Some(sa("190.245.223.51:54321"))
        );
    }

    #[test]
    fn header_invalido_no_pisa_la_direccion() {
        assert_eq!(addr_from_header("no-una-ip", 54321), None);
        assert_eq!(addr_from_header("", 54321), None);
        assert_eq!(addr_from_header("190.245.223.51:9999", 54321), None);
    }

    #[test]
    fn puerto_cero_cuando_no_hay_x_real_port() {
        assert_eq!(
            addr_from_header("190.245.223.51", 0),
            Some(sa("190.245.223.51:0"))
        );
    }
}

#[cfg(test)]
mod tests_udp_robustez {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    async fn socket_local() -> FramedSocket {
        FramedSocket::new(&sa("127.0.0.1:0")).await.unwrap()
    }

    fn msg() -> RendezvousMessage {
        let mut m = RendezvousMessage::new();
        m.set_punch_hole_response(PunchHoleResponse::default());
        m
    }

    /// El socket sigue vivo: manda a un receptor real y el datagrama llega.
    async fn assert_socket_sigue_vivo(socket: &mut FramedSocket) {
        let mut rx = socket_local().await;
        let rx_addr = rx.local_addr().unwrap();
        // is_udp_peer_addr descarta loopback, asi que se prueba el envio crudo.
        socket.send(&msg(), rx_addr).await.unwrap();
        assert!(rx.next_timeout(2_000).await.is_some());
    }

    #[test]
    fn direccion_de_par_invalida() {
        // El caso de produccion: par sin ws_addr cuyo socket_addr quedo en 0.
        assert!(!is_udp_peer_addr(&sa("190.245.223.51:0")));
        // Peer::default(), tal como se carga un par traido de la base.
        assert!(!is_udp_peer_addr(&sa("0.0.0.0:0")));
        assert!(!is_udp_peer_addr(&sa("0.0.0.0:21116")));
        assert!(!is_udp_peer_addr(&sa("[::]:21116")));
        // Un par nunca es el propio servidor.
        assert!(!is_udp_peer_addr(&sa("127.0.0.1:21116")));
        assert!(!is_udp_peer_addr(&sa("[::1]:21116")));
        assert!(!is_udp_peer_addr(&sa("[::ffff:127.0.0.1]:21116")));
        // Direcciones utiles.
        assert!(is_udp_peer_addr(&sa("190.245.223.51:33000")));
        assert!(is_udp_peer_addr(&sa("192.168.1.122:21116")));
        assert!(is_udp_peer_addr(&sa("[2800:810:1::1]:21116")));
    }

    #[tokio::test]
    async fn envio_a_puerto_cero_no_tumba_el_servidor() {
        let mut socket = socket_local().await;
        let enviado =
            send_udp_to_peer(&mut socket, &msg(), sa("190.245.223.51:0"), "test").await;
        assert!(!enviado, "no se debe intentar enviar a puerto 0");
        assert_socket_sigue_vivo(&mut socket).await;
    }

    #[tokio::test]
    async fn envio_a_unspecified_no_tumba_el_servidor() {
        let mut socket = socket_local().await;
        assert!(!send_udp_to_peer(&mut socket, &msg(), sa("0.0.0.0:0"), "test").await);
        assert!(!send_udp_to_peer(&mut socket, &msg(), sa("0.0.0.0:21116"), "test").await);
        assert!(!send_udp_to_peer(&mut socket, &msg(), sa("[::]:21116"), "test").await);
        assert_socket_sigue_vivo(&mut socket).await;
    }

    /// Fallo genuino de `sendto` del SO, que la validacion no puede prever:
    /// socket IPv4 enviando a un destino IPv6. Es el caso que exige que la
    /// robustez no dependa de que la validacion sea perfecta.
    #[tokio::test]
    async fn fallo_de_send_to_no_tumba_el_servidor() {
        let mut socket = socket_local().await;
        let destino = sa("[2800:810:1::1]:21116");
        assert!(is_udp_peer_addr(&destino), "la validacion lo deja pasar");
        assert!(
            !send_udp_to_peer(&mut socket, &msg(), destino, "test").await,
            "el envio debe fallar en el SO y ser absorbido"
        );
        assert_socket_sigue_vivo(&mut socket).await;
    }

    /// Reproduce la secuencia de produccion: punch hole con ws_addr=None manda a
    /// una direccion muerta y, acto seguido, llega un registro que hay que
    /// responder. Antes el segundo envio heredaba el EINVAL del primero.
    #[tokio::test]
    async fn un_envio_fallido_no_envenena_los_siguientes() {
        let mut socket = socket_local().await;
        send_udp_to_peer(&mut socket, &msg(), sa("190.245.223.51:0"), "punch hole").await;
        assert_socket_sigue_vivo(&mut socket).await;
        for _ in 0..20 {
            send_udp_to_peer(&mut socket, &msg(), sa("190.245.223.51:0"), "punch hole").await;
            send_udp_to_peer(&mut socket, &msg(), sa("[2800:810:1::1]:21116"), "punch hole").await;
        }
        assert_socket_sigue_vivo(&mut socket).await;
    }

    #[test]
    fn solo_una_racha_de_errores_recrea_el_socket() {
        // Un error suelto de recepcion no debe llegar al umbral.
        assert!(1 < MAX_CONSECUTIVE_UDP_RECV_ERRORS);
        assert!(MAX_CONSECUTIVE_UDP_RECV_ERRORS >= 10);
    }
}
