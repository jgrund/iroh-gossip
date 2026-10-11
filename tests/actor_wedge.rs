//! Adapted from the reproduction by cbenhagen on iroh-gossip issue 47.
//!
//! A "zombie" neighbour completes the membership handshake, is promoted into
//! the victim's active view, then stops reading while the connection stays
//! alive at the QUIC level. Its per-connection `SendLoop` blocks in
//! `write_all().await` once the stream flow-control credit is spent, the
//! per-peer send queue fills behind it, and an actor that awaits that queue
//! stops serving every topic on the node.
//!
//! The test asserts collateral liveness only: while topic A drains into the
//! zombie, a broadcast on unrelated topic B must still reach a healthy peer.
//! Transport and gossip configs are default; the flood only has to exceed the
//! 1.25 MiB stream receive window plus the send queue.

use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use bytes::Bytes;
use iroh::{
    address_lookup::memory::MemoryLookup,
    endpoint::{presets, Connection, RecvStream, SendStream},
    protocol::Router,
    Endpoint, EndpointAddr, EndpointId, RelayMode, SecretKey, TransportAddr,
};
use iroh_gossip::{
    api::{Event as ApiEvent, GossipReceiver},
    net::Gossip,
    proto::{
        Command, Config as ProtoConfig, Event as ProtoEvent, InEvent, Message as WireMessage,
        OutEvent, PeerData, State as ProtoState, TopicId,
    },
};
use n0_error::{Result, StdResultExt};
use n0_future::{time::Instant, StreamExt as _};
use n0_tracing_test::traced_test;
use rand::{rngs::StdRng, SeedableRng};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    time::timeout,
};
use tracing::{debug, info};

/// Just under `DEFAULT_MAX_MESSAGE_SIZE` (4096), leaving header room.
const PAYLOAD_SIZE: usize = 3800;
/// Exhausts the default 1.25 MiB stream receive window (~330 payloads) plus
/// the per-peer send queue several times over.
const FLOOD_MESSAGES: usize = 1500;
/// On a live actor the probe is a couple of loopback round trips.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);
const JOIN_TIMEOUT: Duration = Duration::from_secs(30);

#[tokio::test(flavor = "multi_thread")]
#[traced_test]
async fn zombie_neighbor_does_not_block_unrelated_topics() -> Result<()> {
    let flood_topic = TopicId::from_bytes([0xAB; 32]);
    let probe_topic = TopicId::from_bytes([0xCD; 32]);
    let lookup = MemoryLookup::new();

    let zombie_endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        .alpns(vec![iroh_gossip::ALPN.to_vec()])
        .bind()
        .await
        .std_context("bind zombie endpoint")?;
    let zombie_id = zombie_endpoint.id();
    lookup.add_endpoint_info(loopback_addr(&zombie_endpoint));
    tokio::spawn({
        let endpoint = zombie_endpoint.clone();
        async move {
            if let Err(err) = run_zombie(endpoint, flood_topic).await {
                debug!("zombie task ended: {err:#}");
            }
        }
    });

    let (victim_endpoint, victim_gossip, _victim_router) = gossip_node(&lookup).await?;
    let (bystander_endpoint, bystander_gossip, _bystander_router) = gossip_node(&lookup).await?;

    let victim_id = victim_endpoint.id();
    let bystander_join = tokio::spawn({
        let gossip = bystander_gossip.clone();
        async move {
            gossip
                .subscribe_and_join(probe_topic, vec![victim_id])
                .await
        }
    });
    let victim_probe_topic = timeout(
        JOIN_TIMEOUT,
        victim_gossip.subscribe_and_join(probe_topic, vec![]),
    )
    .await
    .std_context("timed out joining probe topic")??;
    let bystander_probe_topic = timeout(JOIN_TIMEOUT, bystander_join)
        .await
        .std_context("timed out waiting for bystander join")?
        .std_context("bystander join task panicked")?
        .std_context("bystander failed to join probe topic")?;
    let (probe_sender, _victim_probe_receiver) = victim_probe_topic.split();
    let (_bystander_sender, mut bystander_receiver) = bystander_probe_topic.split();

    probe_sender
        .broadcast(Bytes::from_static(b"pre-flood probe"))
        .await
        .std_context("pre-flood probe broadcast")?;
    wait_for_message(&mut bystander_receiver, b"pre-flood probe", PROBE_TIMEOUT)
        .await
        .std_context("pre-flood probe was not received: harness problem, not the bug")?;
    info!("pre-flood probe delivered");

    let flood_topic_handle = timeout(
        JOIN_TIMEOUT,
        victim_gossip.subscribe_and_join(flood_topic, vec![zombie_id]),
    )
    .await
    .std_context("timed out joining flood topic with the zombie as bootstrap")??;
    info!(zombie = %zombie_id.fmt_short(), "zombie joined as neighbor");
    let (flood_sender, mut flood_receiver) = flood_topic_handle.split();
    tokio::spawn(async move { while flood_receiver.next().await.is_some() {} });

    let progress = Arc::new(AtomicUsize::new(0));
    let flood_task = tokio::spawn({
        let progress = progress.clone();
        async move {
            let payload = Bytes::from(vec![0x5A; PAYLOAD_SIZE]);
            for _ in 0..FLOOD_MESSAGES {
                if flood_sender.broadcast(payload.clone()).await.is_err() {
                    break;
                }
                progress.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    let mut last = 0_usize;
    loop {
        tokio::time::sleep(Duration::from_secs(3)).await;
        let now = progress.load(Ordering::Relaxed);
        if flood_task.is_finished() {
            info!(sent = now, "flood completed");
            break;
        }
        if now == last {
            info!(sent = now, "flood stalled (sender backpressured)");
            break;
        }
        last = now;
    }

    let probe_result: Result<()> = async {
        probe_sender
            .broadcast(Bytes::from_static(b"mid-flood probe"))
            .await
            .std_context("mid-flood probe broadcast did not complete")?;
        wait_for_message(&mut bystander_receiver, b"mid-flood probe", PROBE_TIMEOUT)
            .await
            .std_context("mid-flood probe was not received by the healthy peer")?;
        Ok(())
    }
    .await;

    zombie_endpoint.close().await;
    flood_task.abort();

    if let Err(err) = probe_result {
        panic!(
            "gossip actor wedged by one zombie neighbor: unrelated topic lost \
             end-to-end liveness while topic {} drained into a non-reading peer \
             (see #47): {err:#}",
            flood_topic.fmt_short()
        );
    }
    info!("collateral liveness held: unrelated topic delivered during flood");

    bystander_endpoint.close().await;
    victim_endpoint.close().await;
    Ok(())
}

async fn gossip_node(lookup: &MemoryLookup) -> Result<(Endpoint, Gossip, Router)> {
    let endpoint = Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::generate())
        .relay_mode(RelayMode::Disabled)
        .bind()
        .await
        .std_context("bind endpoint")?;
    endpoint
        .address_lookup()
        .std_context("endpoint closed")?
        .add(lookup.clone());
    lookup.add_endpoint_info(loopback_addr(&endpoint));
    let gossip = Gossip::builder().spawn(endpoint.clone());
    let router = Router::builder(endpoint.clone())
        .accept(iroh_gossip::ALPN, gossip.clone())
        .spawn();
    Ok((endpoint, gossip, router))
}

fn loopback_addr(endpoint: &Endpoint) -> EndpointAddr {
    let sockets: Vec<TransportAddr> = endpoint
        .bound_sockets()
        .into_iter()
        .map(|mut sa| {
            if sa.ip().is_unspecified() {
                let loopback = if sa.is_ipv4() {
                    std::net::IpAddr::from([127, 0, 0, 1])
                } else {
                    std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST)
                };
                sa.set_ip(loopback);
            }
            TransportAddr::Ip(sa)
        })
        .collect();
    assert!(!sockets.is_empty(), "endpoint has no bound sockets");
    EndpointAddr::from_parts(endpoint.id(), sockets)
}

async fn wait_for_message(
    receiver: &mut GossipReceiver,
    expected: &[u8],
    budget: Duration,
) -> Result<()> {
    timeout(budget, async {
        while let Some(event) = receiver.next().await {
            if let Ok(ApiEvent::Received(msg)) = event {
                if msg.content.as_ref() == expected {
                    return Ok(());
                }
            }
        }
        Err(std::io::Error::other("receiver stream ended")).std_context("event stream")
    })
    .await
    .std_context("timed out waiting for message")?
}

/// Answers the membership handshake through the public [`ProtoState`] machine so
/// the victim promotes us into its active view, then stops reading. The endpoint
/// driver keeps acknowledging at the transport level, so the connection stays up
/// while stream flow-control credit is never returned.
async fn run_zombie(endpoint: Endpoint, topic: TopicId) -> Result<()> {
    let mut state: ProtoState<EndpointId, StdRng> = ProtoState::new(
        endpoint.id(),
        PeerData::new(Vec::<u8>::new()),
        ProtoConfig::default(),
        StdRng::seed_from_u64(0xB0B),
    );
    _ = state
        .handle(
            InEvent::Command(topic, Command::Join(vec![])),
            Instant::now(),
            None,
        )
        .count();
    let state = Arc::new(tokio::sync::Mutex::new(state));

    loop {
        let Some(incoming) = endpoint.accept().await else {
            return Ok(());
        };
        let conn = match incoming.await {
            Ok(conn) => conn,
            Err(err) => {
                debug!("zombie: incoming connection failed: {err:#}");
                continue;
            }
        };
        let state = state.clone();
        tokio::spawn(async move {
            let remote = conn.remote_id();
            if let Err(err) = zombie_conn(conn, topic, remote, state).await {
                debug!("zombie conn ended: {err:#}");
            }
        });
    }
}

async fn zombie_conn(
    conn: Connection,
    topic: TopicId,
    remote: EndpointId,
    state: Arc<tokio::sync::Mutex<ProtoState<EndpointId, StdRng>>>,
) -> Result<()> {
    let mut recv = conn.accept_uni().await.std_context("accept_uni")?;

    // The length-prefixed postcard `StreamHeader` encodes byte-identically to the
    // bare 32-byte topic id.
    let header = read_frame_bytes(&mut recv)
        .await
        .std_context("read header")?;
    assert_eq!(
        header.as_slice(),
        topic.as_bytes().as_slice(),
        "unexpected topic in stream header"
    );

    let mut send: Option<SendStream> = None;
    loop {
        let payload = read_frame_bytes(&mut recv)
            .await
            .std_context("read frame")?;
        // postcard concatenates struct fields with no framing, so
        // postcard(Message{topic,inner}) == 32 topic bytes ++ postcard(inner).
        let mut buf = Vec::with_capacity(32 + payload.len());
        buf.extend_from_slice(topic.as_bytes());
        buf.extend_from_slice(&payload);
        let msg: WireMessage<EndpointId> =
            postcard::from_bytes(&buf).std_context("decode gossip message")?;

        let outs: Vec<OutEvent<EndpointId>> = state
            .lock()
            .await
            .handle(InEvent::RecvMessage(remote, msg), Instant::now(), None)
            .collect();

        let mut neighbor_up = false;
        for out in outs {
            match out {
                OutEvent::SendMessage(_to, msg) => {
                    let bytes = postcard::to_stdvec(&msg).std_context("encode gossip message")?;
                    assert!(bytes.len() > 32 && &bytes[..32] == topic.as_bytes().as_slice());
                    let stream = match send.as_mut() {
                        Some(s) => s,
                        None => {
                            let mut s = conn.open_uni().await.std_context("open_uni")?;
                            write_frame_bytes(&mut s, topic.as_bytes()).await?;
                            send.insert(s)
                        }
                    };
                    write_frame_bytes(stream, &bytes[32..]).await?;
                }
                OutEvent::EmitEvent(_, ProtoEvent::NeighborUp(peer)) => {
                    info!(peer = %peer.fmt_short(), "zombie: neighbor up, going silent now");
                    neighbor_up = true;
                }
                _ => {}
            }
        }
        if neighbor_up {
            break;
        }
    }

    // Hold the connection and streams open without ever reading again.
    std::future::pending().await
}

async fn read_frame_bytes(recv: &mut RecvStream) -> Result<Vec<u8>> {
    let len = recv.read_u32().await.std_context("read frame len")? as usize;
    assert!(len <= 1024 * 1024, "frame too large: {len}");
    let mut buf = vec![0_u8; len];
    recv.read_exact(&mut buf)
        .await
        .std_context("read frame body")?;
    Ok(buf)
}

async fn write_frame_bytes(send: &mut SendStream, payload: &[u8]) -> Result<()> {
    send.write_u32(payload.len() as u32)
        .await
        .std_context("write frame len")?;
    send.write_all(payload)
        .await
        .std_context("write frame body")?;
    Ok(())
}
