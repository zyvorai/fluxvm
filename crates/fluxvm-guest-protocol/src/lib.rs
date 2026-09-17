// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Wire protocol for the Zyvor FluxVM guest agent: one JSON object per
//! line (newline-delimited, no length prefix), one request in, one response
//! out, over AF_VSOCK. This crate is compiled into both `fluxvm-guest-agent`
//! (runs inside the guest) and `fluxvm-vsock-client` (runs on the host), so
//! the two sides can never drift out of sync on the message shapes.

use serde::{Deserialize, Serialize};

/// Default AF_VSOCK port the guest agent listens on.
pub const DEFAULT_PORT: u32 = 17777;

/// Default exec timeout when a request doesn't specify one.
pub const DEFAULT_EXEC_TIMEOUT_SECS: u64 = 30;

/// Where the guest agent looks for its shared-secret token (see
/// [`Envelope`]). Written into the guest's own disk *before* boot by
/// `fluxvm_image::inject_guest_agent_token`, so it's already in place by
/// the time the agent's systemd unit starts. Absent -> the agent runs
/// unauthenticated (only true for VMs created before this existed, or with
/// `agent.enabled: false`).
pub const TOKEN_FILE_PATH: &str = "/etc/fluxvm-guest-agent.token";

/// Requests/responses carrying file content are capped at this size —
/// generous for config files and small scripts (what `copy_to`/`copy_from`
/// are actually used for), small enough that a base64-in-one-JSON-line
/// transfer (no chunking/streaming) stays sane in guest-agent and host
/// memory alike. Bulk data belongs in a disk image, not this channel.
pub const MAX_FILE_TRANSFER_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "kebab-case")]
pub enum AgentRequest {
    Ping,
    Exec {
        command: String,
        #[serde(default)]
        timeout_seconds: Option<u64>,
    },
    /// Write `content_base64` (decoded) to `path` inside the guest,
    /// creating parent directories as needed. Replaces machinectl's
    /// `copy-to`.
    PutFile {
        path: String,
        content_base64: String,
        /// Unix permission bits, e.g. `0o644`. Defaults to `0o644` if unset.
        #[serde(default)]
        mode: Option<u32>,
    },
    /// Read `path` from inside the guest, returned base64-encoded in
    /// [`AgentResponse::FileContent`]. Replaces machinectl's `copy-from`.
    GetFile {
        path: String,
    },
    /// Open an interactive PTY-backed shell. Unlike every other request,
    /// this is the *last* JSON line the agent reads on this connection —
    /// once it answers [`AgentResponse::ShellOpened`], the connection stops
    /// being newline-JSON-framed and every message read from the client
    /// becomes a [`PtyFrame`] instead: keystrokes ride in `PtyFrame::Data`,
    /// and a client can resize the PTY at any point during the session with
    /// `PtyFrame::Resize` — no reconnect needed. PTY output flowing back to
    /// the client stays completely unframed raw bytes (see [`PtyFrame`]'s
    /// own docs for why this is intentionally one-directional).
    OpenShell {
        #[serde(default = "default_pty_cols")]
        cols: u16,
        #[serde(default = "default_pty_rows")]
        rows: u16,
    },
    Shutdown,
}
fn default_pty_cols() -> u16 {
    80
}
fn default_pty_rows() -> u16 {
    24
}

/// Every request the agent authored by `fluxvm-vsock-client` is wrapped in
/// this envelope. `token` is checked against the file at [`TOKEN_FILE_PATH`]
/// before `request` is acted on — this is what stops any *other* process on
/// the host (anything that can open a raw AF_VSOCK socket to the same CID,
/// bypassing the fluxvm daemon/CLI entirely) from running commands in the
/// guest as root. It's a shared secret over a host-local transport, not a
/// substitute for REST-layer auth/RBAC (see `fluxvm-api`'s `Role`) — those
/// answer different questions ("can this human/service call fluxvm at
/// all") vs. ("is this vsock caller actually fluxvm").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(flatten)]
    pub request: AgentRequest,
}

impl Envelope {
    pub fn new(token: Option<String>, request: AgentRequest) -> Self {
        Self { token, request }
    }
}

/// Constant-time comparison so a mismatched guest-agent token can't be
/// brute-forced via response-time measurement. Zero-dependency by design —
/// `fluxvm-guest-agent` deliberately stays a minimal, small guest binary
/// (see its Cargo.toml), so this doesn't pull in a crypto crate for one
/// tiny comparison.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case")]
pub enum AgentResponse {
    Pong,
    Exec {
        exit_code: i32,
        stdout: String,
        stderr: String,
    },
    FileWritten,
    FileContent {
        content_base64: String,
        /// Unix permission bits the file had on the guest, e.g. `0o644`.
        mode: u32,
    },
    /// Acknowledges `AgentRequest::OpenShell` — the last JSON-framed message
    /// on this connection; every byte the client sends after this
    /// response's trailing `\n` is a [`PtyFrame`], and every byte the
    /// client reads back is raw PTY output (not JSON, not framed).
    ShellOpened,
    ShuttingDown,
    Error {
        message: String,
    },
}

/// Bounds a single [`PtyFrame::Data`] frame's payload — generous for a
/// paste or a fast-scrolling command's worth of keystrokes batched into one
/// write, small enough that a corrupt or hostile length header can't make
/// the guest agent allocate an unbounded buffer before it's even had a
/// chance to reject the frame (see [`PtyFrame::read_from`]).
pub const MAX_PTY_FRAME_BYTES: usize = 1024 * 1024;

const PTY_FRAME_TAG_DATA: u8 = 0;
const PTY_FRAME_TAG_RESIZE: u8 = 1;

/// One message on the wire *after* `AgentResponse::ShellOpened` — i.e. once
/// an `OpenShell` connection has left newline-JSON framing behind. Unlike
/// every other message this crate defines, a `PtyFrame` is hand-rolled
/// binary (`[tag: u8]` then type-specific bytes), not JSON: JSON can't
/// safely carry a shell's actual byte-for-byte keystrokes (arbitrary,
/// possibly non-UTF-8 bytes) without an encoding round trip on every single
/// byte typed, which defeats the point of a raw low-latency PTY pipe.
///
/// Only ever sent host -> guest (`fluxvm-vsock-client`'s caller encodes,
/// `fluxvm-guest-agent` decodes via [`PtyFrame::read_from`]). PTY output
/// flowing guest -> host stays completely unframed raw bytes: the guest
/// agent never has anything of its own to signal back mid-session, and
/// framing that direction too would force every reader of PTY output
/// (a terminal emulator on the other end) to speak this protocol instead
/// of just rendering bytes as they arrive.
///
/// This is deliberately in-band on the *same* connection rather than a
/// second control connection identified by a session ID — the pattern
/// `fluxvm-container-protocol`'s `ResizePty` uses for exec sessions, where
/// a long-lived container-agent process already keeps a registry of live
/// sessions to address into. The plain guest agent's `OpenShell` handler
/// deliberately has no such registry: each session runs in its own
/// double-forked, fully detached process specifically so the long-lived
/// vsock listener never keeps a handle on it (see `docs/operations.md`'s
/// "Fixed — process isolation" note on why that isolation exists). Adding
/// a session registry back into the listener just to address resize
/// commands would reintroduce the exact shared state that fix removed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PtyFrame {
    /// Bytes to write to the shell's stdin (keystrokes, pasted text, etc).
    Data(Vec<u8>),
    /// Resize the shell's PTY to `cols`x`rows`, effective immediately — the
    /// shell sees a real `SIGWINCH`, exactly as if a real terminal had been
    /// resized. No reconnect needed, and no acknowledgement is sent back:
    /// this is the same fire-and-forget guarantee level as a keystroke.
    Resize { cols: u16, rows: u16 },
}

impl PtyFrame {
    /// Encodes this frame for the wire: `[tag][type-specific bytes]`. A
    /// `Data` frame is `[0][len: u32 big-endian][len bytes]`; a `Resize`
    /// frame is `[1][cols: u16 big-endian][rows: u16 big-endian]`.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            PtyFrame::Data(bytes) => {
                let mut out = Vec::with_capacity(5 + bytes.len());
                out.push(PTY_FRAME_TAG_DATA);
                out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
                out.extend_from_slice(bytes);
                out
            }
            PtyFrame::Resize { cols, rows } => {
                let mut out = Vec::with_capacity(5);
                out.push(PTY_FRAME_TAG_RESIZE);
                out.extend_from_slice(&cols.to_be_bytes());
                out.extend_from_slice(&rows.to_be_bytes());
                out
            }
        }
    }

    /// Blocks until one full frame has been read from `r`. Returns
    /// `Ok(None)` on a clean EOF *before* any byte of a new frame arrives
    /// (the connection closing between frames — the normal way an
    /// `OpenShell` session ends). An EOF *mid*-frame, an oversized `Data`
    /// length header (over [`MAX_PTY_FRAME_BYTES`]), or an unrecognized tag
    /// byte are all reported as `Err` rather than silently truncating,
    /// accepting a partial frame, or best-effort-guessing at an unknown
    /// tag's shape — matching this crate's fail-closed convention on the
    /// wire (a malformed frame ends the session, it doesn't get
    /// half-interpreted).
    pub fn read_from<R: std::io::Read>(r: &mut R) -> std::io::Result<Option<PtyFrame>> {
        let mut tag = [0u8; 1];
        if r.read(&mut tag)? == 0 {
            return Ok(None);
        }
        match tag[0] {
            PTY_FRAME_TAG_DATA => {
                let mut len_buf = [0u8; 4];
                r.read_exact(&mut len_buf)?;
                let len = u32::from_be_bytes(len_buf) as usize;
                if len > MAX_PTY_FRAME_BYTES {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "pty data frame of {len} bytes exceeds the {MAX_PTY_FRAME_BYTES}-byte limit"
                        ),
                    ));
                }
                let mut payload = vec![0u8; len];
                r.read_exact(&mut payload)?;
                Ok(Some(PtyFrame::Data(payload)))
            }
            PTY_FRAME_TAG_RESIZE => {
                let mut buf = [0u8; 4];
                r.read_exact(&mut buf)?;
                let cols = u16::from_be_bytes([buf[0], buf[1]]);
                let rows = u16::from_be_bytes([buf[2], buf[3]]);
                Ok(Some(PtyFrame::Resize { cols, rows }))
            }
            other => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unknown pty frame tag {other}"),
            )),
        }
    }
}

/// Serializes `value` as one line of JSON terminated by `\n`, ready to write
/// directly to a socket.
pub fn encode_line<T: Serialize>(value: &T) -> serde_json::Result<String> {
    let mut line = serde_json::to_string(value)?;
    line.push('\n');
    Ok(line)
}

/// Parses one previously-`encode_line`d JSON line (trailing newline
/// tolerated but not required).
pub fn decode_line<T: for<'de> Deserialize<'de>>(line: &str) -> serde_json::Result<T> {
    serde_json::from_str(line.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_only_identical_strings() {
        assert!(constant_time_eq("secret", "secret"));
        assert!(!constant_time_eq("secret", "wrong"));
        assert!(!constant_time_eq("secret", "secre"));
        assert!(!constant_time_eq("", "x"));
        assert!(constant_time_eq("", ""));
    }

    #[test]
    fn envelope_round_trips_with_flattened_request() {
        let env = Envelope::new(
            Some("tok".into()),
            AgentRequest::Exec {
                command: "echo hi".into(),
                timeout_seconds: Some(5),
            },
        );
        let line = encode_line(&env).unwrap();
        assert!(line.contains("\"token\":\"tok\""));
        assert!(line.contains("\"op\":\"exec\""));
        let back: Envelope = decode_line(&line).unwrap();
        assert_eq!(back.token.as_deref(), Some("tok"));
        match back.request {
            AgentRequest::Exec {
                command,
                timeout_seconds,
            } => {
                assert_eq!(command, "echo hi");
                assert_eq!(timeout_seconds, Some(5));
            }
            other => panic!("unexpected request: {other:?}"),
        }
    }

    #[test]
    fn envelope_with_no_token_still_parses() {
        let line = "{\"op\":\"ping\"}\n";
        let env: Envelope = decode_line(line).unwrap();
        assert!(env.token.is_none());
        assert!(matches!(env.request, AgentRequest::Ping));
    }

    #[test]
    fn put_file_and_get_file_round_trip() {
        let put = AgentRequest::PutFile {
            path: "/etc/myapp/config.yaml".into(),
            content_base64: "aGVsbG8=".into(),
            mode: Some(0o600),
        };
        let line = encode_line(&put).unwrap();
        assert!(line.contains("\"op\":\"put-file\""));
        let back: AgentRequest = decode_line(&line).unwrap();
        match back {
            AgentRequest::PutFile {
                path,
                content_base64,
                mode,
            } => {
                assert_eq!(path, "/etc/myapp/config.yaml");
                assert_eq!(content_base64, "aGVsbG8=");
                assert_eq!(mode, Some(0o600));
            }
            other => panic!("unexpected request: {other:?}"),
        }

        let get = AgentRequest::GetFile {
            path: "/etc/myapp/config.yaml".into(),
        };
        let line = encode_line(&get).unwrap();
        assert!(line.contains("\"op\":\"get-file\""));

        let resp = AgentResponse::FileContent {
            content_base64: "aGVsbG8=".into(),
            mode: 0o600,
        };
        let line = encode_line(&resp).unwrap();
        assert!(line.contains("\"result\":\"file-content\""));
        let back: AgentResponse = decode_line(&line).unwrap();
        assert!(matches!(
            back,
            AgentResponse::FileContent { mode: 0o600, .. }
        ));
    }

    #[test]
    fn open_shell_defaults_cols_and_rows_when_omitted() {
        let line = "{\"op\":\"open-shell\"}\n";
        let req: AgentRequest = decode_line(line).unwrap();
        match req {
            AgentRequest::OpenShell { cols, rows } => {
                assert_eq!(cols, 80);
                assert_eq!(rows, 24);
            }
            other => panic!("unexpected request: {other:?}"),
        }

        let explicit = AgentRequest::OpenShell {
            cols: 120,
            rows: 40,
        };
        let line = encode_line(&explicit).unwrap();
        assert!(line.contains("\"cols\":120"));
        assert!(line.contains("\"rows\":40"));

        let opened = encode_line(&AgentResponse::ShellOpened).unwrap();
        assert!(opened.contains("\"result\":\"shell-opened\""));
    }

    #[test]
    fn pty_data_frame_round_trips() {
        let frame = PtyFrame::Data(b"echo hi\n".to_vec());
        let bytes = frame.encode();
        assert_eq!(bytes[0], PTY_FRAME_TAG_DATA);
        let mut cursor = std::io::Cursor::new(bytes);
        let back = PtyFrame::read_from(&mut cursor).unwrap().unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn pty_resize_frame_round_trips() {
        let frame = PtyFrame::Resize {
            cols: 132,
            rows: 43,
        };
        let bytes = frame.encode();
        assert_eq!(bytes, vec![PTY_FRAME_TAG_RESIZE, 0, 132, 0, 43]);
        let mut cursor = std::io::Cursor::new(bytes);
        let back = PtyFrame::read_from(&mut cursor).unwrap().unwrap();
        assert_eq!(back, frame);
    }

    #[test]
    fn pty_frame_stream_of_multiple_frames_reads_each_in_order() {
        let mut bytes = PtyFrame::Data(b"a".to_vec()).encode();
        bytes.extend(PtyFrame::Resize { cols: 1, rows: 2 }.encode());
        bytes.extend(PtyFrame::Data(b"b".to_vec()).encode());
        let mut cursor = std::io::Cursor::new(bytes);
        assert_eq!(
            PtyFrame::read_from(&mut cursor).unwrap().unwrap(),
            PtyFrame::Data(b"a".to_vec())
        );
        assert_eq!(
            PtyFrame::read_from(&mut cursor).unwrap().unwrap(),
            PtyFrame::Resize { cols: 1, rows: 2 }
        );
        assert_eq!(
            PtyFrame::read_from(&mut cursor).unwrap().unwrap(),
            PtyFrame::Data(b"b".to_vec())
        );
        assert!(PtyFrame::read_from(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn pty_frame_clean_eof_before_any_frame_is_none() {
        let mut cursor = std::io::Cursor::new(Vec::<u8>::new());
        assert!(PtyFrame::read_from(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn pty_frame_eof_mid_frame_is_an_error() {
        // A `Data` tag promising a length, but the connection closes before
        // even the length header arrives.
        let mut cursor = std::io::Cursor::new(vec![PTY_FRAME_TAG_DATA, 0, 0]);
        assert!(PtyFrame::read_from(&mut cursor).is_err());
    }

    #[test]
    fn pty_frame_oversized_data_length_is_rejected() {
        let mut bytes = vec![PTY_FRAME_TAG_DATA];
        bytes.extend(((MAX_PTY_FRAME_BYTES + 1) as u32).to_be_bytes());
        let mut cursor = std::io::Cursor::new(bytes);
        let err = PtyFrame::read_from(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn pty_frame_unknown_tag_is_rejected() {
        let mut cursor = std::io::Cursor::new(vec![0xFFu8]);
        let err = PtyFrame::read_from(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }
}
