//! The newstyle NBD protocol (spec §B, §K S13).
//!
//! Only the parts a read-only export needs are implemented: the fixed-newstyle
//! handshake, the `LIST`, `INFO` and `GO` options (what modern `nbd-client`
//! uses) plus `EXPORT_NAME` (the older path), and the transmission phase with
//! `READ`, `DISC`, `FLUSH` and `TRIM`. Every write-like command is answered
//! with `EPERM`, and the export advertises `NBD_FLAG_READ_ONLY`, so a client
//! cannot mistake the device for writable.
//!
//! The protocol is defined by `nbd/doc/proto.md`; wire values are big-endian.

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use lr_core::{Error, Result};

use crate::backend::BlockBackend;

/// `"NBDMAGIC"`.
pub const NBDMAGIC: u64 = 0x4e42_444d_4147_4943;
/// `"IHAVEOPT"`.
pub const IHAVEOPT: u64 = 0x4948_4156_454f_5054;
/// Magic of an option reply.
pub const REP_MAGIC: u64 = 0x0003_e889_0455_65a9;
/// Magic of a transmission request.
pub const REQUEST_MAGIC: u32 = 0x2560_9513;
/// Magic of a transmission reply.
pub const SIMPLE_REPLY_MAGIC: u32 = 0x6744_6698;

/// Server handshake flags: fixed newstyle.
pub const FLAG_FIXED_NEWSTYLE: u16 = 1;
/// Server handshake flags: the client may skip the trailing zeroes.
pub const FLAG_NO_ZEROES: u16 = 2;
/// Client flag: it understood the fixed newstyle handshake.
pub const FLAG_C_FIXED_NEWSTYLE: u32 = 1;
/// Client flag: it does not want the 124 zero bytes.
pub const FLAG_C_NO_ZEROES: u32 = 2;

/// Transmission flags.
pub const FLAG_HAS_FLAGS: u16 = 1;
/// The export may only be read.
pub const FLAG_READ_ONLY: u16 = 2;
/// The export supports `NBD_CMD_FLUSH`.
pub const FLAG_SEND_FLUSH: u16 = 4;
/// The export supports `NBD_CMD_TRIM`.
pub const FLAG_SEND_TRIM: u16 = 32;

/// Options.
/// `NBD_OPT_EXPORT_NAME`: the old way to select the export.
pub const OPT_EXPORT_NAME: u32 = 1;
/// `NBD_OPT_ABORT`: the client gives up.
pub const OPT_ABORT: u32 = 2;
/// `NBD_OPT_LIST`: enumerate exports.
pub const OPT_LIST: u32 = 3;
/// `NBD_OPT_INFO`: ask for export details.
pub const OPT_INFO: u32 = 6;
/// `NBD_OPT_GO`: select the export and start the transmission phase.
pub const OPT_GO: u32 = 7;

/// Option reply types.
/// Acknowledged.
pub const REP_ACK: u32 = 1;
/// One listed export.
pub const REP_SERVER: u32 = 2;
/// One piece of export information.
pub const REP_INFO: u32 = 3;
/// An option the server does not implement.
pub const REP_ERR_UNSUP: u32 = 0x8000_0001;
/// An option with a bad argument.
pub const REP_ERR_INVALID: u32 = 0x8000_0003;

/// Information types for `NBD_OPT_INFO`/`NBD_OPT_GO`.
/// Export size and transmission flags.
pub const INFO_EXPORT: u16 = 0;
/// Export name.
pub const INFO_NAME: u16 = 1;
/// Minimum, preferred and maximum block sizes.
pub const INFO_BLOCK_SIZE: u16 = 3;

/// Commands.
/// Read `length` bytes at `offset`.
pub const CMD_READ: u16 = 0;
/// Write `length` bytes (refused: the export is read-only).
pub const CMD_WRITE: u16 = 1;
/// Disconnect.
pub const CMD_DISC: u16 = 2;
/// Flush the export (nothing is buffered; acknowledged).
pub const CMD_FLUSH: u16 = 3;
/// Mark a range as unused (nothing is stored; acknowledged).
pub const CMD_TRIM: u16 = 4;
/// Zero a range (refused: the export is read-only).
pub const CMD_WRITE_ZEROES: u16 = 6;

/// Error codes (`nbd`'s `enum nbd_error`).
/// Operation not permitted.
pub const ERR_PERM: u32 = 1;
/// I/O error.
pub const ERR_IO: u32 = 5;
/// Invalid argument.
pub const ERR_INVAL: u32 = 22;
/// Operation not supported.
pub const ERR_NOTSUP: u32 = 95;

/// How a served export presents itself.
#[derive(Debug, Clone)]
pub struct ExportConfig {
    /// Export name; an empty name is accepted for any request.
    pub name: String,
    /// Human-readable description, for `NBD_OPT_LIST`.
    pub description: String,
    /// Advertise (and enforce) read-only.
    pub read_only: bool,
}

impl Default for ExportConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            description: "LinuxReflect image".to_owned(),
            read_only: true,
        }
    }
}

impl ExportConfig {
    /// Transmission flags for this export.
    #[must_use]
    pub fn transmission_flags(&self) -> u16 {
        let mut flags = FLAG_HAS_FLAGS | FLAG_SEND_FLUSH | FLAG_SEND_TRIM;
        if self.read_only {
            flags |= FLAG_READ_ONLY;
        }
        flags
    }
}

/// Serve one connected client until it disconnects or `stop` is set.
///
/// # Errors
/// Returns [`Error::Io`] for transport failures and [`Error::Corrupt`] when the
/// client sends something the protocol does not allow.
pub fn serve_connection<S: Read + Write>(
    mut stream: S,
    backend: Arc<dyn BlockBackend>,
    config: &ExportConfig,
    stop: &AtomicBool,
) -> Result<()> {
    if !handshake(&mut stream, config)? {
        return Ok(());
    }
    if !option_haggling(&mut stream, &backend, config)? {
        return Ok(());
    }
    transmission(&mut stream, &backend, stop)
}

/// The fixed-newstyle handshake. `Ok(false)` means the client went away.
///
/// # Errors
/// Returns [`Error::Corrupt`] for a client flag the handshake forbids.
fn handshake<S: Read + Write>(stream: &mut S, _config: &ExportConfig) -> Result<bool> {
    write_u64(stream, NBDMAGIC)?;
    write_u64(stream, IHAVEOPT)?;
    write_u16(stream, FLAG_FIXED_NEWSTYLE | FLAG_NO_ZEROES)?;
    let client_flags = match read_u32(stream) {
        Ok(flags) => flags,
        Err(error) if is_disconnect(&error) => return Ok(false),
        Err(error) => return Err(error),
    };
    if client_flags & FLAG_C_FIXED_NEWSTYLE == 0 {
        return Err(Error::corrupt(
            "the client did not accept the fixed newstyle handshake",
        ));
    }
    Ok(true)
}

/// Option haggling; `Ok(false)` means the client aborted or went away.
///
/// # Errors
/// Returns [`Error::Io`] on transport failures.
fn option_haggling<S: Read + Write>(
    stream: &mut S,
    backend: &Arc<dyn BlockBackend>,
    config: &ExportConfig,
) -> Result<bool> {
    loop {
        let magic = match read_u64(stream) {
            Ok(magic) => magic,
            Err(error) if is_disconnect(&error) => return Ok(false),
            Err(error) => return Err(error),
        };
        if magic != IHAVEOPT {
            return Err(Error::corrupt(format!(
                "option magic {magic:#x} is not IHAVEOPT"
            )));
        }
        let option = read_u32(stream)?;
        let length = read_u32(stream)? as usize;
        let mut data = vec![0u8; length];
        stream.read_exact(&mut data).map_err(Error::Io)?;

        match option {
            OPT_EXPORT_NAME => {
                // Reply with the size, the transmission flags and (unless the
                // client asked to skip them) 124 zero bytes.
                let name = String::from_utf8_lossy(&data);
                if !config.name.is_empty() && name != config.name {
                    // EXPORT_NAME has no way to report an error; close.
                    tracing::warn!(%name, "unknown export name");
                    return Ok(false);
                }
                write_u64(stream, backend.size_bytes())?;
                write_u16(stream, config.transmission_flags())?;
                stream.flush().map_err(Error::Io)?;
                return Ok(true);
            }
            OPT_ABORT => {
                return Ok(false);
            }
            OPT_LIST => {
                let mut entry = Vec::new();
                entry.extend_from_slice(&(config.name.len() as u32).to_be_bytes());
                entry.extend_from_slice(config.name.as_bytes());
                entry.extend_from_slice(&(config.description.len() as u32).to_be_bytes());
                entry.extend_from_slice(config.description.as_bytes());
                option_reply(stream, option, REP_SERVER, &entry)?;
                option_reply(stream, option, REP_ACK, &[])?;
            }
            OPT_INFO | OPT_GO => {
                if length < 6 {
                    option_reply(stream, option, REP_ERR_INVALID, b"short info request")?;
                    continue;
                }
                let name_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
                if 4 + name_len + 2 > data.len() {
                    option_reply(stream, option, REP_ERR_INVALID, b"bad info request")?;
                    continue;
                }
                let name = String::from_utf8_lossy(&data[4..4 + name_len]).into_owned();
                if !config.name.is_empty() && name != config.name {
                    option_reply(stream, option, REP_ERR_UNSUP, b"unknown export")?;
                    continue;
                }
                let count_at = 4 + name_len;
                let requested = u16::from_be_bytes([data[count_at], data[count_at + 1]]) as usize;
                // `NBD_OPT_GO` has to answer with `NBD_INFO_EXPORT` whether or
                // not the client asked for it; without it a client cannot
                // learn the size (`qemu-img` refuses, `nbd-client` attaches a
                // device with a nonsense size). `NBD_OPT_INFO` is free to send
                // only what was requested, and a zero count means the default
                // set.
                let requested_infos: Vec<u16> = (0..requested)
                    .filter_map(|index| {
                        let at = count_at + 2 + index * 2;
                        data.get(at..at + 2)
                            .map(|bytes| u16::from_be_bytes([bytes[0], bytes[1]]))
                    })
                    .collect();
                let mut requests: Vec<u16> = if option == OPT_GO {
                    let mut list = vec![INFO_EXPORT];
                    list.extend(requested_infos);
                    list
                } else if requested == 0 {
                    vec![INFO_EXPORT, INFO_BLOCK_SIZE]
                } else {
                    requested_infos
                };
                requests.dedup();
                for info in &requests {
                    let info = *info;
                    match info {
                        INFO_EXPORT => {
                            // A `NBD_REP_INFO` payload starts with the info
                            // type, then its data.
                            let mut payload = Vec::with_capacity(12);
                            payload.extend_from_slice(&INFO_EXPORT.to_be_bytes());
                            payload.extend_from_slice(&backend.size_bytes().to_be_bytes());
                            payload.extend_from_slice(&config.transmission_flags().to_be_bytes());
                            option_reply(stream, option, REP_INFO, &payload)?;
                        }
                        INFO_NAME => {
                            let mut payload = Vec::with_capacity(2 + config.name.len());
                            payload.extend_from_slice(&INFO_NAME.to_be_bytes());
                            payload.extend_from_slice(config.name.as_bytes());
                            option_reply(stream, option, REP_INFO, &payload)?;
                        }
                        INFO_BLOCK_SIZE => {
                            let mut payload = Vec::with_capacity(14);
                            payload.extend_from_slice(&INFO_BLOCK_SIZE.to_be_bytes());
                            payload.extend_from_slice(&512u32.to_be_bytes());
                            payload.extend_from_slice(&4096u32.to_be_bytes());
                            payload.extend_from_slice(&(32 * 1024 * 1024u32).to_be_bytes());
                            option_reply(stream, option, REP_INFO, &payload)?;
                        }
                        _ => {}
                    }
                }
                option_reply(stream, option, REP_ACK, &[])?;
                stream.flush().map_err(Error::Io)?;
                if option == OPT_GO {
                    return Ok(true);
                }
            }
            other => {
                tracing::debug!(option = other, "unimplemented NBD option");
                option_reply(stream, other, REP_ERR_UNSUP, b"unsupported option")?;
            }
        }
    }
}

fn option_reply<S: Write>(
    stream: &mut S,
    option: u32,
    reply_type: u32,
    payload: &[u8],
) -> Result<()> {
    write_u64(stream, REP_MAGIC)?;
    write_u32(stream, option)?;
    write_u32(stream, reply_type)?;
    write_u32(stream, payload.len() as u32)?;
    stream.write_all(payload).map_err(Error::Io)?;
    stream.flush().map_err(Error::Io)?;
    Ok(())
}

/// The transmission phase: requests in, replies out, until `DISC` or EOF.
///
/// # Errors
/// Returns [`Error::Io`] on transport failures. Backend errors become NBD error
/// replies, so one unreadable chunk does not kill the export.
fn transmission<S: Read + Write>(
    stream: &mut S,
    backend: &Arc<dyn BlockBackend>,
    stop: &AtomicBool,
) -> Result<()> {
    let mut header = [0u8; 28];
    loop {
        if stop.load(Ordering::Relaxed) {
            return Ok(());
        }
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            Err(error) if io_disconnect(&error) => return Ok(()),
            Err(error) => return Err(Error::Io(error)),
        }
        let magic = u32::from_be_bytes([header[0], header[1], header[2], header[3]]);
        if magic != REQUEST_MAGIC {
            return Err(Error::corrupt(format!(
                "request magic {magic:#x} is not {REQUEST_MAGIC:#x}"
            )));
        }
        let _flags = u16::from_be_bytes([header[4], header[5]]);
        let command = u16::from_be_bytes([header[6], header[7]]);
        let handle = u64::from_be_bytes(header[8..16].try_into().unwrap_or_default());
        let offset = u64::from_be_bytes(header[16..24].try_into().unwrap_or_default());
        let length = u32::from_be_bytes(header[24..28].try_into().unwrap_or_default());

        match command {
            CMD_READ => {
                let capacity = usize::try_from(length).unwrap_or(usize::MAX);
                let mut buffer = vec![0u8; capacity];
                match read_backend(backend, offset, &mut buffer) {
                    Ok(()) => {
                        write_u32(stream, SIMPLE_REPLY_MAGIC)?;
                        write_u32(stream, 0)?;
                        write_u64(stream, handle)?;
                        stream.write_all(&buffer).map_err(Error::Io)?;
                        stream.flush().map_err(Error::Io)?;
                    }
                    Err(error) => {
                        tracing::warn!(%error, offset, length, "NBD read failed");
                        let code = match error {
                            Error::BadSector { .. } => ERR_IO,
                            _ => ERR_IO,
                        };
                        simple_error(stream, code, handle)?;
                    }
                }
            }
            CMD_DISC => return Ok(()),
            CMD_FLUSH => simple_error(stream, 0, handle)?,
            CMD_TRIM => simple_error(stream, 0, handle)?,
            CMD_WRITE | CMD_WRITE_ZEROES => {
                // Read-only export: refuse, and say why.
                simple_error(stream, ERR_PERM, handle)?;
            }
            other => {
                tracing::debug!(command = other, "unknown NBD command");
                simple_error(stream, ERR_NOTSUP, handle)?;
            }
        }
    }
}

fn read_backend(backend: &Arc<dyn BlockBackend>, offset: u64, buffer: &mut [u8]) -> Result<()> {
    let size = backend.size_bytes();
    let end = offset
        .checked_add(buffer.len() as u64)
        .ok_or_else(|| Error::corrupt("NBD read overflows the address space"))?;
    if end > size {
        return Err(Error::corrupt(format!(
            "NBD read of {} bytes at {offset} is past the end of the {size}-byte export",
            buffer.len()
        )));
    }
    backend.read_at(offset, buffer)
}

fn simple_error<S: Write>(stream: &mut S, code: u32, handle: u64) -> Result<()> {
    write_u32(stream, SIMPLE_REPLY_MAGIC)?;
    write_u32(stream, code)?;
    write_u64(stream, handle)?;
    stream.flush().map_err(Error::Io)?;
    Ok(())
}

fn io_disconnect(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::UnexpectedEof
            | ErrorKind::ConnectionReset
            | ErrorKind::ConnectionAborted
            | ErrorKind::BrokenPipe
    )
}

fn is_disconnect(error: &Error) -> bool {
    match error {
        Error::Io(io) => matches!(
            io.kind(),
            ErrorKind::UnexpectedEof
                | ErrorKind::ConnectionReset
                | ErrorKind::ConnectionAborted
                | ErrorKind::BrokenPipe
        ),
        _ => false,
    }
}

fn read_u32<S: Read>(stream: &mut S) -> Result<u32> {
    let mut bytes = [0u8; 4];
    stream.read_exact(&mut bytes).map_err(Error::Io)?;
    Ok(u32::from_be_bytes(bytes))
}

fn read_u64<S: Read>(stream: &mut S) -> Result<u64> {
    let mut bytes = [0u8; 8];
    stream.read_exact(&mut bytes).map_err(Error::Io)?;
    Ok(u64::from_be_bytes(bytes))
}

fn write_u16<S: Write>(stream: &mut S, value: u16) -> Result<()> {
    stream.write_all(&value.to_be_bytes()).map_err(Error::Io)
}

fn write_u32<S: Write>(stream: &mut S, value: u32) -> Result<()> {
    stream.write_all(&value.to_be_bytes()).map_err(Error::Io)
}

fn write_u64<S: Write>(stream: &mut S, value: u64) -> Result<()> {
    stream.write_all(&value.to_be_bytes()).map_err(Error::Io)
}

/// Accept loop over a Unix socket; returns when `stop` is set.
///
/// # Errors
/// Returns [`Error::Io`] for listener failures.
pub fn serve_unix(
    socket: &std::path::Path,
    backend: Arc<dyn BlockBackend>,
    config: ExportConfig,
    stop: Arc<AtomicBool>,
) -> Result<()> {
    let listener = std::os::unix::net::UnixListener::bind(socket).map_err(Error::Io)?;
    listener.set_nonblocking(true).map_err(Error::Io)?;
    let _ = std::fs::set_permissions(socket, std::os::unix::fs::PermissionsExt::from_mode(0o600));
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                // No read timeout: an idle mounted filesystem must keep its
                // connection, and a timeout would look like a device failure.
                // The client ends the connection with `nbd-client -d`.
                if let Err(error) = serve_connection(stream, Arc::clone(&backend), &config, &stop) {
                    tracing::warn!(%error, "NBD client ended with an error");
                }
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(error) => return Err(Error::Io(error)),
        }
    }
    let _ = std::fs::remove_file(socket);
    Ok(())
}
