use anyhow::{bail, Result};

/// Byteshift table used for decoding .l64 files.
struct ByteshiftTable {
    bytes: &'static [u8],
    offset: usize,
    mask: usize,
}

// ── Luau (FS25) tables ──────────────────────────────────────────────

/// Standard dataS/scripts table (versions 3 and 6).
const LUAU_TABLE_STD: ByteshiftTable = ByteshiftTable {
    bytes: &[0x02, 0x13, 0x0A, 0x08, 0x01, 0x07, 0x02, 0x02],
    offset: 0,
    mask: 0x07,
};

/// DLC scripts table (versions 3 and 6).
const LUAU_TABLE_DLC: ByteshiftTable = ByteshiftTable {
    bytes: &[
        0x14, 0x05, 0x0F, 0x0B, 0x01, 0x08, 0x02, 0x03,
        0x03, 0x08, 0x04, 0x03, 0x01, 0x04, 0x07, 0x08,
    ],
    offset: 0,
    mask: 0x0F,
};

// ── LuaJIT (FS17 / FS19 / FS22) tables ─────────────────────────────

const LUAJIT_TABLE_V3: ByteshiftTable = ByteshiftTable {
    bytes: &[0x14, 0x0B, 0x09, 0x02, 0x08, 0x03, 0x03, 0x03],
    offset: 4,
    mask: 0x07,
};

const LUAJIT_TABLE_V4: ByteshiftTable = ByteshiftTable {
    bytes: &[
        0x06, 0x10, 0x0C, 0x02, 0x09, 0x03, 0x04, 0x04,
        0x09, 0x05, 0x04, 0x02, 0x05, 0x08, 0x09, 0x15,
    ],
    offset: 4,
    mask: 0x0F,
};

// ── Format detection ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
enum Format {
    /// Luau bytecode (FS25). `version` is the Luau bytecode version,
    /// `is_dlc` selects the DLC byteshift table.
    Luau { is_dlc: bool },
    /// LuaJIT bytecode (FS17/19/22). `version` is the encoding version (3 or 4).
    LuaJIT { version: u8 },
}

fn detect_format(buf: &[u8]) -> Option<Format> {
    if buf.len() < 5 {
        return None;
    }

    // Luau encoded patterns (first 2–3 bytes)
    if buf[..3] == [0x03, 0x00, 0xF2] {
        return Some(Format::Luau { is_dlc: true });
    }
    match buf[..2] {
        [0x02, 0xEF] => return Some(Format::Luau { is_dlc: false }),
        [0x03, 0xFD] => return Some(Format::Luau { is_dlc: true }),
        [0x02, 0xF0] => return Some(Format::Luau { is_dlc: false }),
        [0x02, 0xF2] => return Some(Format::Luau { is_dlc: false }),
        _ => {}
    }

    // Already-decoded Luau (no encoding byte)
    match buf[0] {
        0x03 | 0x04 | 0x06 => {
            // Could be plain Luau bytecode — treat as already decoded
            return None;
        }
        _ => {}
    }

    // LuaJIT header: 1B 4C 4A
    if buf[..3] == [0x1B, 0x4C, 0x4A] {
        let ver = buf[3];
        if (ver == 3 || ver == 4) && (buf[4] == 0xFC || buf[4] == 0xFB) {
            return Some(Format::LuaJIT { version: ver });
        }
        // Valid LuaJIT but not encoded
        return None;
    }

    None
}

// ── Byte-shifting core ──────────────────────────────────────────────

fn shift_bytes(buf: &mut [u8], table: &ByteshiftTable) {
    for (i, byte) in buf.iter_mut().enumerate().skip(table.offset) {
        let key = table.bytes[i & table.mask];
        *byte = byte.wrapping_add(key).wrapping_add(i as u8);
    }
}

// ── Public API ──────────────────────────────────────────────────────

/// Decode a .l64 buffer **in place**, returning the decoded bytecode.
///
/// Returns `Ok(decoded_bytes)` on success.  The caller is responsible
/// for writing the result to disk.
pub fn decode_l64(raw: &[u8]) -> Result<Vec<u8>> {
    let fmt = detect_format(raw);

    let Some(fmt) = fmt else {
        bail!("File is not an encoded .l64 or is already decoded");
    };

    let mut buf = raw.to_vec();

    match fmt {
        Format::Luau { is_dlc } => {
            let table = if is_dlc { &LUAU_TABLE_DLC } else { &LUAU_TABLE_STD };
            shift_bytes(&mut buf, table);
            // Remove the leading encoding byte
            buf.remove(0);
        }
        Format::LuaJIT { version } => {
            let table = match version {
                3 => &LUAJIT_TABLE_V3,
                4 => &LUAJIT_TABLE_V4,
                _ => bail!("Unsupported LuaJIT encoding version {version}"),
            };
            shift_bytes(&mut buf, table);
            buf[3] = 0x02;
        }
    }

    Ok(buf)
}
