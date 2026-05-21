use anyhow::{bail, Result};

struct ByteshiftTable {
    bytes: &'static [u8],
    offset: usize,
    mask: usize,
}

// ── Luau (FS25) tables ──────────────────────────────────────────────

const LUAU_TABLE_STD: ByteshiftTable = ByteshiftTable {
    bytes: &[0x02, 0x13, 0x0A, 0x08, 0x01, 0x07, 0x02, 0x02],
    offset: 0,
    mask: 0x07,
};

const LUAU_TABLE_DLC: ByteshiftTable = ByteshiftTable {
    bytes: &[
        0x14, 0x05, 0x0F, 0x0B, 0x01, 0x08, 0x02, 0x03, 0x03, 0x08, 0x04, 0x03, 0x01, 0x04,
        0x07, 0x08,
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
        0x06, 0x10, 0x0C, 0x02, 0x09, 0x03, 0x04, 0x04, 0x09, 0x05, 0x04, 0x02, 0x05, 0x08,
        0x09, 0x15,
    ],
    offset: 4,
    mask: 0x0F,
};

// ── Target enum ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Fs19,
    Fs20,
    Fs22,
    Fs23,
    Fs25,
    Fs26,
}

impl std::fmt::Display for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Target::Fs19 => write!(f, "fs19"),
            Target::Fs20 => write!(f, "fs20"),
            Target::Fs22 => write!(f, "fs22"),
            Target::Fs23 => write!(f, "fs23"),
            Target::Fs25 => write!(f, "fs25"),
            Target::Fs26 => write!(f, "fs26"),
        }
    }
}

impl std::str::FromStr for Target {
    type Err = String;
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "fs19" => Ok(Target::Fs19),
            "fs20" => Ok(Target::Fs20),
            "fs22" => Ok(Target::Fs22),
            "fs23" => Ok(Target::Fs23),
            "fs25" => Ok(Target::Fs25),
            "fs26" => Ok(Target::Fs26),
            _ => Err(format!(
                "unknown target '{}' (expected: fs19, fs20, fs22, fs23, fs25, fs26)",
                s
            )),
        }
    }
}

impl Target {
    pub fn is_luajit(self) -> bool {
        matches!(self, Target::Fs19 | Target::Fs20 | Target::Fs22)
    }
}

// ── Format detection ────────────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
pub enum Format {
    Luau { is_dlc: bool },
    LuaJIT { version: u8 },
}

pub fn detect_format(buf: &[u8]) -> Option<Format> {
    if buf.len() < 5 {
        return None;
    }

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

    match buf[0] {
        0x03 | 0x04 | 0x06 => {
            return None;
        }
        _ => {}
    }

    if buf[..3] == [0x1B, 0x4C, 0x4A] {
        let ver = buf[3];
        if (ver == 3 || ver == 4) && (buf[4] == 0xFC || buf[4] == 0xFB) {
            return Some(Format::LuaJIT { version: ver });
        }
        return None;
    }

    None
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BytecodeInfo {
    LuaJIT,
    Luau { version: u8 },
}

impl std::fmt::Display for BytecodeInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BytecodeInfo::LuaJIT => write!(f, "luajit"),
            BytecodeInfo::Luau { version } => write!(f, "luau-v{version}"),
        }
    }
}

impl BytecodeInfo {
    pub fn language(&self) -> &'static str {
        match self {
            BytecodeInfo::LuaJIT => "luajit",
            BytecodeInfo::Luau { .. } => "luau",
        }
    }
}

/// Detect whether raw bytecode is Luau or LuaJIT (unencrypted),
/// including the Luau bytecode version (e.g. v3, v6).
pub fn detect_bytecode_format(buf: &[u8]) -> Option<BytecodeInfo> {
    if buf.len() < 4 {
        return None;
    }
    if buf[..3] == [0x1B, 0x4C, 0x4A] {
        return Some(BytecodeInfo::LuaJIT);
    }
    if matches!(buf[0], 0x03..=0x06) {
        return Some(BytecodeInfo::Luau { version: buf[0] });
    }
    None
}

// ── Byte-shifting ───────────────────────────────────────────────────

fn shift_decode(buf: &mut [u8], table: &ByteshiftTable) {
    for (i, byte) in buf.iter_mut().enumerate().skip(table.offset) {
        let key = table.bytes[i & table.mask];
        *byte = byte.wrapping_add(key).wrapping_add(i as u8);
    }
}

fn shift_encode(buf: &mut [u8], table: &ByteshiftTable) {
    for (i, byte) in buf.iter_mut().enumerate().skip(table.offset) {
        let key = table.bytes[i & table.mask];
        *byte = byte.wrapping_sub(key).wrapping_sub(i as u8);
    }
}

// ── Public API ──────────────────────────────────────────────────────

pub fn decode_l64(raw: &[u8]) -> Result<Vec<u8>> {
    let fmt = detect_format(raw);

    let Some(fmt) = fmt else {
        bail!("File is not an encoded .l64 or is already decoded");
    };

    let mut buf = raw.to_vec();

    match fmt {
        Format::Luau { is_dlc } => {
            let table = if is_dlc {
                &LUAU_TABLE_DLC
            } else {
                &LUAU_TABLE_STD
            };
            shift_decode(&mut buf, table);
            buf.remove(0);
        }
        Format::LuaJIT { version } => {
            let table = match version {
                3 => &LUAJIT_TABLE_V3,
                4 => &LUAJIT_TABLE_V4,
                _ => bail!("Unsupported LuaJIT encoding version {version}"),
            };
            shift_decode(&mut buf, table);
            buf[3] = 0x02;
        }
    }

    Ok(buf)
}

const LUAU_STD_MARKER: u8 = 0x04;

pub fn encode_l64(bytecode: &[u8], target: Target) -> Result<Vec<u8>> {
    match target {
        Target::Fs23 | Target::Fs25 | Target::Fs26 => encode_luau(bytecode),
        Target::Fs19 | Target::Fs20 => encode_luajit(bytecode, 3),
        Target::Fs22 => encode_luajit(bytecode, 4),
    }
}

fn encode_luau(bytecode: &[u8]) -> Result<Vec<u8>> {
    if bytecode.is_empty() {
        bail!("Empty bytecode");
    }

    let mut buf = Vec::with_capacity(bytecode.len() + 1);
    buf.push(LUAU_STD_MARKER);
    buf.extend_from_slice(bytecode);
    shift_encode(&mut buf, &LUAU_TABLE_STD);
    Ok(buf)
}

fn encode_luajit(bytecode: &[u8], encoding_version: u8) -> Result<Vec<u8>> {
    if bytecode.len() < 5 {
        bail!("Bytecode too short for LuaJIT format");
    }

    if bytecode[..3] != [0x1B, 0x4C, 0x4A] {
        bail!(
            "Not valid LuaJIT bytecode (expected header 1B 4C 4A, got {:02X} {:02X} {:02X})",
            bytecode[0],
            bytecode[1],
            bytecode[2]
        );
    }

    let mut buf = bytecode.to_vec();
    buf[3] = encoding_version;

    let table = match encoding_version {
        3 => &LUAJIT_TABLE_V3,
        4 => &LUAJIT_TABLE_V4,
        _ => bail!("Unsupported LuaJIT encoding version {encoding_version}"),
    };

    shift_encode(&mut buf, table);
    Ok(buf)
}
