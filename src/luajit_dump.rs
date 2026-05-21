use anyhow::{bail, Result};
use std::fmt::Write;

const LUAJIT_HEADER: [u8; 3] = [0x1B, 0x4C, 0x4A];
const BC_F_STRIP: u8 = 0x02;

#[rustfmt::skip]
const OPNAMES: &[&str] = &[
    "ISLT",  "ISGE",  "ISLE",  "ISGT",   // 0-3
    "ISEQV", "ISNEV", "ISEQS", "ISNES",  // 4-7
    "ISEQN", "ISNEN", "ISEQP", "ISNEP",  // 8-11
    "ISTC",  "ISFC",  "IST",   "ISF",    // 12-15
    "ISTYPE","ISNUM", "MOV",   "NOT",    // 16-19
    "UNM",   "LEN",   "ADDVN", "SUBVN",  // 20-23
    "MULVN", "DIVVN", "MODVN", "ADDNV",  // 24-27
    "SUBNV", "MULNV", "DIVNV", "MODNV",  // 28-31
    "ADDVV", "SUBVV", "MULVV", "DIVVV",  // 32-35
    "MODVV", "POW",   "CAT",   "KSTR",   // 36-39
    "KCDATA","KSHORT","KNUM",  "KPRI",   // 40-43
    "KNIL",  "UGET",  "USETV", "USETS",  // 44-47
    "USETN", "USETP", "UCLO",  "FNEW",   // 48-51
    "TNEW",  "TDUP",  "GGET",  "GSET",   // 52-55
    "TGETV", "TGETS", "TGETB", "TGETR",  // 56-59
    "TSETV", "TSETS", "TSETB", "TSETM",  // 60-63
    "TSETR", "CALLM", "CALL",  "CALLMT", // 64-67
    "CALLT", "ITERC", "ITERN", "VARG",   // 68-71
    "ISNEXT","RETM",  "RET",   "RET0",   // 72-75
    "RET1",  "FORI",  "JFORI", "FORL",   // 76-79
    "IFORL", "JFORL", "ITERL", "IITERL", // 80-83
    "JITERL","LOOP",  "ILOOP", "JLOOP",  // 84-87
    "JMP",   "FUNCF", "IFUNCF","JFUNCF", // 88-91
    "FUNCV", "IFUNCV","JFUNCV","FUNCC",  // 92-95
    "FUNCCW",                             // 96
];

enum OpMode {
    AD,
    Abc,
}

fn op_mode(op: u8) -> OpMode {
    match op {
        22..=38 | 56 | 60 | 65..=66 | 71 => OpMode::Abc,
        _ => OpMode::AD,
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    fn read_u8(&mut self) -> Result<u8> {
        if self.pos >= self.data.len() {
            bail!("unexpected end of data");
        }
        let b = self.data[self.pos];
        self.pos += 1;
        Ok(b)
    }

    fn read_uleb128(&mut self) -> Result<u32> {
        let mut result = self.read_u8()? as u32;
        if result >= 0x80 {
            result &= 0x7F;
            let mut shift = 7u32;
            loop {
                let b = self.read_u8()? as u32;
                result |= (b & 0x7F) << shift;
                if b < 0x80 {
                    break;
                }
                shift += 7;
            }
        }
        Ok(result)
    }

    fn read_bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.pos + n > self.data.len() {
            bail!("unexpected end of data");
        }
        let slice = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(slice)
    }
}

pub fn disassemble_luajit(bytecode: &[u8]) -> Result<String> {
    let mut r = Reader::new(bytecode);
    let mut out = String::new();

    let h0 = r.read_u8()?;
    let h1 = r.read_u8()?;
    let h2 = r.read_u8()?;
    if [h0, h1, h2] != LUAJIT_HEADER {
        bail!("Not valid LuaJIT bytecode");
    }

    let version = r.read_u8()?;
    let flags = r.read_uleb128()? as u8;
    let is_stripped = (flags & BC_F_STRIP) != 0;

    writeln!(out, "-- LuaJIT bytecode v{version}")?;
    writeln!(
        out,
        "-- flags: 0x{flags:02X}{}",
        if is_stripped { " (stripped)" } else { "" }
    )?;

    if !is_stripped {
        let name_len = r.read_uleb128()? as usize;
        let name_bytes = r.read_bytes(name_len)?;
        let name = String::from_utf8_lossy(name_bytes);
        writeln!(out, "-- chunk: {name}")?;
    }

    writeln!(out)?;

    let mut proto_idx = 0u32;
    loop {
        let proto_size = r.read_uleb128()? as usize;
        if proto_size == 0 {
            break;
        }
        let proto_start = r.pos;

        let pflags = r.read_u8()?;
        let numparams = r.read_u8()?;
        let framesize = r.read_u8()?;
        let numuv = r.read_u8()?;
        let numkgc = r.read_uleb128()?;
        let numkn = r.read_uleb128()?;
        let numbc = r.read_uleb128()?;

        let mut dbg_size = 0u32;
        let mut first_line = 0u32;
        let mut num_lines = 0u32;
        if !is_stripped {
            dbg_size = r.read_uleb128()?;
            if dbg_size > 0 {
                first_line = r.read_uleb128()?;
                num_lines = r.read_uleb128()?;
            }
        }

        writeln!(out, "-- PROTO #{proto_idx}")?;
        writeln!(
            out,
            "--   params={numparams} framesize={framesize} upvalues={numuv} flags=0x{pflags:02X}"
        )?;
        if !is_stripped && dbg_size > 0 {
            writeln!(out, "--   lines {first_line}..{}", first_line + num_lines)?;
        }

        // Instructions
        let bc_bytes = r.read_bytes(numbc as usize * 4)?;
        for i in 0..numbc as usize {
            let off = i * 4;
            let op = bc_bytes[off];
            let a = bc_bytes[off + 1];
            let c = bc_bytes[off + 2];
            let b = bc_bytes[off + 3];
            let d = u16::from_le_bytes([c, b]);

            let name = if (op as usize) < OPNAMES.len() {
                OPNAMES[op as usize]
            } else {
                "???"
            };

            match op_mode(op) {
                OpMode::Abc => {
                    writeln!(out, "  {i:04}  {name:<10} {a:3} {b:3} {c:3}")?;
                }
                OpMode::AD => {
                    writeln!(out, "  {i:04}  {name:<10} {a:3} {d:5}")?;
                }
            }
        }

        // Upvalue refs
        if numuv > 0 {
            let uv_bytes = r.read_bytes(numuv as usize * 2)?;
            write!(out, "  -- upvalues:")?;
            for i in 0..numuv as usize {
                let uv = u16::from_le_bytes([uv_bytes[i * 2], uv_bytes[i * 2 + 1]]);
                write!(out, " {uv:04X}")?;
            }
            writeln!(out)?;
        }

        // KGC constants
        let mut kgc_strs: Vec<String> = Vec::new();
        for _ in 0..numkgc {
            let ty = r.read_uleb128()?;
            match ty {
                0 => {
                    kgc_strs.push("<child_proto>".to_string());
                }
                1 => {
                    let tab_narray = r.read_uleb128()?;
                    let tab_nhash = r.read_uleb128()?;
                    kgc_strs
                        .push(format!("<table narray={tab_narray} nhash={tab_nhash}>"));
                    // Skip table data
                    for _ in 0..tab_narray {
                        skip_ktab_val(&mut r)?;
                    }
                    for _ in 0..tab_nhash {
                        skip_ktab_val(&mut r)?;
                        skip_ktab_val(&mut r)?;
                    }
                }
                2 => {
                    let lo = r.read_uleb128()?;
                    let hi = r.read_uleb128()?;
                    kgc_strs.push(format!("<i64 {}>", ((hi as i64) << 32) | lo as i64));
                }
                3 => {
                    let lo = r.read_uleb128()?;
                    let hi = r.read_uleb128()?;
                    kgc_strs.push(format!("<u64 {}>", ((hi as u64) << 32) | lo as u64));
                }
                4 => {
                    let lo = r.read_uleb128()?;
                    let hi = r.read_uleb128()?;
                    let bits = ((hi as u64) << 32) | lo as u64;
                    let val = f64::from_bits(bits);
                    kgc_strs.push(format!("<complex {val}>"));
                }
                n if n >= 5 => {
                    let len = (n - 5) as usize;
                    let bytes = r.read_bytes(len)?;
                    let s = String::from_utf8_lossy(bytes);
                    kgc_strs.push(format!("\"{s}\""));
                }
                _ => {
                    kgc_strs.push(format!("<unknown_kgc type={ty}>"));
                }
            }
        }

        if !kgc_strs.is_empty() {
            writeln!(out, "  -- constants (gc):")?;
            for (i, s) in kgc_strs.iter().enumerate() {
                writeln!(out, "  --   [{i}] {s}")?;
            }
        }

        // KN constants (numbers)
        if numkn > 0 {
            writeln!(out, "  -- constants (num):")?;
            for i in 0..numkn {
                let lo = r.read_uleb128()?;
                let is_num = lo & 1;
                let lo = lo >> 1;
                if is_num != 0 {
                    let hi = r.read_uleb128()?;
                    let bits = ((hi as u64) << 32) | lo as u64;
                    let val = f64::from_bits(bits);
                    writeln!(out, "  --   [{i}] {val}")?;
                } else {
                    writeln!(out, "  --   [{i}] {lo}")?;
                }
            }
        }

        // Skip remaining proto data (debug info)
        let consumed = r.pos - proto_start;
        if consumed < proto_size {
            let skip = proto_size - consumed;
            r.read_bytes(skip)?;
        }

        writeln!(out)?;
        proto_idx += 1;
    }

    if r.remaining() > 0 {
        writeln!(out, "-- {} trailing bytes", r.remaining())?;
    }

    Ok(out)
}

fn skip_ktab_val(r: &mut Reader) -> Result<()> {
    let ty = r.read_uleb128()?;
    match ty {
        0..=2 => {} // nil, false, true
        3 => {
            r.read_uleb128()?;
        } // int
        4 => {
            r.read_uleb128()?;
            r.read_uleb128()?;
        } // num (lo+hi)
        n if n >= 5 => {
            let len = (n - 5) as usize;
            r.read_bytes(len)?;
        } // string
        _ => {}
    }
    Ok(())
}
