use bytemuck::Pod;
use std::convert::TryFrom;
use std::mem;
use std::string::String;
use std::vec::Vec;

#[allow(non_snake_case)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum LuauOpcode {
    LOP_NOP,
    LOP_BREAK,
    LOP_LOADNIL,
    LOP_LOADB,
    LOP_LOADN,
    LOP_LOADK,
    LOP_MOVE,
    LOP_GETGLOBAL,
    LOP_SETGLOBAL,
    LOP_GETUPVAL,
    LOP_SETUPVAL,
    LOP_CLOSEUPVALS,
    LOP_GETIMPORT,
    LOP_GETTABLE,
    LOP_SETTABLE,
    LOP_GETTABLEKS,
    LOP_SETTABLEKS,
    LOP_GETTABLEN,
    LOP_SETTABLEN,
    LOP_NEWCLOSURE,
    LOP_NAMECALL,
    LOP_CALL,
    LOP_RETURN,
    LOP_JUMP,
    LOP_JUMPBACK,
    LOP_JUMPIF,
    LOP_JUMPIFNOT,
    LOP_JUMPIFEQ,
    LOP_JUMPIFLE,
    LOP_JUMPIFLT,
    LOP_JUMPIFNOTEQ,
    LOP_JUMPIFNOTLE,
    LOP_JUMPIFNOTLT,
    LOP_ADD,
    LOP_SUB,
    LOP_MUL,
    LOP_DIV,
    LOP_MOD,
    LOP_POW,
    LOP_ADDK,
    LOP_SUBK,
    LOP_MULK,
    LOP_DIVK,
    LOP_MODK,
    LOP_POWK,
    LOP_AND,
    LOP_OR,
    LOP_ANDK,
    LOP_ORK,
    LOP_CONCAT,
    LOP_NOT,
    LOP_MINUS,
    LOP_LENGTH,
    LOP_NEWTABLE,
    LOP_DUPTABLE,
    LOP_SETLIST,
    LOP_FORNPREP,
    LOP_FORNLOOP,
    LOP_FORGLOOP,
    LOP_FORGPREP_INEXT,
    LOP_FASTCALL3,
    LOP_FORGPREP_NEXT,
    LOP_NATIVECALL,
    LOP_GETVARARGS,
    LOP_DUPCLOSURE,
    LOP_PREPVARARGS,
    LOP_LOADKX,
    LOP_JUMPX,
    LOP_FASTCALL,
    LOP_COVERAGE,
    LOP_CAPTURE,
    LOP_SUBRK,
    LOP_DIVRK,
    LOP_FASTCALL1,
    LOP_FASTCALL2,
    LOP_FASTCALL2K,
    LOP_FORGPREP,
    LOP_JUMPXEQKNIL,
    LOP_JUMPXEQKB,
    LOP_JUMPXEQKN,
    LOP_JUMPXEQKS,
    LOP_IDIV,
    LOP_IDIVK,
    LOP__COUNT,
}

#[derive(Debug)]
pub enum InstructionFormat {
    ABC,
    AD,
    E,
}

#[derive(Debug)]
pub enum ConstantType {
    LBC_CONSTANT_NIL,
    LBC_CONSTANT_BOOLEAN,
    LBC_CONSTANT_NUMBER,
    LBC_CONSTANT_VECTOR,
    LBC_CONSTANT_STRING,
    LBC_CONSTANT_IMPORT,
    LBC_CONSTANT_TABLE,
    LBC_CONSTANT_TABLE_WITH_CONSTANTS,
    LBC_CONSTANT_CLOSURE,
}

#[derive(Debug, Clone, Copy)]
pub struct Instruction {
    pub opcode: u8,
    pub a: u8,
    pub b: u8,
    pub c: u8,
    pub d: i16,
    pub e: i32,
    pub aux: u32,
}

#[derive(Debug, Clone)]
pub struct Proto {
    pub source: String,
    pub bytecodeid: i32,
    pub maxstacksize: u8,
    pub numparams: u8,
    pub nups: u8,
    pub is_vararg: u8,
    pub flags: u8,
    pub typeinfo: Vec<u8>,
    pub sizetypeinfo: usize,
    pub code: Vec<u32>,
    pub sizecode: usize,
    pub k: Vec<Constant>,
    pub sizek: usize,
    pub p: Vec<Proto>,
    pub child_proto_indices: Vec<usize>,
    pub sizep: usize,
    pub linedefined: u32,
    pub debugname: String,
    pub linegaplog2: u8,
    pub lineinfo: Vec<u8>,
    pub sizelineinfo: usize,
    pub abslineinfo: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Constant {
    Nil,
    Boolean(bool),
    Number(f64),
    Vector(f32, f32, f32, f32),
    String(String),
    Import(u32),
    Table(Vec<(usize, f64)>),
    TableWithConstants(Vec<(usize, Constant)>),
    Closure(usize),
    Integer(i64),
}

#[derive(Debug)]
pub struct BytecodeFile {
    pub version: u8,
    pub types_version: u8,
    pub strings: Vec<String>,
    pub protos: Vec<Proto>,
    pub main_proto: Option<usize>,
}

/// Minimum Luau bytecode version accepted by the FS23 runtime.
/// Based on `luau_load` pseudoC: `expected [3..3]`.
pub const LBC_VERSION_MIN: u8 = 3;
/// Maximum Luau bytecode version accepted by the FS23 runtime.
pub const LBC_VERSION_MAX: u8 = 3;

pub struct BytecodeReader<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> BytecodeReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        BytecodeReader { data, offset: 0 }
    }

    fn ensure(&self, n: usize) -> Result<(), String> {
        if self.offset + n > self.data.len() {
            Err(format!(
                "truncated bytecode: tried to read {} bytes at offset {} (data len {})",
                n,
                self.offset,
                self.data.len()
            ))
        } else {
            Ok(())
        }
    }

    pub fn read<T: Sized + Copy + Pod>(&mut self) -> Result<T, String> {
        let size = mem::size_of::<T>();
        self.ensure(size)?;
        let slice = &self.data[self.offset..self.offset + size];
        self.offset += size;
        Ok(bytemuck::pod_read_unaligned(slice))
    }

    pub fn read_var_int(&mut self) -> Result<u32, String> {
        let mut result = 0u32;
        let mut shift = 0u32;

        loop {
            let byte: u8 = self.read()?;
            result |= ((byte & 127) as u32) << shift;
            shift += 7;
            if (byte & 128) == 0 {
                break;
            }
            if shift >= 35 {
                return Err(format!(
                    "varint overflow at offset {} (>=5 continuation bytes)",
                    self.offset
                ));
            }
        }
        Ok(result)
    }

    pub fn read_var_int64(&mut self) -> Result<u64, String> {
        let mut result = 0u64;
        let mut shift = 0u32;

        loop {
            let byte: u8 = self.read()?;
            result |= ((byte & 127) as u64) << shift;
            shift += 7;
            if (byte & 128) == 0 {
                break;
            }
            if shift >= 70 {
                return Err(format!(
                    "varint64 overflow at offset {} (>=10 continuation bytes)",
                    self.offset
                ));
            }
        }
        Ok(result)
    }

    pub fn read_string(&mut self, strings: &[String]) -> Result<String, String> {
        let id = self.read_var_int()?;
        if id == 0 {
            Ok(String::new())
        } else {
            let idx = (id - 1) as usize;
            strings
                .get(idx)
                .cloned()
                .ok_or_else(|| format!("string id {} out of range (have {})", id, strings.len()))
        }
    }

    pub fn read_bytecode_file(&mut self) -> Result<BytecodeFile, String> {
        // loadBuffer in the game strips a leading `0x01` sentinel before
        // handing the blob to luau_load: see pseudoC/loadBuffer_00bb6f84.c.
        // We mirror that normalization so callers can feed us the raw `01 03`
        // stream produced by `decode_l64`.
        if self.data.get(..2) == Some(&[0x01, 0x03]) {
            self.offset = 1;
        }

        let version: u8 = self.read()?;

        if version == 0 {
            // The runtime encodes a compile error as `\0<message>`; surface it.
            let msg = std::str::from_utf8(&self.data[self.offset..]).unwrap_or("Invalid UTF-8");
            return Err(format!("compile error payload: {}", msg));
        }

        if !(LBC_VERSION_MIN..=LBC_VERSION_MAX).contains(&version) {
            return Err(format!(
                "bytecode version mismatch (expected [{}..{}], got {})",
                LBC_VERSION_MIN, LBC_VERSION_MAX, version
            ));
        }

        let types_version = if version >= 4 { self.read::<u8>()? } else { 0 };

        // Read strings
        let string_count = self.read_var_int()?;
        let mut strings = Vec::with_capacity(string_count as usize);
        for _ in 0..string_count {
            let length = self.read_var_int()? as usize;
            self.ensure(length)?;
            let slice = &self.data[self.offset..self.offset + length];
            self.offset += length;
            strings.push(String::from_utf8_lossy(slice).to_string());
        }

        // userdata type remapping table (types_version == 3) - not used in FS23 (v3).

        // Read protos
        let proto_count = self.read_var_int()?;
        let mut protos = Vec::with_capacity(proto_count as usize);
        for i in 0..proto_count {
            let bytecodeid = i as i32;

            let maxstacksize = self.read::<u8>()?;
            let numparams = self.read::<u8>()?;
            let nups = self.read::<u8>()?;
            let is_vararg = self.read::<u8>()?;

            let mut flags = 0;
            if version >= 4 {
                flags = self.read::<u8>()?;

                if types_version == 1 || types_version == 2 || types_version == 3 {
                    let typesize = self.read_var_int()? as usize;
                    self.ensure(typesize)?;
                    self.offset += typesize;
                }
            }

            let sizecode = self.read_var_int()? as usize;
            let mut code = Vec::with_capacity(sizecode);
            for _ in 0..sizecode {
                code.push(self.read::<u32>()?);
            }

            let sizek = self.read_var_int()? as usize;
            let mut k = Vec::with_capacity(sizek);
            for _ in 0..sizek {
                let constant_type = self.read::<u8>()?;
                match constant_type {
                    0 => k.push(Constant::Nil),
                    1 => k.push(Constant::Boolean(self.read::<u8>()? != 0)),
                    2 => k.push(Constant::Number(self.read::<f64>()?)),
                    3 => k.push(Constant::String(self.read_string(&strings)?)),
                    4 => k.push(Constant::Import(self.read::<u32>()?)),
                    5 => {
                        let keys = self.read_var_int()? as usize;
                        let mut table_entries = Vec::with_capacity(keys);
                        for _ in 0..keys {
                            let key_idx = self.read_var_int()? as usize;
                            // In LBC v3 table constants, values are implicit nil.
                            table_entries.push((key_idx, 0.0));
                        }
                        k.push(Constant::Table(table_entries));
                    }
                    6 => k.push(Constant::Closure(self.read_var_int()? as usize)),
                    // tags 7/8/9 are not supported by the FS23 Luau runtime
                    // (`luau_load` only handles 0..=6). Accept them for
                    // forward-compat when parsing upstream Luau blobs.
                    7 => {
                        if version < 4 {
                            return Err(format!(
                                "unsupported constant type {} (Vector) in LBC v{} (proto {}, offset {})",
                                constant_type, version, i, self.offset
                            ));
                        }
                        k.push(Constant::Vector(
                            self.read::<f32>()?,
                            self.read::<f32>()?,
                            self.read::<f32>()?,
                            self.read::<f32>()?,
                        ));
                    }
                    8 => {
                        if version < 4 {
                            return Err(format!(
                                "unsupported constant type {} (TableWithConstants) in LBC v{} (proto {}, offset {})",
                                constant_type, version, i, self.offset
                            ));
                        }
                        let keys = self.read_var_int()? as usize;
                        let mut table_entries = Vec::with_capacity(keys);
                        for _ in 0..keys {
                            let key_idx = self.read_var_int()? as usize;
                            let _constant_idx = self.read::<i32>()?;
                            table_entries.push((key_idx, Constant::Nil));
                        }
                        k.push(Constant::TableWithConstants(table_entries));
                    }
                    9 => {
                        if version < 4 {
                            return Err(format!(
                                "unsupported constant type {} (Integer) in LBC v{} (proto {}, offset {})",
                                constant_type, version, i, self.offset
                            ));
                        }
                        let is_negative = self.read::<u8>()? != 0;
                        let magnitude = self.read_var_int64()?;
                        let value = if is_negative {
                            (!magnitude).wrapping_add(1) as i64
                        } else {
                            magnitude as i64
                        };
                        k.push(Constant::Integer(value));
                    }
                    _ => {
                        return Err(format!(
                            "Unknown constant type: {} (proto {}, constant {}, offset {})",
                            constant_type,
                            i,
                            k.len(),
                            self.offset
                        ));
                    }
                }
            }

            let sizep = self.read_var_int()? as usize;
            let mut child_proto_ids = Vec::with_capacity(sizep);
            for _ in 0..sizep {
                child_proto_ids.push(self.read_var_int()? as usize);
            }

            let linedefined = self.read_var_int()?;
            let debugname = self.read_string(&strings)?;

            let lineinfo_flag = self.read::<u8>()?;
            let mut linegaplog2 = 0;
            let mut lineinfo = Vec::new();
            let mut abslineinfo = Vec::new();

            if lineinfo_flag != 0 {
                linegaplog2 = self.read::<u8>()?;
                // In LBC v3 lineinfo layout, the number of absolute line
                // intervals is `((sizecode - 1) >> linegaplog2) + 1` when
                // sizecode > 0.
                let intervals = if sizecode == 0 {
                    0
                } else {
                    ((sizecode - 1) >> linegaplog2) + 1
                };

                let mut last_offset: u8 = 0;
                for _ in 0..sizecode {
                    last_offset = last_offset.wrapping_add(self.read::<u8>()?);
                    lineinfo.push(last_offset);
                }

                let mut last_line: i32 = 0;
                for _ in 0..intervals {
                    last_line = last_line.wrapping_add(self.read::<i32>()?);
                    abslineinfo.push(last_line);
                }
            }

            let debuginfo_flag = self.read::<u8>()?;
            if debuginfo_flag != 0 {
                let sizelocvars = self.read_var_int()?;
                for _ in 0..sizelocvars {
                    let _varname = self.read_string(&strings)?;
                    let _startpc = self.read_var_int()?;
                    let _endpc = self.read_var_int()?;
                    let _reg = self.read::<u8>()?;
                }

                let sizeupvalues = self.read_var_int()?;
                for _ in 0..sizeupvalues {
                    let _upvalue_name = self.read_string(&strings)?;
                }
            }

            let source = strings.first().cloned().unwrap_or_default();

            let children = child_proto_ids
                .iter()
                .filter_map(|idx| protos.get(*idx).cloned())
                .collect::<Vec<_>>();

            let sizelineinfo = lineinfo.len();

            protos.push(Proto {
                source,
                bytecodeid,
                maxstacksize,
                numparams,
                nups,
                is_vararg,
                flags,
                typeinfo: Vec::new(),
                sizetypeinfo: 0,
                code,
                sizecode,
                k,
                sizek,
                p: children,
                child_proto_indices: child_proto_ids,
                sizep,
                linedefined,
                debugname,
                linegaplog2,
                lineinfo,
                sizelineinfo,
                abslineinfo,
            });
        }

        for i in 0..protos.len() {
            let child_indices = protos[i].child_proto_indices.clone();
            protos[i].p = child_indices
                .iter()
                .filter_map(|idx| protos.get(*idx).cloned())
                .collect();
        }

        let main_proto = if self.offset < self.data.len() {
            Some(self.read_var_int()? as usize)
        } else {
            None
        };

        Ok(BytecodeFile {
            version,
            types_version,
            strings,
            protos,
            main_proto,
        })
    }
}

impl TryFrom<u8> for LuauOpcode {
    type Error = String;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value < LuauOpcode::LOP__COUNT as u8 {
            // SAFETY: Checked that value is within the contiguous repr(u8) range.
            Ok(unsafe { std::mem::transmute::<u8, LuauOpcode>(value) })
        } else {
            Err(format!("Invalid LuauOpcode value: {}", value))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ensure_rejects_oob() {
        let buf = [0u8; 2];
        let reader = BytecodeReader::new(&buf);
        assert!(reader.ensure(3).is_err());
        assert!(reader.ensure(2).is_ok());
    }

    #[test]
    fn read_var_int_roundtrip() {
        // 300 = 0b1_0010_1100 -> bytes: 0xAC, 0x02
        let data = [0xACu8, 0x02];
        let mut r = BytecodeReader::new(&data);
        assert_eq!(r.read_var_int().unwrap(), 300);
    }

    #[test]
    fn read_var_int_truncated() {
        let data = [0xAC];
        let mut r = BytecodeReader::new(&data);
        assert!(r.read_var_int().is_err());
    }

    #[test]
    fn bytecode_version_must_be_three() {
        // Simulate a v1 header: single version byte + zero strings/protos/main.
        // Any non-3 version must be rejected.
        let data = [0x01u8];
        let mut r = BytecodeReader::new(&data);
        let err = r.read_bytecode_file().unwrap_err();
        assert!(err.contains("version mismatch"), "got: {}", err);
    }

    #[test]
    fn bytecode_compile_error_payload() {
        // Version byte 0 means the runtime reports a compile error string.
        let mut data = vec![0x00u8];
        data.extend_from_slice(b"oops");
        let mut r = BytecodeReader::new(&data);
        let err = r.read_bytecode_file().unwrap_err();
        assert!(err.contains("compile error"), "got: {}", err);
        assert!(err.contains("oops"), "got: {}", err);
    }

    #[test]
    fn sentinel_01_03_is_stripped() {
        // `01 03 <rest>` must skip byte 0 (matches loadBuffer behaviour).
        let data = [0x01u8, 0x03];
        let mut r = BytecodeReader::new(&data);
        // After skipping 0x01, we read 0x03 as version -> then fail reading
        // strings because the buffer is truncated. The important thing is
        // that the version check passes (offset advanced past 0x01).
        let err = r.read_bytecode_file().unwrap_err();
        assert!(
            !err.contains("version mismatch"),
            "sentinel not stripped, got: {}",
            err
        );
    }
}
