//! Reconstruction of Luau source code from parsed Luau bytecode.
//!
//! This module implements the second half of the workflow:
//!
//! ```text
//! .l64  ──► decipher ──► .lb  ──► this module ──► .luau (source)
//! ```
//!
//! The goal is to produce Luau source that a human can read, edit, and
//! (in most cases) feed back through a Luau compiler. The implementation
//! is deliberately pragmatic:
//!
//! * instructions are decoded into a typed [`Instr`] enum;
//! * per-register expressions are tracked in a virtual [`RegFile`];
//! * statements are emitted lazily so that intermediate registers
//!   (`r0 = K(3); StartParams = r0`) collapse into direct assignments
//!   (`StartParams = "start"`);
//! * control flow is reconstructed for the common cases (if/else,
//!   numeric/generic for, while) and otherwise falls back to explicit
//!   comment labels that keep the output syntactically valid Luau.

use super::bytecode::{BytecodeFile, Constant, LuauOpcode, Proto};
use std::collections::{BTreeMap, BTreeSet};
use std::convert::TryFrom;
use std::fmt::Write;

/// Decoded Luau instruction. The bytecode is a flat `Vec<u32>`; each
/// logical instruction occupies either one or two `u32` slots (the
/// second one, when present, is the `aux` word).
#[derive(Debug, Clone)]
pub struct Instr {
    pub pc: usize,
    pub next_pc: usize,
    pub op: LuauOpcode,
    pub a: u8,
    pub b: u8,
    pub c: u8,
    /// Signed 16-bit (AD form).
    pub d: i16,
    /// Signed 24-bit (E form, sign-extended).
    pub e: i32,
    pub aux: u32,
}

/// Returns `true` when the opcode consumes an extra `aux` word after it.
fn opcode_uses_aux(op: LuauOpcode) -> bool {
    matches!(
        op,
        LuauOpcode::LOP_GETGLOBAL
            | LuauOpcode::LOP_SETGLOBAL
            | LuauOpcode::LOP_GETIMPORT
            | LuauOpcode::LOP_GETTABLEKS
            | LuauOpcode::LOP_SETTABLEKS
            | LuauOpcode::LOP_NAMECALL
            | LuauOpcode::LOP_JUMPIFEQ
            | LuauOpcode::LOP_JUMPIFLE
            | LuauOpcode::LOP_JUMPIFLT
            | LuauOpcode::LOP_JUMPIFNOTEQ
            | LuauOpcode::LOP_JUMPIFNOTLE
            | LuauOpcode::LOP_JUMPIFNOTLT
            | LuauOpcode::LOP_NEWTABLE
            | LuauOpcode::LOP_SETLIST
            | LuauOpcode::LOP_FORGLOOP
            | LuauOpcode::LOP_FASTCALL2
            | LuauOpcode::LOP_FASTCALL2K
            | LuauOpcode::LOP_FASTCALL3
            | LuauOpcode::LOP_LOADKX
            | LuauOpcode::LOP_JUMPXEQKNIL
            | LuauOpcode::LOP_JUMPXEQKB
            | LuauOpcode::LOP_JUMPXEQKN
            | LuauOpcode::LOP_JUMPXEQKS
    )
}

/// Decode every instruction in `proto.code`. Each returned [`Instr`]
/// already has `aux` resolved and `next_pc` set to the start of the
/// following instruction.
pub fn decode_proto(proto: &Proto) -> Result<Vec<Instr>, String> {
    let mut out = Vec::new();
    let mut pc = 0usize;
    while pc < proto.code.len() {
        let word = proto.code[pc];
        let op = match LuauOpcode::try_from((word & 0xFF) as u8) {
            Ok(op) => op,
            Err(_) => {
                // Skip unknown opcode word; keep going so that we can
                // still decompile the rest of the proto.
                pc += 1;
                continue;
            }
        };

        let a = ((word >> 8) & 0xFF) as u8;
        let b = ((word >> 16) & 0xFF) as u8;
        let c = ((word >> 24) & 0xFF) as u8;
        let d = ((word >> 16) & 0xFFFF) as i16;
        let e = (word as i32) >> 8;

        let aux = if opcode_uses_aux(op) {
            if pc + 1 >= proto.code.len() {
                return Err(format!(
                    "opcode at pc {} expects aux word but code ended",
                    pc
                ));
            }
            proto.code[pc + 1]
        } else {
            0
        };

        let next_pc = pc + 1 + usize::from(opcode_uses_aux(op));
        out.push(Instr {
            pc,
            next_pc,
            op,
            a,
            b,
            c,
            d,
            e,
            aux,
        });
        pc = next_pc;
    }
    Ok(out)
}

/// Precedence levels, mirroring Lua's grammar. Larger = binds tighter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Prec {
    Lowest,
    Or,
    And,
    Cmp,
    BitOr,
    BitXor,
    BitAnd,
    Shift,
    Concat,
    AddSub,
    MulDivMod,
    Unary,
    Power,
    Primary,
}

fn binop_prec(op: &str) -> Prec {
    match op {
        "or" => Prec::Or,
        "and" => Prec::And,
        "==" | "~=" | "<" | "<=" | ">" | ">=" => Prec::Cmp,
        ".." => Prec::Concat,
        "+" | "-" => Prec::AddSub,
        "*" | "/" | "//" | "%" => Prec::MulDivMod,
        "^" => Prec::Power,
        _ => Prec::Primary,
    }
}

/// Expression AST node. Kept deliberately small.
#[derive(Debug, Clone)]
#[derive(PartialEq)]
pub enum Expr {
    Nil,
    Bool(bool),
    Num(f64),
    Str(String),
    Vararg,
    /// Logical register slot, rendered as `v<index>` by default.
    Reg(u8),
    /// Proto upvalue slot, rendered as `u<index>`.
    Upval(u8),
    /// Bytecode proto, rendered as an inline `function(...) ... end`.
    Closure(usize),
    /// `_G.<name>` / `<name>`.
    Global(String),
    /// Dotted import path resolved from GETIMPORT aux.
    ImportPath(Vec<String>),
    /// `base[key]`.
    Index(Box<Expr>, Box<Expr>),
    /// `base.field` (syntactic sugar when `field` is an identifier).
    Field(Box<Expr>, String),
    /// Regular call: `f(a, b, ...)`.
    Call {
        func: Box<Expr>,
        args: Vec<Expr>,
        /// When true, the last argument is a trailing `...` varargs/multret.
        vararg_tail: bool,
    },
    /// Method call: `obj:method(a, b, ...)`.
    Method {
        obj: Box<Expr>,
        name: String,
        args: Vec<Expr>,
        vararg_tail: bool,
    },
    BinOp {
        op: &'static str,
        lhs: Box<Expr>,
        rhs: Box<Expr>,
    },
    UnOp {
        op: &'static str,
        operand: Box<Expr>,
    },
    Concat(Vec<Expr>),
    Length(Box<Expr>),
    /// Table literal.
    Table {
        array: Vec<Expr>,
        hash: Vec<(Expr, Expr)>,
    },
    /// Fallback when we can't represent the value precisely. Rendered
    /// verbatim so editors can still operate on the generated source.
    Raw(String),
}

/// A Luau statement we emit into the reconstructed source.
#[derive(Debug, Clone)]
enum Stmt {
    Assign {
        target: Expr,
        value: Expr,
    },
    /// `t1, t2, ... = v` — multi-target assignment (e.g. from a multi-return call)
    /// when the targets are already-declared locals.
    MultiAssign {
        targets: Vec<Expr>,
        value: Expr,
    },
    /// `local v_a, v_b, ... = v, w, ...` for multi-return calls/locals.
    LocalList {
        names: Vec<String>,
        value: Expr,
        /// Number of extra names bound from the same expression.
        extra: usize,
    },
    Call(Expr),
    Return(Vec<Expr>),
    /// `if cond then <then_block> [else <else_block>] end`.
    If {
        cond: Expr,
        then_block: Vec<Stmt>,
        else_block: Option<Vec<Stmt>>,
    },
    /// `while cond do <body> end`.
    While {
        cond: Expr,
        body: Vec<Stmt>,
    },
    /// `repeat <body> until cond`.
    Repeat {
        body: Vec<Stmt>,
        cond: Expr,
    },
    /// `for <var> = <start>, <limit>[, <step>] do <body> end`.
    ForNum {
        var: String,
        start: Expr,
        limit: Expr,
        step: Option<Expr>,
        body: Vec<Stmt>,
    },
    /// `for <vars...> in <exprs...> do <body> end`.
    ForGen {
        vars: Vec<String>,
        exprs: Vec<Expr>,
        body: Vec<Stmt>,
    },
    /// `break`.
    Break,
    /// `continue`.
    Continue,
    /// Free-form comment line (no leading `-- `; the renderer adds it).
    Comment(String),
    /// Label comment, e.g. `-- [L42]` used as a jump target marker.
    LabelMarker(usize),
    /// `-- goto Lpc` style comment preserving the original jump.
    GotoComment(usize, String),
    /// Blank line.
    Blank,
}

/// Virtual register file. Each register holds either `None` (no known
/// expression; the register is "dirty") or `Some(expr)` (the current
/// expression produced by the most recent write).
#[derive(Default, Clone)]
struct RegFile {
    regs: BTreeMap<u8, Expr>,
}

impl RegFile {
    fn set(&mut self, reg: u8, expr: Expr) {
        self.regs.insert(reg, expr);
    }
    fn get(&self, reg: u8) -> Expr {
        self.regs.get(&reg).cloned().unwrap_or(Expr::Reg(reg))
    }
    fn take(&mut self, reg: u8) -> Expr {
        self.regs.remove(&reg).unwrap_or(Expr::Reg(reg))
    }
    fn invalidate_from(&mut self, start: u8) {
        self.regs.retain(|&k, _| k < start);
    }
}

/// Main entry: reconstruct Luau source from a parsed [`BytecodeFile`].
pub fn reconstruct(file: &BytecodeFile) -> Result<String, String> {
    let main_idx = file
        .main_proto
        .or_else(|| if file.protos.is_empty() { None } else { Some(file.protos.len() - 1) })
        .ok_or_else(|| "bytecode file has no protos".to_string())?;
    let mut out = String::new();
    writeln!(
        out,
        "-- Reconstructed Luau source (luauc64 {}).",
        env!("CARGO_PKG_VERSION")
    )
    .ok();
    writeln!(
        out,
        "-- This is a best-effort lift from bytecode; review before running."
    )
    .ok();
    writeln!(out).ok();

    let main_proto = &file.protos[main_idx];
    let body = reconstruct_proto_body(file, main_proto, 0)?;
    out.push_str(&body);
    Ok(out)
}

fn proto_header(proto: &Proto) -> String {
    let mut params: Vec<String> = (0..proto.numparams)
        .map(|i| {
            if i == 0 && looks_like_method(proto) {
                "self".to_string()
            } else {
                format!("v{}", i)
            }
        })
        .collect();
    if proto.is_vararg != 0 {
        params.push("...".to_string());
    }
    format!("function({})", params.join(", "))
}

/// Render `X.name = function(...) ... end` as the idiomatic
/// `function X.name(...) ... end`, and `X.name = function(self, ...) ... end`
/// as `function X:name(...) ... end`. Returns `None` (and lets the
/// generic assignment path handle it) if the target/value shape does
/// not fit the pattern.
fn try_render_function_assign(
    target: &Expr,
    value: &Expr,
    pad: &str,
    file: &BytecodeFile,
    indent: usize,
) -> Option<String> {
    let child_idx = match value {
        Expr::Closure(idx) => *idx,
        _ => return None,
    };
    let child = file.protos.get(child_idx)?;

    // Walk the target and split it into a dotted "base" prefix plus an
    // optional final `.name` (which we can turn into `:name` if the
    // proto is a method).
    let (base_expr, final_name) = match target {
        Expr::Field(base, name) if is_identifier(name) => {
            (base.as_ref().clone(), Some(name.clone()))
        }
        Expr::Index(base, key) => match key.as_ref() {
            Expr::Str(s) if is_identifier(s) => {
                (base.as_ref().clone(), Some(s.clone()))
            }
            _ => return None,
        },
        Expr::Global(_) => (target.clone(), None),
        _ => return None,
    };

    // The base expression must render to something reasonable as a
    // prefix for a function declaration. Globals and dotted chains
    // qualify; anything producing a call or non-primary expr doesn't.
    let base_str = match &base_expr {
        Expr::Global(name) => name.clone(),
        Expr::Field(_, _) | Expr::Index(_, _) => {
            render_expr(&base_expr, Prec::Primary, file, indent)
        }
        _ if final_name.is_none() => {
            // Top-level `function X()` — target itself is the name.
            render_expr(&base_expr, Prec::Primary, file, indent)
        }
        _ => return None,
    };

    let method = final_name.is_some() && looks_like_method(child);
    let qualified = match &final_name {
        Some(n) if method => format!("{}:{}", base_str, n),
        Some(n) => format!("{}.{}", base_str, n),
        None => base_str,
    };

    let header = proto_header_named(child, &qualified, method);
    let body = match reconstruct_proto_body(file, child, indent + 1) {
        Ok(b) => b,
        Err(e) => format!("{}  -- reconstruction error: {}\n", pad, e),
    };
    // When rendered as a method, reconstruct_proto_body already
    // performed the v0→self substitution on the body. The `function
    // X:name()` header itself already omits `self` from the signature.

    let mut out = String::new();
    out.push_str(pad);
    out.push_str(&header);
    out.push('\n');
    out.push_str(&body);
    out.push_str(pad);
    out.push_str("end\n");
    Some(out)
}

/// Render a header like `function Foo.bar(...)` or `function Foo:bar(...)`.
/// When `method` is true, the first parameter is absorbed into the
/// receiver (via the `:` separator) and dropped from the signature.
fn proto_header_named(proto: &Proto, qualified: &str, method: bool) -> String {
    let start: u8 = if method { 1 } else { 0 };
    let mut params: Vec<String> = (start..proto.numparams)
        .map(|i| format!("v{}", i))
        .collect();
    if proto.is_vararg != 0 {
        params.push("...".to_string());
    }
    format!("function {}({})", qualified, params.join(", "))
}

/// Heuristic: the proto is a method if its first register (v0) is used
/// as the receiver of a `NAMECALL` or as the table in a `GETTABLEKS` /
/// `SETTABLEKS` / `GETTABLE` / `SETTABLE` anywhere in its code.
fn looks_like_method(proto: &Proto) -> bool {
    if proto.numparams == 0 {
        return false;
    }
    let Ok(instrs) = decode_proto(proto) else {
        return false;
    };
    use LuauOpcode::*;
    instrs.iter().any(|i| {
        matches!(
            i.op,
            LOP_NAMECALL
                | LOP_GETTABLEKS
                | LOP_SETTABLEKS
                | LOP_GETTABLE
                | LOP_SETTABLE
                | LOP_GETTABLEN
                | LOP_SETTABLEN
        ) && i.b == 0
    })
}

/// Replace the bare identifier `v0` with `self` in the rendered body of a
/// method — walk the text respecting Lua identifier boundaries so that
/// other identifiers that happen to contain `v0` (e.g. `v05`, `foov0`) are
/// left alone.  String literals are preserved verbatim.
fn rename_reg0_to_self(body: &str) -> String {
    let bytes = body.as_bytes();
    let mut out = String::with_capacity(body.len());
    let mut i = 0usize;
    let is_ident = |c: u8| c.is_ascii_alphanumeric() || c == b'_';
    while i < bytes.len() {
        let c = bytes[i];
        // Skip double-quoted string literals intact.
        if c == b'"' {
            let start = i;
            i += 1;
            while i < bytes.len() {
                let b = bytes[i];
                if b == b'\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if b == b'"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            out.push_str(&body[start..i]);
            continue;
        }
        // Skip `-- ...` line comments (don't touch v0 mentions in comments).
        if c == b'-' && i + 1 < bytes.len() && bytes[i + 1] == b'-' {
            let start = i;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            out.push_str(&body[start..i]);
            continue;
        }
        // Identifier / number run.
        if is_ident(c) {
            let start = i;
            while i < bytes.len() && is_ident(bytes[i]) {
                i += 1;
            }
            let token = &body[start..i];
            if token == "v0" {
                out.push_str("self");
            } else {
                out.push_str(token);
            }
            continue;
        }
        out.push(c as char);
        i += 1;
    }
    out
}

/// Reconstruct a single proto body. Each line in the returned string is
/// indented by `indent` levels (two spaces per level).
fn reconstruct_proto_body(
    file: &BytecodeFile,
    proto: &Proto,
    indent: usize,
) -> Result<String, String> {
    let instrs = decode_proto(proto)?;
    let pc_to_idx: BTreeMap<usize, usize> = instrs
        .iter()
        .enumerate()
        .map(|(idx, i)| (i.pc, idx))
        .collect();

    let mut regs = RegFile::default();
    // Seed params as local registers v0..vN — these count as "already
    // declared" locals so subsequent writes to them don't get a spurious
    // `local` keyword.
    let mut declared: BTreeSet<u8> = BTreeSet::new();
    for i in 0..proto.numparams {
        regs.set(i, Expr::Reg(i));
        declared.insert(i);
    }
    let mut pending_captures: Vec<Capture> = Vec::new();

    let mut stmts = lift_range(
        file,
        proto,
        &instrs,
        &pc_to_idx,
        0,
        instrs.len(),
        &mut regs,
        &mut declared,
        &mut pending_captures,
        &LoopContext::default(),
    )?;

    // Post-processing: idiomatic rewrites that are hard to do during
    // lifting but trivial to spot on the finished statement tree.
    post_process_stmts(&mut stmts, /* is_proto_body */ true);

    // Render statements to text.
    let mut out = String::new();
    let pad = "  ".repeat(indent);
    for s in &stmts {
        render_stmt(&mut out, s, &pad, file, indent)?;
    }
    if looks_like_method(proto) {
        out = rename_reg0_to_self(&out);
    }
    Ok(out)
}

/// Apply idiomatic-Luau rewrites over a block of statements. Runs
/// recursively through nested blocks (if/while/for/repeat bodies)
/// before touching the current level so transforms see already-
/// normalised children.
fn post_process_stmts(stmts: &mut Vec<Stmt>, is_proto_body: bool) {
    // Recurse into nested blocks first.
    for s in stmts.iter_mut() {
        match s {
            Stmt::If {
                then_block,
                else_block,
                ..
            } => {
                post_process_stmts(then_block, false);
                if let Some(e) = else_block {
                    post_process_stmts(e, false);
                }
            }
            Stmt::While { body, .. }
            | Stmt::Repeat { body, .. }
            | Stmt::ForNum { body, .. }
            | Stmt::ForGen { body, .. } => {
                post_process_stmts(body, false);
            }
            _ => {}
        }
    }

    fold_empty_table_field_assigns(stmts);
    fold_compound_and_if(stmts);
    inline_return_local(stmts);
    if is_proto_body {
        strip_trailing_bare_return(stmts);
    }
}

/// `local v<k> = <expr>` immediately followed by `return v<k>` → just
/// `return <expr>`. Only applies when the local isn't used between the
/// two statements (enforced by adjacency).
fn inline_return_local(stmts: &mut Vec<Stmt>) {
    if stmts.len() < 2 {
        return;
    }
    let n = stmts.len();
    let ret_reg = match &stmts[n - 1] {
        Stmt::Return(values) if values.len() == 1 => match &values[0] {
            Expr::Reg(r) => *r,
            _ => return,
        },
        _ => return,
    };
    let (name_matches, value) = match &stmts[n - 2] {
        Stmt::LocalList {
            names,
            value,
            extra,
        } if *extra == 0 && names.len() == 1 => {
            (names[0] == format!("v{}", ret_reg), value.clone())
        }
        _ => return,
    };
    if !name_matches {
        return;
    }
    stmts.truncate(n - 2);
    stmts.push(Stmt::Return(vec![value]));
}

/// Strip a trailing bare `return` from the very end of a function body.
/// Lua inserts one implicitly, so it is visual noise when decompiled.
fn strip_trailing_bare_return(stmts: &mut Vec<Stmt>) {
    if matches!(stmts.last(), Some(Stmt::Return(v)) if v.is_empty()) {
        stmts.pop();
    }
}

/// Collapse `Assign { target: T, value: {} }` immediately followed by
/// one or more `Assign { target: Field/Index(T, k), value: V }` whose
/// base is lexically equal to `T`, merging them into a single
/// `Assign { target: T, value: { ..., k = V } }`.
fn fold_empty_table_field_assigns(stmts: &mut Vec<Stmt>) {
    let mut i = 0;
    while i < stmts.len() {
        let is_empty_init = matches!(
            &stmts[i],
            Stmt::Assign {
                value: Expr::Table { array, hash },
                ..
            } if array.is_empty() && hash.is_empty()
        );
        if !is_empty_init {
            i += 1;
            continue;
        }
        let anchor = match &stmts[i] {
            Stmt::Assign { target, .. } => target.clone(),
            _ => unreachable!(),
        };
        let array: Vec<Expr> = Vec::new();
        let mut hash: Vec<(Expr, Expr)> = Vec::new();
        let mut consumed = 0usize;
        while i + 1 + consumed < stmts.len() {
            let (key, val) = match &stmts[i + 1 + consumed] {
                Stmt::Assign { target, value } => {
                    // Don't fold closures into a table literal — those
                    // render better as separate `function X.name(...)`
                    // declarations.
                    if matches!(value, Expr::Closure(_)) {
                        break;
                    }
                    match target {
                        Expr::Field(b, name) if **b == anchor => {
                            (Expr::Str(name.clone()), value.clone())
                        }
                        Expr::Index(b, k) if **b == anchor => {
                            ((**k).clone(), value.clone())
                        }
                        _ => break,
                    }
                }
                _ => break,
            };
            hash.push((key, val));
            consumed += 1;
        }
        if consumed == 0 {
            i += 1;
            continue;
        }
        // Replace the run with a single Assign carrying the merged table.
        let new_stmt = Stmt::Assign {
            target: anchor,
            value: Expr::Table { array, hash },
        };
        stmts.splice(i..i + 1 + consumed, std::iter::once(new_stmt));
        i += 1;
    }
}

/// `if A then if B then body end end` (no else on either) →
/// `if A and B then body end`. Applied iteratively so triples collapse
/// as well.
fn fold_compound_and_if(stmts: &mut Vec<Stmt>) {
    for s in stmts.iter_mut() {
        if let Stmt::If {
            cond,
            then_block,
            else_block: None,
        } = s
        {
            // Drain what we need before re-borrowing.
            if then_block.len() == 1 {
                if let Stmt::If {
                    cond: inner_cond,
                    then_block: inner_then,
                    else_block: None,
                } = &then_block[0]
                {
                    let new_cond = Expr::BinOp {
                        op: "and",
                        lhs: Box::new(cond.clone()),
                        rhs: Box::new(inner_cond.clone()),
                    };
                    let new_then = inner_then.clone();
                    *cond = new_cond;
                    *then_block = new_then;
                }
            }
        }
    }
}

/// Context passed through nested `lift_range` calls so that a bare
/// JUMP/JUMPBACK can be recognised as a `break` / `continue` out of the
/// innermost loop instead of a goto-comment.
#[derive(Default, Clone)]
struct LoopContext {
    /// Index of the instruction that should be reached to continue the
    /// innermost loop (i.e. the FORNLOOP/JUMPBACK target or the while
    /// header re-check).
    continue_target: Option<usize>,
    /// Index of the instruction just past the innermost loop (i.e. the
    /// fall-through target after the loop ends).
    break_target: Option<usize>,
}

/// Collect the set of `pc` values that are jump targets anywhere in the
/// proto (so we can mark them with comment labels in the output).
fn collect_jump_targets(instrs: &[Instr]) -> BTreeSet<usize> {
    let mut out = BTreeSet::new();
    for i in instrs {
        let target = match i.op {
            LuauOpcode::LOP_JUMP
            | LuauOpcode::LOP_JUMPBACK
            | LuauOpcode::LOP_JUMPIF
            | LuauOpcode::LOP_JUMPIFNOT
            | LuauOpcode::LOP_JUMPIFEQ
            | LuauOpcode::LOP_JUMPIFLE
            | LuauOpcode::LOP_JUMPIFLT
            | LuauOpcode::LOP_JUMPIFNOTEQ
            | LuauOpcode::LOP_JUMPIFNOTLE
            | LuauOpcode::LOP_JUMPIFNOTLT => {
                Some((i.pc as isize + 1 + i.d as isize) as usize)
            }
            LuauOpcode::LOP_JUMPX => Some((i.pc as isize + 1 + i.e as isize) as usize),
            LuauOpcode::LOP_JUMPXEQKNIL
            | LuauOpcode::LOP_JUMPXEQKB
            | LuauOpcode::LOP_JUMPXEQKN
            | LuauOpcode::LOP_JUMPXEQKS => {
                // D is in the main word, followed by aux.
                Some((i.pc as isize + 1 + i.d as isize) as usize)
            }
            LuauOpcode::LOP_FORNPREP | LuauOpcode::LOP_FORNLOOP => {
                Some((i.pc as isize + 1 + i.d as isize) as usize)
            }
            LuauOpcode::LOP_FORGLOOP
            | LuauOpcode::LOP_FORGPREP
            | LuauOpcode::LOP_FORGPREP_NEXT
            | LuauOpcode::LOP_FORGPREP_INEXT => Some((i.pc as isize + 1 + i.d as isize) as usize),
            _ => None,
        };
        if let Some(t) = target {
            out.insert(t);
        }
    }
    out
}

/// A `LOP_CAPTURE` instruction that we are holding for the next
/// `NEWCLOSURE`/`DUPCLOSURE`.
#[derive(Debug, Clone)]
struct Capture {
    kind: u8, // 0=value, 1=ref, 2=upval
    idx: u8,
}

/// If `instr` is a conditional `JUMPIF*` whose body runs when the
/// `skip-jump` is not taken, return the positive condition expression
/// that should head an `if`/`while`. `None` for unsupported opcodes.
fn jumpif_condition(i: &Instr, regs: &RegFile, proto: &Proto) -> Option<Expr> {
    use LuauOpcode::*;
    match i.op {
        LOP_JUMPIFNOT => Some(regs.get(i.a)),
        LOP_JUMPIF => Some(Expr::UnOp {
            op: "not ",
            operand: Box::new(regs.get(i.a)),
        }),
        LOP_JUMPIFEQ
        | LOP_JUMPIFNOTEQ
        | LOP_JUMPIFLE
        | LOP_JUMPIFNOTLE
        | LOP_JUMPIFLT
        | LOP_JUMPIFNOTLT => {
            let lhs = regs.get(i.a);
            let rhs = regs.get(i.aux as u8);
            let op: &'static str = match i.op {
                // Jump-if skips the body; the body runs when the
                // comparison is *inverted*.
                LOP_JUMPIFEQ => "~=",
                LOP_JUMPIFNOTEQ => "==",
                LOP_JUMPIFLE => ">",
                LOP_JUMPIFNOTLE => "<=",
                LOP_JUMPIFLT => ">=",
                LOP_JUMPIFNOTLT => "<",
                _ => unreachable!(),
            };
            Some(Expr::BinOp {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            })
        }
        LOP_JUMPXEQKNIL | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS => {
            // aux bit 31 = "not equal" flag; low bits hold the k-index
            // except for JUMPXEQKNIL/KB where the payload is inline.
            let not_eq = (i.aux >> 31) & 1 == 1;
            let lhs = regs.get(i.a);
            let rhs = match i.op {
                LOP_JUMPXEQKNIL => Expr::Nil,
                LOP_JUMPXEQKB => Expr::Bool((i.aux & 1) != 0),
                LOP_JUMPXEQKN => {
                    let k_idx = (i.aux & 0x00FFFFFF) as usize;
                    constant_to_expr(proto, k_idx)
                }
                LOP_JUMPXEQKS => {
                    let k_idx = (i.aux & 0x00FFFFFF) as usize;
                    constant_to_expr(proto, k_idx)
                }
                _ => unreachable!(),
            };
            // The bytecode jumps when the equality check matches `not_eq`.
            // The body runs when the equality check matches the *opposite*
            // of `not_eq`, so:
            //   not_eq=false (jump-if-equal)     → body runs when a ~= rhs
            //   not_eq=true  (jump-if-not-equal) → body runs when a == rhs
            let op = if not_eq { "==" } else { "~=" };
            Some(Expr::BinOp {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            })
        }
        _ => None,
    }
}

/// If the last statement in `out` is `local v{a}, v{a+1}, v{a+2} = <call>`
/// (matching the 3 iter/state/ctrl registers that `FORGPREP` reads),
/// remove it and return the single right-hand expression.  Used to
/// collapse `pairs(t)` / `ipairs(t)` calls into the `for ... in <call>`
/// header.
fn try_inline_forgen_iterator(out: &mut Vec<Stmt>, base: u8) -> Option<Vec<Expr>> {
    // Inspect the previous statement: either `local v<b>, v<b+1>, v<b+2> = <call>`
    // or a bare `v<b>, v<b+1>, v<b+2> = <call>` left-over from an already-declared
    // triplet.  Both represent the iter/state/ctrl registers a FORGPREP expects.
    let (value_is_call, matches) = match out.last()? {
        Stmt::LocalList { names, value, .. } => (
            matches!(value, Expr::Call { .. } | Expr::Method { .. }),
            names.len() == 3
                && (0..3u8)
                    .all(|k| names[k as usize] == format!("v{}", base + k)),
        ),
        Stmt::MultiAssign { targets, value } => (
            matches!(value, Expr::Call { .. } | Expr::Method { .. }),
            targets.len() == 3
                && (0..3u8).all(|k| {
                    matches!(targets[k as usize], Expr::Reg(r) if r == base + k)
                }),
        ),
        _ => return None,
    };
    if !value_is_call || !matches {
        return None;
    }
    match out.pop()? {
        Stmt::LocalList { value, .. } | Stmt::MultiAssign { value, .. } => {
            Some(vec![value])
        }
        _ => None,
    }
}

fn seed_params(regs: &mut RegFile, numparams: u8) {
    regs.regs.clear();
    for i in 0..numparams {
        regs.set(i, Expr::Reg(i));
    }
}

/// Return true if `op` is any flavour of jump that carries a `d` offset.
fn is_forward_jump_family(op: LuauOpcode) -> bool {
    use LuauOpcode::*;
    matches!(
        op,
        LOP_JUMP
            | LOP_JUMPBACK
            | LOP_JUMPIF
            | LOP_JUMPIFNOT
            | LOP_JUMPIFEQ
            | LOP_JUMPIFNOTEQ
            | LOP_JUMPIFLE
            | LOP_JUMPIFNOTLE
            | LOP_JUMPIFLT
            | LOP_JUMPIFNOTLT
            | LOP_JUMPXEQKNIL
            | LOP_JUMPXEQKB
            | LOP_JUMPXEQKN
            | LOP_JUMPXEQKS
    )
}

/// Pre-scan `[from, to)` for backward jumps and return a map from
/// `loop_start_idx` → `tail_idx` (the last instruction in the loop body,
/// i.e. the backward jump itself).  When multiple back-jumps target the
/// same index, we keep the farthest one so the whole loop is captured.
fn scan_loop_starts(
    instrs: &[Instr],
    pc_to_idx: &BTreeMap<usize, usize>,
    from: usize,
    to: usize,
) -> BTreeMap<usize, usize> {
    let mut loops: BTreeMap<usize, usize> = BTreeMap::new();
    for (j, inst) in instrs.iter().enumerate().take(to).skip(from) {
        if !is_forward_jump_family(inst.op) || inst.d >= 0 {
            continue;
        }
        let back_pc = (inst.pc as isize + 1 + inst.d as isize) as usize;
        let Some(&back_idx) = pc_to_idx.get(&back_pc) else {
            continue;
        };
        if back_idx < from || back_idx > j || back_idx >= to {
            continue;
        }
        loops
            .entry(back_idx)
            .and_modify(|tail| {
                if *tail < j {
                    *tail = j;
                }
            })
            .or_insert(j);
    }
    loops
}

/// Lift a range of instructions `[from, to)` to a list of statements,
/// detecting `for` / `if` / `while` / `repeat` regions along the way.
#[allow(clippy::too_many_arguments)]
fn lift_range(
    file: &BytecodeFile,
    proto: &Proto,
    instrs: &[Instr],
    pc_to_idx: &BTreeMap<usize, usize>,
    from: usize,
    to: usize,
    regs: &mut RegFile,
    declared: &mut BTreeSet<u8>,
    pending_captures: &mut Vec<Capture>,
    loop_ctx: &LoopContext,
) -> Result<Vec<Stmt>, String> {
    use LuauOpcode::*;
    let loop_starts = scan_loop_starts(instrs, pc_to_idx, from, to);
    let mut out: Vec<Stmt> = Vec::new();
    let mut i = from;
    while i < to {
        let instr = &instrs[i];

        // ---- loop region starting here (pre-scan) ----
        if let Some(&tail_idx) = loop_starts.get(&i) {
            if tail_idx < to && tail_idx >= i {
                let tail = &instrs[tail_idx];
                let break_target = Some(tail_idx + 1);

                // `while cond do body end`: the first instruction in the
                // body is a forward skip-jump past the tail, and the tail
                // is an unconditional JUMPBACK to `i`.
                if let Some(cond) = jumpif_condition(instr, regs, proto) {
                    if instr.d > 0 {
                        let skip_pc =
                            (instr.pc as isize + 1 + instr.d as isize) as usize;
                        let skip_idx = pc_to_idx.get(&skip_pc).copied();
                        if skip_idx == Some(tail_idx + 1)
                            && matches!(tail.op, LOP_JUMPBACK | LOP_JUMP)
                            && tail.d < 0
                        {
                            let back_pc =
                                (tail.pc as isize + 1 + tail.d as isize) as usize;
                            if pc_to_idx.get(&back_pc) == Some(&i) {
                                let mut body_regs = RegFile::default();
                                seed_params(&mut body_regs, proto.numparams);
                                let inner_ctx = LoopContext {
                                    continue_target: Some(tail_idx),
                                    break_target,
                                };
                                let body = lift_range(
                                    file,
                                    proto,
                                    instrs,
                                    pc_to_idx,
                                    i + 1,
                                    tail_idx,
                                    &mut body_regs,
                                    declared,
                                    pending_captures,
                                    &inner_ctx,
                                )?;
                                out.push(Stmt::While { cond, body });
                                seed_params(regs, proto.numparams);
                                i = tail_idx + 1;
                                continue;
                            }
                        }
                    }
                }

                // `repeat body until cond`: tail is a backward conditional
                // jump landing on `i`.
                if tail.d < 0 {
                    let back_pc =
                        (tail.pc as isize + 1 + tail.d as isize) as usize;
                    if pc_to_idx.get(&back_pc) == Some(&i) {
                        let mut body_regs = RegFile::default();
                        seed_params(&mut body_regs, proto.numparams);
                        let inner_ctx = LoopContext {
                            continue_target: Some(tail_idx),
                            break_target,
                        };
                        let body = lift_range(
                            file,
                            proto,
                            instrs,
                            pc_to_idx,
                            i,
                            tail_idx,
                            &mut body_regs,
                            declared,
                            pending_captures,
                            &inner_ctx,
                        )?;
                        if let Some(cond) =
                            jumpif_condition(tail, &body_regs, proto)
                        {
                            out.push(Stmt::Repeat { body, cond });
                            seed_params(regs, proto.numparams);
                            i = tail_idx + 1;
                            continue;
                        }
                        // Unconditional JUMPBACK with no predicate → infinite
                        // loop with break-inside semantics.
                        if matches!(tail.op, LOP_JUMPBACK | LOP_JUMP) {
                            let mut body_regs = RegFile::default();
                            seed_params(&mut body_regs, proto.numparams);
                            let body = lift_range(
                                file,
                                proto,
                                instrs,
                                pc_to_idx,
                                i,
                                tail_idx,
                                &mut body_regs,
                                declared,
                                pending_captures,
                                &inner_ctx,
                            )?;
                            out.push(Stmt::While {
                                cond: Expr::Bool(true),
                                body,
                            });
                            seed_params(regs, proto.numparams);
                            i = tail_idx + 1;
                            continue;
                        }
                    }
                }
            }
        }

        // ---- numeric for loop ----
        if matches!(instr.op, LOP_FORNPREP) {
            let target_pc = (instr.pc as isize + 1 + instr.d as isize) as usize;
            if let Some(&loop_idx) = pc_to_idx.get(&target_pc) {
                if loop_idx > i
                    && loop_idx < to
                    && matches!(instrs[loop_idx].op, LOP_FORNLOOP)
                {
                    let start = regs.get(instr.a + 2);
                    let limit = regs.get(instr.a);
                    let step = regs.get(instr.a + 1);
                    let step_opt = match &step {
                        Expr::Num(n) if (*n - 1.0).abs() < f64::EPSILON => None,
                        _ => Some(step),
                    };
                    let var = format!("v{}", instr.a + 2);
                    let mut body_regs = RegFile::default();
                    seed_params(&mut body_regs, proto.numparams);
                    body_regs.set(instr.a + 2, Expr::Reg(instr.a + 2));
                    declared.insert(instr.a + 2);
                    let inner_ctx = LoopContext {
                        continue_target: Some(loop_idx),
                        break_target: Some(loop_idx + 1),
                    };
                    let body = lift_range(
                        file,
                        proto,
                        instrs,
                        pc_to_idx,
                        i + 1,
                        loop_idx,
                        &mut body_regs,
                        declared,
                        pending_captures,
                        &inner_ctx,
                    )?;
                    out.push(Stmt::ForNum {
                        var,
                        start,
                        limit,
                        step: step_opt,
                        body,
                    });
                    seed_params(regs, proto.numparams);
                    i = loop_idx + 1;
                    continue;
                }
            }
        }

        // ---- generic for loop ----
        if matches!(
            instr.op,
            LOP_FORGPREP | LOP_FORGPREP_NEXT | LOP_FORGPREP_INEXT
        ) {
            let target_pc = (instr.pc as isize + 1 + instr.d as isize) as usize;
            if let Some(&loop_idx) = pc_to_idx.get(&target_pc) {
                if loop_idx > i
                    && loop_idx < to
                    && matches!(instrs[loop_idx].op, LOP_FORGLOOP)
                {
                    let forgloop = &instrs[loop_idx];
                    let num_vars_raw = forgloop.aux & 0xFF;
                    // FORGLOOP aux low byte = number of loop variables.
                    let num_vars = if num_vars_raw == 0 {
                        1
                    } else {
                        num_vars_raw as u8
                    };
                    let exprs_base = instr.a;
                    let exprs = vec![
                        regs.get(exprs_base),
                        regs.get(exprs_base + 1),
                        regs.get(exprs_base + 2),
                    ];
                    let vars: Vec<String> = (0..num_vars)
                        .map(|k| format!("v{}", instr.a + 3 + k))
                        .collect();
                    let mut body_regs = RegFile::default();
                    seed_params(&mut body_regs, proto.numparams);
                    for k in 0..num_vars {
                        let r = instr.a + 3 + k;
                        body_regs.set(r, Expr::Reg(r));
                        declared.insert(r);
                    }
                    let inner_ctx = LoopContext {
                        continue_target: Some(loop_idx),
                        break_target: Some(loop_idx + 1),
                    };
                    let body = lift_range(
                        file,
                        proto,
                        instrs,
                        pc_to_idx,
                        i + 1,
                        loop_idx,
                        &mut body_regs,
                        declared,
                        pending_captures,
                        &inner_ctx,
                    )?;
                    // If the three iter/state/ctrl registers were just
                    // produced by a single preceding call, fold that call
                    // back into the `for ... in <call>(...)` header.
                    let folded_exprs = try_inline_forgen_iterator(
                        &mut out,
                        instr.a,
                    )
                    .unwrap_or(exprs);
                    out.push(Stmt::ForGen {
                        vars,
                        exprs: folded_exprs,
                        body,
                    });
                    seed_params(regs, proto.numparams);
                    i = loop_idx + 1;
                    continue;
                }
            }
        }

        // ---- conditional break / continue (taken before any `if` so
        //      that `if cond then continue end` inside a loop body is
        //      recognised instead of being folded into a giant `if`
        //      block stretching to the loop tail) ----
        if let Some(cond) = jumpif_condition(instr, regs, proto) {
            if instr.d > 0 {
                let target_pc =
                    (instr.pc as isize + 1 + instr.d as isize) as usize;
                if let Some(&target_idx) = pc_to_idx.get(&target_pc) {
                    let neg = Expr::UnOp {
                        op: "not ",
                        operand: Box::new(cond.clone()),
                    };
                    if Some(target_idx) == loop_ctx.break_target {
                        out.push(Stmt::If {
                            cond: neg,
                            then_block: vec![Stmt::Break],
                            else_block: None,
                        });
                        i += 1;
                        continue;
                    }
                    if Some(target_idx) == loop_ctx.continue_target {
                        out.push(Stmt::If {
                            cond: neg,
                            then_block: vec![Stmt::Continue],
                            else_block: None,
                        });
                        i += 1;
                        continue;
                    }
                }
            }
        }

        // ---- forward conditional jump: if-then[-else] or while ----
        if let Some(cond) = jumpif_condition(instr, regs, proto) {
            if instr.d > 0 {
                let skip_pc = (instr.pc as isize + 1 + instr.d as isize) as usize;
                if let Some(&skip_idx) = pc_to_idx.get(&skip_pc) {
                    if skip_idx > i && skip_idx <= to {
                        // `while`: the last instruction before `skip_idx`
                        // is a JUMPBACK that lands back at `i`.
                        let last_then = skip_idx.saturating_sub(1);
                        if last_then > i {
                            let lt = &instrs[last_then];
                            if matches!(lt.op, LOP_JUMPBACK | LOP_JUMP) && lt.d < 0 {
                                let back_pc =
                                    (lt.pc as isize + 1 + lt.d as isize) as usize;
                                if pc_to_idx.get(&back_pc) == Some(&i) {
                                    let mut body_regs = RegFile::default();
                                    seed_params(&mut body_regs, proto.numparams);
                                    let inner_ctx = LoopContext {
                                        continue_target: Some(last_then),
                                        break_target: Some(skip_idx),
                                    };
                                    let body = lift_range(
                                        file,
                                        proto,
                                        instrs,
                                        pc_to_idx,
                                        i + 1,
                                        last_then,
                                        &mut body_regs,
                                        declared,
                                        pending_captures,
                                        &inner_ctx,
                                    )?;
                                    out.push(Stmt::While { cond, body });
                                    seed_params(regs, proto.numparams);
                                    i = skip_idx;
                                    continue;
                                }
                            }
                        }

                        // Detect if/else: last then-instr is JUMP forward to `merge`.
                        let (then_end, else_end) = {
                            if last_then > i {
                                let lt = &instrs[last_then];
                                if matches!(lt.op, LOP_JUMP) && lt.d > 0 {
                                    let merge_pc =
                                        (lt.pc as isize + 1 + lt.d as isize) as usize;
                                    if let Some(&merge_idx) = pc_to_idx.get(&merge_pc) {
                                        if merge_idx > skip_idx && merge_idx <= to {
                                            (last_then, Some(merge_idx))
                                        } else {
                                            (skip_idx, None)
                                        }
                                    } else {
                                        (skip_idx, None)
                                    }
                                } else {
                                    (skip_idx, None)
                                }
                            } else {
                                (skip_idx, None)
                            }
                        };

                        let then_block = {
                            let mut body_regs = regs.clone();
                            lift_range(
                                file,
                                proto,
                                instrs,
                                pc_to_idx,
                                i + 1,
                                then_end,
                                &mut body_regs,
                                declared,
                                pending_captures,
                                loop_ctx,
                            )?
                        };
                        let else_block = if let Some(merge_idx) = else_end {
                            let mut body_regs = regs.clone();
                            Some(lift_range(
                                file,
                                proto,
                                instrs,
                                pc_to_idx,
                                skip_idx,
                                merge_idx,
                                &mut body_regs,
                                declared,
                                pending_captures,
                                loop_ctx,
                            )?)
                        } else {
                            None
                        };
                        out.push(Stmt::If {
                            cond,
                            then_block,
                            else_block,
                        });
                        seed_params(regs, proto.numparams);
                        i = else_end.unwrap_or(skip_idx);
                        continue;
                    }
                }
            }
            // ---- backward conditional jump: `repeat ... until cond` ----
            if instr.d < 0 {
                let back_pc = (instr.pc as isize + 1 + instr.d as isize) as usize;
                if let Some(&back_idx) = pc_to_idx.get(&back_pc) {
                    if back_idx >= from && back_idx <= i {
                        // Only accept if the region [back_idx, i] is fully
                        // contained in our current range and no other
                        // higher-level structure has claimed it (the
                        // previous statements in `out` that correspond to
                        // this body will be moved into the `repeat`).
                        let body_stmts_start = out
                            .iter()
                            .rposition(|s| matches!(s, Stmt::LabelMarker(pc) if *pc == back_pc))
                            .map(|p| p + 1)
                            .unwrap_or(0);
                        let body: Vec<Stmt> = out.split_off(body_stmts_start);
                        out.push(Stmt::Repeat { body, cond });
                        seed_params(regs, proto.numparams);
                        i += 1;
                        continue;
                    }
                }
            }
        }

        // ---- bare JUMP to loop break/continue targets ----
        if matches!(instr.op, LOP_JUMP | LOP_JUMPBACK | LOP_JUMPX) {
            let target_pc = match instr.op {
                LOP_JUMPX => (instr.pc as isize + 1 + instr.e as isize) as usize,
                _ => (instr.pc as isize + 1 + instr.d as isize) as usize,
            };
            if let Some(&target_idx) = pc_to_idx.get(&target_pc) {
                if Some(target_idx) == loop_ctx.break_target {
                    out.push(Stmt::Break);
                    i += 1;
                    continue;
                }
                if Some(target_idx) == loop_ctx.continue_target {
                    out.push(Stmt::Continue);
                    i += 1;
                    continue;
                }
            }
        }

        // ---- fallback: plain instruction lifting ----
        lift_instr(
            file,
            proto,
            instr,
            instrs,
            i,
            regs,
            &mut out,
            declared,
            pending_captures,
        )?;
        i += 1;
    }
    Ok(out)
}

/// Lift one instruction into statements and/or register updates.
#[allow(clippy::too_many_arguments)]
fn lift_instr(
    file: &BytecodeFile,
    proto: &Proto,
    i: &Instr,
    all: &[Instr],
    idx: usize,
    regs: &mut RegFile,
    stmts: &mut Vec<Stmt>,
    declared: &mut BTreeSet<u8>,
    pending_captures: &mut Vec<Capture>,
) -> Result<(), String> {
    use LuauOpcode::*;

    // Reusable helpers that rely on the context of this invocation.
    let kconst = |idx: usize| -> Expr { constant_to_expr(proto, idx) };
    let knum_or = |idx: usize, default: f64| -> f64 {
        match proto.k.get(idx) {
            Some(Constant::Number(n)) => *n,
            Some(Constant::Integer(n)) => *n as f64,
            _ => default,
        }
    };
    let _ = knum_or;

    match i.op {
        LOP_NOP | LOP_BREAK | LOP_COVERAGE | LOP_PREPVARARGS => {
            // No-ops for source reconstruction purposes.
        }

        LOP_LOADNIL => regs.set(i.a, Expr::Nil),
        LOP_LOADB => {
            regs.set(i.a, Expr::Bool(i.b != 0));
            // `LOP_LOADB` with C != 0 also jumps forward by C; we let the
            // jump-target pass handle the label, but we don't structure it.
        }
        LOP_LOADN => regs.set(i.a, Expr::Num(i.d as f64)),
        LOP_LOADK => regs.set(i.a, kconst(i.d as u16 as usize)),
        LOP_LOADKX => regs.set(i.a, kconst(i.aux as usize)),
        LOP_MOVE => {
            let src = regs.get(i.b);
            regs.set(i.a, src);
        }
        LOP_GETUPVAL => regs.set(i.a, Expr::Upval(i.b)),
        LOP_SETUPVAL => {
            stmts.push(Stmt::Assign {
                target: Expr::Upval(i.b),
                value: regs.get(i.a),
            });
        }
        LOP_CLOSEUPVALS => {
            // Informational — mention it as a comment so the line count
            // roughly tracks bytecode flow.
        }

        LOP_GETGLOBAL => {
            let name = string_const(proto, i.aux as usize)
                .unwrap_or_else(|| format!("_G_{}", i.aux));
            regs.set(i.a, Expr::Global(name));
        }
        LOP_SETGLOBAL => {
            let name = string_const(proto, i.aux as usize)
                .unwrap_or_else(|| format!("_G_{}", i.aux));
            stmts.push(Stmt::Assign {
                target: Expr::Global(name),
                value: regs.get(i.a),
            });
        }

        LOP_GETIMPORT => {
            regs.set(i.a, import_path_expr(proto, i.aux));
            // aux is followed by the k-index of the "fallback" constant
            // which was already loaded as LOP_LOADK into register a; the
            // runtime prefers the import chain if available.
        }

        LOP_GETTABLE => {
            let t = regs.get(i.b);
            let k = regs.get(i.c);
            regs.set(i.a, Expr::Index(Box::new(t), Box::new(k)));
        }
        LOP_SETTABLE => {
            let t = regs.get(i.b);
            let k = regs.get(i.c);
            stmts.push(Stmt::Assign {
                target: Expr::Index(Box::new(t), Box::new(k)),
                value: regs.get(i.a),
            });
        }
        LOP_GETTABLEKS => {
            let t = regs.get(i.b);
            let name = string_const(proto, i.aux as usize)
                .unwrap_or_else(|| format!("k{}", i.aux));
            regs.set(i.a, field_or_index(t, name));
        }
        LOP_SETTABLEKS => {
            let name = string_const(proto, i.aux as usize)
                .unwrap_or_else(|| format!("k{}", i.aux));
            let value = regs.get(i.a);
            // If register `b` still holds a non-escaped in-progress table
            // literal, merge the key/value into its hash part instead of
            // emitting a standalone `t.k = v` statement.
            if let Some(Expr::Table { hash, .. }) = regs.regs.get_mut(&i.b) {
                hash.push((Expr::Str(name), value));
            } else {
                let t = regs.get(i.b);
                stmts.push(Stmt::Assign {
                    target: field_or_index(t, name),
                    value,
                });
            }
        }
        LOP_GETTABLEN => {
            let t = regs.get(i.b);
            regs.set(
                i.a,
                Expr::Index(Box::new(t), Box::new(Expr::Num((i.c as u32 + 1) as f64))),
            );
        }
        LOP_SETTABLEN => {
            let idx_val = Expr::Num((i.c as u32 + 1) as f64);
            let value = regs.get(i.a);
            if let Some(Expr::Table { array, .. }) = regs.regs.get_mut(&i.b) {
                // Fill with `nil` until the slot matches the 1-based index.
                let want = (i.c as usize) + 1;
                while array.len() + 1 < want {
                    array.push(Expr::Nil);
                }
                if array.len() + 1 == want {
                    array.push(value);
                } else {
                    // Out-of-order write; fall back to standalone assign.
                    let t = regs.get(i.b);
                    stmts.push(Stmt::Assign {
                        target: Expr::Index(Box::new(t), Box::new(idx_val)),
                        value,
                    });
                }
            } else {
                let t = regs.get(i.b);
                stmts.push(Stmt::Assign {
                    target: Expr::Index(Box::new(t), Box::new(idx_val)),
                    value,
                });
            }
        }

        LOP_NEWTABLE => regs.set(
            i.a,
            Expr::Table {
                array: Vec::new(),
                hash: Vec::new(),
            },
        ),
        LOP_DUPTABLE => regs.set(
            i.a,
            Expr::Table {
                array: Vec::new(),
                hash: Vec::new(),
            },
        ),
        LOP_SETLIST => {
            // Merge array part into the existing table literal in reg A.
            let count = if i.c == 0 { 0 } else { (i.c as usize) - 1 };
            let base = i.b;
            let mut items = Vec::with_capacity(count);
            for j in 0..count {
                items.push(regs.get(base + j as u8));
            }
            if let Some(Expr::Table { array, .. }) = regs.regs.get_mut(&i.a) {
                array.extend(items);
            } else {
                // Fall back to re-creating a table literal.
                regs.set(
                    i.a,
                    Expr::Table {
                        array: items,
                        hash: Vec::new(),
                    },
                );
            }
        }

        LOP_NEWCLOSURE | LOP_DUPCLOSURE => {
            let child_idx = match i.op {
                LOP_DUPCLOSURE => match proto.k.get(i.d as u16 as usize) {
                    Some(Constant::Closure(idx)) => *idx,
                    _ => i.d as u16 as usize,
                },
                _ => proto.child_proto_indices.get(i.d as u16 as usize).copied()
                    .unwrap_or(i.d as u16 as usize),
            };
            regs.set(i.a, Expr::Closure(child_idx));
            pending_captures.clear();
        }
        LOP_CAPTURE => {
            pending_captures.push(Capture {
                kind: i.a,
                idx: i.b,
            });
        }

        LOP_NAMECALL => {
            let obj = regs.get(i.b);
            let name = string_const(proto, i.aux as usize)
                .unwrap_or_else(|| format!("k{}", i.aux));
            // NAMECALL sets A+1 = obj and leaves the call expression in A.
            // We defer until the following LOP_CALL consumes it.
            regs.set(i.a, Expr::Raw(format!("__namecall_{}_{}", i.b, name)));
            regs.set(i.a + 1, obj);
            // Marker: next LOP_CALL at A should become a method call.
            regs.set(
                i.a,
                Expr::Raw(format!("__PENDING_NAMECALL:{}:{}", i.b, name)),
            );
            let _ = name;
        }

        LOP_CALL => {
            // Detect a pending namecall baked into reg a by LOP_NAMECALL.
            let func_slot = regs.take(i.a);
            let pending = match &func_slot {
                Expr::Raw(s) if s.starts_with("__PENDING_NAMECALL:") => {
                    let rest = &s["__PENDING_NAMECALL:".len()..];
                    let mut it = rest.splitn(2, ':');
                    let obj_reg = it.next().and_then(|s| s.parse::<u8>().ok());
                    let name = it.next().map(|s| s.to_string());
                    match (obj_reg, name) {
                        (Some(r), Some(n)) => Some((r, n)),
                        _ => None,
                    }
                }
                _ => None,
            };

            // Gather args.
            let arg_base = i.a + 1;
            let nargs_field = i.b;
            let mut args: Vec<Expr> = Vec::new();
            let mut vararg_tail = false;
            if nargs_field == 0 {
                // Trailing multret from previous expression.
                vararg_tail = true;
            } else if nargs_field >= 1 {
                let n = (nargs_field as usize) - 1;
                for j in 0..n {
                    args.push(regs.get(arg_base + j as u8));
                }
            }

            // For method calls, we need to drop the implicit self arg
            // (which was placed at A+1 by LOP_NAMECALL).
            if pending.is_some() && !args.is_empty() {
                args.remove(0);
            }

            let call_expr = match pending {
                Some((obj_reg, name)) => Expr::Method {
                    obj: Box::new(regs.get(obj_reg)),
                    name,
                    args,
                    vararg_tail,
                },
                None => Expr::Call {
                    func: Box::new(func_slot),
                    args,
                    vararg_tail,
                },
            };

            let nret_field = i.c;
            match nret_field {
                0 => {
                    // multret. Bind to a local so the call happens once
                    // and subsequent reads just reference the register.
                    emit_bound_call(stmts, declared, &[i.a], call_expr);
                    regs.set(i.a, Expr::Reg(i.a));
                }
                1 => {
                    // No returns consumed — pure side-effect statement.
                    stmts.push(Stmt::Call(call_expr));
                    regs.invalidate_from(i.a);
                }
                _ => {
                    let nret = (nret_field as usize) - 1;
                    let regs_bound: Vec<u8> =
                        (0..nret).map(|j| i.a + j as u8).collect();
                    emit_bound_call(stmts, declared, &regs_bound, call_expr);
                    for r in &regs_bound {
                        regs.set(*r, Expr::Reg(*r));
                    }
                }
            }
        }

        LOP_RETURN => {
            let count_field = i.b;
            let mut values = Vec::new();
            if count_field == 0 {
                // multret from reg A onwards; we can't know the count.
                values.push(regs.get(i.a));
            } else if count_field >= 1 {
                let n = (count_field as usize) - 1;
                for j in 0..n {
                    values.push(regs.get(i.a + j as u8));
                }
            }
            stmts.push(Stmt::Return(values));
        }

        LOP_JUMP | LOP_JUMPBACK | LOP_JUMPX => {
            let target = match i.op {
                LOP_JUMPX => (i.pc as isize + 1 + i.e as isize) as usize,
                _ => (i.pc as isize + 1 + i.d as isize) as usize,
            };
            stmts.push(Stmt::GotoComment(
                target,
                format!("{:?} +{}", i.op, i.d as i32),
            ));
        }
        LOP_JUMPIF => {
            let target = (i.pc as isize + 1 + i.d as isize) as usize;
            stmts.push(Stmt::Comment(format!(
                "if {} then goto L{} end",
                render_expr(&regs.get(i.a), Prec::Lowest, file, 0),
                target
            )));
        }
        LOP_JUMPIFNOT => {
            let target = (i.pc as isize + 1 + i.d as isize) as usize;
            stmts.push(Stmt::Comment(format!(
                "if not {} then goto L{} end",
                render_expr(&regs.get(i.a), Prec::Lowest, file, 0),
                target
            )));
        }
        LOP_JUMPIFEQ | LOP_JUMPIFLE | LOP_JUMPIFLT | LOP_JUMPIFNOTEQ | LOP_JUMPIFNOTLE
        | LOP_JUMPIFNOTLT => {
            let op = match i.op {
                LOP_JUMPIFEQ => "==",
                LOP_JUMPIFLE => "<=",
                LOP_JUMPIFLT => "<",
                LOP_JUMPIFNOTEQ => "~=",
                LOP_JUMPIFNOTLE => ">",
                LOP_JUMPIFNOTLT => ">=",
                _ => "?",
            };
            let target = (i.pc as isize + 1 + i.d as isize) as usize;
            stmts.push(Stmt::Comment(format!(
                "if {} {} {} then goto L{} end",
                render_expr(&regs.get(i.a), Prec::Cmp, file, 0),
                op,
                render_expr(&regs.get(i.aux as u8), Prec::Cmp, file, 0),
                target
            )));
        }

        LOP_GETVARARGS => {
            if i.b == 0 || i.b == 1 {
                regs.set(i.a, Expr::Vararg);
            } else {
                for j in 0..(i.b as usize - 1) {
                    regs.set(i.a + j as u8, Expr::Vararg);
                }
            }
        }

        LOP_ADD | LOP_SUB | LOP_MUL | LOP_DIV | LOP_MOD | LOP_POW | LOP_IDIV => {
            let op = arith_op(i.op);
            regs.set(
                i.a,
                Expr::BinOp {
                    op,
                    lhs: Box::new(regs.get(i.b)),
                    rhs: Box::new(regs.get(i.c)),
                },
            );
        }
        LOP_ADDK | LOP_SUBK | LOP_MULK | LOP_DIVK | LOP_MODK | LOP_POWK | LOP_IDIVK => {
            let op = arith_op(i.op);
            regs.set(
                i.a,
                Expr::BinOp {
                    op,
                    lhs: Box::new(regs.get(i.b)),
                    rhs: Box::new(kconst(i.c as usize)),
                },
            );
        }
        LOP_SUBRK | LOP_DIVRK => {
            // rhs is reg, lhs is constant.
            let op = if matches!(i.op, LOP_SUBRK) { "-" } else { "/" };
            regs.set(
                i.a,
                Expr::BinOp {
                    op,
                    lhs: Box::new(kconst(i.b as usize)),
                    rhs: Box::new(regs.get(i.c)),
                },
            );
        }
        LOP_AND => regs.set(
            i.a,
            Expr::BinOp {
                op: "and",
                lhs: Box::new(regs.get(i.b)),
                rhs: Box::new(regs.get(i.c)),
            },
        ),
        LOP_OR => regs.set(
            i.a,
            Expr::BinOp {
                op: "or",
                lhs: Box::new(regs.get(i.b)),
                rhs: Box::new(regs.get(i.c)),
            },
        ),
        LOP_ANDK => regs.set(
            i.a,
            Expr::BinOp {
                op: "and",
                lhs: Box::new(regs.get(i.b)),
                rhs: Box::new(kconst(i.c as usize)),
            },
        ),
        LOP_ORK => regs.set(
            i.a,
            Expr::BinOp {
                op: "or",
                lhs: Box::new(regs.get(i.b)),
                rhs: Box::new(kconst(i.c as usize)),
            },
        ),
        LOP_CONCAT => {
            let mut parts = Vec::new();
            for r in i.b..=i.c {
                parts.push(regs.get(r));
            }
            regs.set(i.a, Expr::Concat(parts));
        }
        LOP_NOT => regs.set(
            i.a,
            Expr::UnOp {
                op: "not ",
                operand: Box::new(regs.get(i.b)),
            },
        ),
        LOP_MINUS => regs.set(
            i.a,
            Expr::UnOp {
                op: "-",
                operand: Box::new(regs.get(i.b)),
            },
        ),
        LOP_LENGTH => regs.set(i.a, Expr::Length(Box::new(regs.get(i.b)))),

        LOP_FORNPREP | LOP_FORNLOOP | LOP_FORGPREP | LOP_FORGLOOP | LOP_FORGPREP_NEXT
        | LOP_FORGPREP_INEXT => {
            stmts.push(Stmt::Comment(format!(
                "TODO: structure {:?} (pc {}, target {})",
                i.op,
                i.pc,
                (i.pc as isize + 1 + i.d as isize) as usize
            )));
        }

        LOP_FASTCALL | LOP_FASTCALL1 | LOP_FASTCALL2 | LOP_FASTCALL2K | LOP_FASTCALL3
        | LOP_NATIVECALL => {
            // Fastcalls are a runtime optimization — the regular CALL
            // follows and produces the actual call expression.
        }

        LOP_JUMPXEQKNIL | LOP_JUMPXEQKB | LOP_JUMPXEQKN | LOP_JUMPXEQKS => {
            let target = (i.pc as isize + 1 + i.d as isize) as usize;
            stmts.push(Stmt::Comment(format!(
                "cmp-jump {:?} R{} aux={:#x} -> L{}",
                i.op, i.a, i.aux, target
            )));
        }

        _ => {
            stmts.push(Stmt::Comment(format!(
                "TODO opcode {:?} A={} B={} C={} D={} aux={:#x}",
                i.op, i.a, i.b, i.c, i.d, i.aux
            )));
        }
    }
    Ok(())
}

/// Emit either a multi-target `local` binding or a plain multi-target
/// assignment for the result of a call, depending on whether each
/// register has been declared as a local yet in this scope.
fn emit_bound_call(
    stmts: &mut Vec<Stmt>,
    declared: &mut BTreeSet<u8>,
    regs_bound: &[u8],
    value: Expr,
) {
    let any_new = regs_bound.iter().any(|r| !declared.contains(r));
    let names: Vec<String> = regs_bound.iter().map(|r| format!("v{}", r)).collect();
    for r in regs_bound {
        declared.insert(*r);
    }
    if any_new {
        stmts.push(Stmt::LocalList {
            names,
            value,
            extra: 0,
        });
    } else if regs_bound.len() == 1 {
        stmts.push(Stmt::Assign {
            target: Expr::Reg(regs_bound[0]),
            value,
        });
    } else {
        // Plain multi-assignment: `v<a>, v<b> = call(...)`.
        let targets: Vec<Expr> = regs_bound.iter().map(|r| Expr::Reg(*r)).collect();
        stmts.push(Stmt::MultiAssign { targets, value });
    }
}

fn arith_op(op: LuauOpcode) -> &'static str {
    match op {
        LuauOpcode::LOP_ADD | LuauOpcode::LOP_ADDK => "+",
        LuauOpcode::LOP_SUB | LuauOpcode::LOP_SUBK | LuauOpcode::LOP_SUBRK => "-",
        LuauOpcode::LOP_MUL | LuauOpcode::LOP_MULK => "*",
        LuauOpcode::LOP_DIV | LuauOpcode::LOP_DIVK | LuauOpcode::LOP_DIVRK => "/",
        LuauOpcode::LOP_IDIV | LuauOpcode::LOP_IDIVK => "//",
        LuauOpcode::LOP_MOD | LuauOpcode::LOP_MODK => "%",
        LuauOpcode::LOP_POW | LuauOpcode::LOP_POWK => "^",
        _ => "?",
    }
}

fn is_last_instruction(all: &[Instr], idx: usize) -> bool {
    idx + 1 >= all.len()
}

fn string_const(proto: &Proto, idx: usize) -> Option<String> {
    match proto.k.get(idx)? {
        Constant::String(s) => Some(s.clone()),
        _ => None,
    }
}

fn constant_to_expr(proto: &Proto, idx: usize) -> Expr {
    match proto.k.get(idx) {
        None => Expr::Raw(format!("<k#{}: missing>", idx)),
        Some(Constant::Nil) => Expr::Nil,
        Some(Constant::Boolean(b)) => Expr::Bool(*b),
        Some(Constant::Number(n)) => Expr::Num(*n),
        Some(Constant::Integer(n)) => Expr::Num(*n as f64),
        Some(Constant::Vector(x, y, z, w)) => Expr::Raw(format!(
            "Vector({:.6}, {:.6}, {:.6}, {:.6})",
            x, y, z, w
        )),
        Some(Constant::String(s)) => Expr::Str(s.clone()),
        Some(Constant::Import(aux)) => import_path_expr(proto, *aux),
        Some(Constant::Table(_)) => Expr::Table {
            array: Vec::new(),
            hash: Vec::new(),
        },
        Some(Constant::TableWithConstants(_)) => Expr::Table {
            array: Vec::new(),
            hash: Vec::new(),
        },
        Some(Constant::Closure(idx)) => Expr::Closure(*idx),
    }
}

fn import_path_expr(proto: &Proto, aux: u32) -> Expr {
    let count = (aux >> 30) as usize;
    if count == 0 || count > 3 {
        return Expr::Raw(format!("import({:#x})", aux));
    }
    let ids = [
        ((aux >> 20) & 0x3FF) as usize,
        ((aux >> 10) & 0x3FF) as usize,
        (aux & 0x3FF) as usize,
    ];
    let mut parts = Vec::with_capacity(count);
    for id in ids.iter().take(count) {
        match proto.k.get(*id) {
            Some(Constant::String(s)) => parts.push(s.clone()),
            _ => return Expr::Raw(format!("import({:#x})", aux)),
        }
    }
    Expr::ImportPath(parts)
}

fn field_or_index(base: Expr, name: String) -> Expr {
    if is_identifier(&name) {
        Expr::Field(Box::new(base), name)
    } else {
        Expr::Index(Box::new(base), Box::new(Expr::Str(name)))
    }
}

fn is_identifier(s: &str) -> bool {
    let mut it = s.chars();
    match it.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    for c in it {
        if !(c.is_ascii_alphanumeric() || c == '_') {
            return false;
        }
    }
    !LUA_KEYWORDS.contains(&s)
}

const LUA_KEYWORDS: &[&str] = &[
    "and", "break", "do", "else", "elseif", "end", "false", "for", "function", "if", "in",
    "local", "nil", "not", "or", "repeat", "return", "then", "true", "until", "while",
    // Luau-specific
    "continue", "export", "type",
];

/// Render an expression with precedence-aware parenthesization.
fn render_expr(e: &Expr, outer: Prec, file: &BytecodeFile, indent: usize) -> String {
    let (inner, prec) = match e {
        Expr::Nil => ("nil".to_string(), Prec::Primary),
        Expr::Bool(b) => (if *b { "true".into() } else { "false".into() }, Prec::Primary),
        Expr::Num(n) => (format_num(*n), Prec::Primary),
        Expr::Str(s) => (format_str(s), Prec::Primary),
        Expr::Vararg => ("...".into(), Prec::Primary),
        Expr::Reg(r) => (format!("v{}", r), Prec::Primary),
        Expr::Upval(u) => (format!("u{}", u), Prec::Primary),
        Expr::Global(name) => (name.clone(), Prec::Primary),
        Expr::ImportPath(parts) => (parts.join("."), Prec::Primary),
        Expr::Closure(child_idx) => {
            let pad = "  ".repeat(indent);
            match file.protos.get(*child_idx) {
                Some(child) => {
                    let header = proto_header(child);
                    let body = match reconstruct_proto_body(file, child, indent + 1) {
                        Ok(b) => b,
                        Err(e) => format!("{}  -- reconstruction error: {}\n", pad, e),
                    };
                    let rendered = format!("{}\n{}{}end", header, body, pad);
                    (rendered, Prec::Primary)
                }
                None => (
                    format!("(--[[closure #{} missing]] nil)", child_idx),
                    Prec::Primary,
                ),
            }
        }
        Expr::Index(t, k) => (
            format!(
                "{}[{}]",
                render_expr(t, Prec::Primary, file, indent),
                render_expr(k, Prec::Lowest, file, indent)
            ),
            Prec::Primary,
        ),
        Expr::Field(t, name) => (
            format!("{}.{}", render_expr(t, Prec::Primary, file, indent), name),
            Prec::Primary,
        ),
        Expr::Call {
            func,
            args,
            vararg_tail,
        } => {
            let mut s = format!("{}(", render_expr(func, Prec::Primary, file, indent));
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&render_expr(a, Prec::Lowest, file, indent));
            }
            if *vararg_tail {
                if !args.is_empty() {
                    s.push_str(", ");
                }
                s.push_str("...");
            }
            s.push(')');
            (s, Prec::Primary)
        }
        Expr::Method {
            obj,
            name,
            args,
            vararg_tail,
        } => {
            let mut s = format!("{}:{}(", render_expr(obj, Prec::Primary, file, indent), name);
            for (i, a) in args.iter().enumerate() {
                if i > 0 {
                    s.push_str(", ");
                }
                s.push_str(&render_expr(a, Prec::Lowest, file, indent));
            }
            if *vararg_tail {
                if !args.is_empty() {
                    s.push_str(", ");
                }
                s.push_str("...");
            }
            s.push(')');
            (s, Prec::Primary)
        }
        Expr::BinOp { op, lhs, rhs } => {
            let prec = binop_prec(op);
            let left = render_expr(lhs, prec, file, indent);
            let right = render_expr(rhs, prec, file, indent);
            (format!("{} {} {}", left, op, right), prec)
        }
        Expr::UnOp { op, operand } => (
            format!("{}{}", op, render_expr(operand, Prec::Unary, file, indent)),
            Prec::Unary,
        ),
        Expr::Concat(parts) => {
            let rendered = parts
                .iter()
                .map(|p| render_expr(p, Prec::Concat, file, indent))
                .collect::<Vec<_>>()
                .join(" .. ");
            (rendered, Prec::Concat)
        }
        Expr::Length(x) => (
            format!("#{}", render_expr(x, Prec::Unary, file, indent)),
            Prec::Unary,
        ),
        Expr::Table { array, hash } => {
            let mut parts = Vec::new();
            for a in array {
                parts.push(render_expr(a, Prec::Lowest, file, indent));
            }
            for (k, v) in hash {
                let key = match k {
                    Expr::Str(s) if is_identifier(s) => s.clone(),
                    other => format!("[{}]", render_expr(other, Prec::Lowest, file, indent)),
                };
                parts.push(format!(
                    "{} = {}",
                    key,
                    render_expr(v, Prec::Lowest, file, indent)
                ));
            }
            (format!("{{{}}}", parts.join(", ")), Prec::Primary)
        }
        Expr::Raw(s) => (s.clone(), Prec::Primary),
    };
    if prec < outer {
        format!("({})", inner)
    } else {
        inner
    }
}

fn format_num(n: f64) -> String {
    if n.is_nan() {
        "(0/0)".into()
    } else if n.is_infinite() {
        if n > 0.0 { "(1/0)".into() } else { "(-1/0)".into() }
    } else if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{}", n)
    }
}

fn format_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\0' => out.push_str("\\0"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\{}", c as u32));
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn render_stmt(
    out: &mut String,
    s: &Stmt,
    pad: &str,
    file: &BytecodeFile,
    indent: usize,
) -> Result<(), String> {
    match s {
        Stmt::Assign { target, value } => {
            if let Some(rendered) =
                try_render_function_assign(target, value, pad, file, indent)
            {
                out.push_str(&rendered);
            } else {
                writeln!(
                    out,
                    "{}{} = {}",
                    pad,
                    render_expr(target, Prec::Lowest, file, indent),
                    render_expr(value, Prec::Lowest, file, indent)
                )
                .map_err(|e| e.to_string())?;
            }
        }
        Stmt::MultiAssign { targets, value } => {
            let rendered: Vec<String> = targets
                .iter()
                .map(|t| render_expr(t, Prec::Lowest, file, indent))
                .collect();
            writeln!(
                out,
                "{}{} = {}",
                pad,
                rendered.join(", "),
                render_expr(value, Prec::Lowest, file, indent)
            )
            .map_err(|e| e.to_string())?;
        }
        Stmt::LocalList { names, value, extra } => {
            let all_names = names.clone();
            let _ = extra;
            if names.len() == 1 {
                if let Expr::Closure(child_idx) = value {
                    if let Some(child) = file.protos.get(*child_idx) {
                        if !looks_like_method(child) {
                            let header =
                                proto_header_named(child, &names[0], false);
                            let body = match reconstruct_proto_body(
                                file,
                                child,
                                indent + 1,
                            ) {
                                Ok(b) => b,
                                Err(e) => format!(
                                    "{}  -- reconstruction error: {}\n",
                                    pad, e
                                ),
                            };
                            writeln!(out, "{}local {}", pad, header)
                                .map_err(|e| e.to_string())?;
                            out.push_str(&body);
                            writeln!(out, "{}end", pad)
                                .map_err(|e| e.to_string())?;
                            return Ok(());
                        }
                    }
                }
            }
            writeln!(
                out,
                "{}local {} = {}",
                pad,
                all_names.join(", "),
                render_expr(value, Prec::Lowest, file, indent)
            )
            .map_err(|e| e.to_string())?;
        }
        Stmt::Call(e) => {
            writeln!(
                out,
                "{}{}",
                pad,
                render_expr(e, Prec::Lowest, file, indent)
            )
            .map_err(|e| e.to_string())?;
        }
        Stmt::Return(values) => {
            if values.is_empty() {
                writeln!(out, "{}return", pad).map_err(|e| e.to_string())?;
            } else {
                let rendered = values
                    .iter()
                    .map(|v| render_expr(v, Prec::Lowest, file, indent))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(out, "{}return {}", pad, rendered).map_err(|e| e.to_string())?;
            }
        }
        Stmt::Comment(c) => {
            writeln!(out, "{}-- {}", pad, c).map_err(|e| e.to_string())?;
        }
        Stmt::LabelMarker(pc) => {
            writeln!(out, "{}-- [L{}]", pad, pc).map_err(|e| e.to_string())?;
        }
        Stmt::GotoComment(target, detail) => {
            writeln!(out, "{}-- goto L{}  ({})", pad, target, detail).map_err(|e| e.to_string())?;
        }
        Stmt::Blank => {
            writeln!(out).map_err(|e| e.to_string())?;
        }
        Stmt::Break => {
            writeln!(out, "{}break", pad).map_err(|e| e.to_string())?;
        }
        Stmt::Continue => {
            writeln!(out, "{}continue", pad).map_err(|e| e.to_string())?;
        }
        Stmt::If {
            cond,
            then_block,
            else_block,
        } => {
            writeln!(
                out,
                "{}if {} then",
                pad,
                render_expr(cond, Prec::Lowest, file, indent)
            )
            .map_err(|e| e.to_string())?;
            let body_pad = "  ".repeat(indent + 1);
            for s in then_block {
                render_stmt(out, s, &body_pad, file, indent + 1)?;
            }
            if let Some(else_b) = else_block {
                // Collapse `else { if ... }` into `elseif`.
                if else_b.len() == 1 {
                    if let Stmt::If {
                        cond: c2,
                        then_block: t2,
                        else_block: e2,
                    } = &else_b[0]
                    {
                        writeln!(
                            out,
                            "{}elseif {} then",
                            pad,
                            render_expr(c2, Prec::Lowest, file, indent)
                        )
                        .map_err(|e| e.to_string())?;
                        for s in t2 {
                            render_stmt(out, s, &body_pad, file, indent + 1)?;
                        }
                        if let Some(e3) = e2 {
                            writeln!(out, "{}else", pad).map_err(|e| e.to_string())?;
                            for s in e3 {
                                render_stmt(out, s, &body_pad, file, indent + 1)?;
                            }
                        }
                        writeln!(out, "{}end", pad).map_err(|e| e.to_string())?;
                        return Ok(());
                    }
                }
                writeln!(out, "{}else", pad).map_err(|e| e.to_string())?;
                for s in else_b {
                    render_stmt(out, s, &body_pad, file, indent + 1)?;
                }
            }
            writeln!(out, "{}end", pad).map_err(|e| e.to_string())?;
        }
        Stmt::While { cond, body } => {
            writeln!(
                out,
                "{}while {} do",
                pad,
                render_expr(cond, Prec::Lowest, file, indent)
            )
            .map_err(|e| e.to_string())?;
            let body_pad = "  ".repeat(indent + 1);
            for s in body {
                render_stmt(out, s, &body_pad, file, indent + 1)?;
            }
            writeln!(out, "{}end", pad).map_err(|e| e.to_string())?;
        }
        Stmt::Repeat { body, cond } => {
            writeln!(out, "{}repeat", pad).map_err(|e| e.to_string())?;
            let body_pad = "  ".repeat(indent + 1);
            for s in body {
                render_stmt(out, s, &body_pad, file, indent + 1)?;
            }
            writeln!(
                out,
                "{}until {}",
                pad,
                render_expr(cond, Prec::Lowest, file, indent)
            )
            .map_err(|e| e.to_string())?;
        }
        Stmt::ForNum {
            var,
            start,
            limit,
            step,
            body,
        } => {
            let header = match step {
                Some(s) => format!(
                    "for {} = {}, {}, {} do",
                    var,
                    render_expr(start, Prec::Lowest, file, indent),
                    render_expr(limit, Prec::Lowest, file, indent),
                    render_expr(s, Prec::Lowest, file, indent),
                ),
                None => format!(
                    "for {} = {}, {} do",
                    var,
                    render_expr(start, Prec::Lowest, file, indent),
                    render_expr(limit, Prec::Lowest, file, indent),
                ),
            };
            writeln!(out, "{}{}", pad, header).map_err(|e| e.to_string())?;
            let body_pad = "  ".repeat(indent + 1);
            for s in body {
                render_stmt(out, s, &body_pad, file, indent + 1)?;
            }
            writeln!(out, "{}end", pad).map_err(|e| e.to_string())?;
        }
        Stmt::ForGen { vars, exprs, body } => {
            let rhs = exprs
                .iter()
                .map(|e| render_expr(e, Prec::Lowest, file, indent))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(out, "{}for {} in {} do", pad, vars.join(", "), rhs)
                .map_err(|e| e.to_string())?;
            let body_pad = "  ".repeat(indent + 1);
            for s in body {
                render_stmt(out, s, &body_pad, file, indent + 1)?;
            }
            writeln!(out, "{}end", pad).map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_str_escapes_controls_and_quotes() {
        assert_eq!(format_str("hello"), "\"hello\"");
        assert_eq!(format_str("a\"b"), "\"a\\\"b\"");
        assert_eq!(format_str("\n\r\t"), "\"\\n\\r\\t\"");
    }

    #[test]
    fn format_num_prefers_integer_when_exact() {
        assert_eq!(format_num(0.0), "0");
        assert_eq!(format_num(-7.0), "-7");
        assert_eq!(format_num(1.5), "1.5");
    }

    #[test]
    fn is_identifier_rejects_keywords_and_bad_starts() {
        assert!(is_identifier("foo"));
        assert!(is_identifier("_bar"));
        assert!(is_identifier("foo_bar9"));
        assert!(!is_identifier("if"));
        assert!(!is_identifier("return"));
        assert!(!is_identifier("9foo"));
        assert!(!is_identifier("foo bar"));
        assert!(!is_identifier(""));
    }

    #[test]
    fn field_or_index_picks_dot_for_identifiers() {
        let base = Expr::Reg(0);
        match field_or_index(base.clone(), "foo".into()) {
            Expr::Field(_, n) => assert_eq!(n, "foo"),
            other => panic!("expected Field, got {:?}", other),
        }
        match field_or_index(base, "bad key".into()) {
            Expr::Index(_, k) => match *k {
                Expr::Str(s) => assert_eq!(s, "bad key"),
                other => panic!("expected Str key, got {:?}", other),
            },
            other => panic!("expected Index, got {:?}", other),
        }
    }

    #[test]
    fn import_path_expr_decodes_packed_aux() {
        // Construct a synthetic proto with two string constants and an
        // import packed as `(count=2, ids=[0, 1])`.
        let proto = Proto {
            source: String::new(),
            bytecodeid: 0,
            maxstacksize: 1,
            numparams: 0,
            nups: 0,
            is_vararg: 0,
            flags: 0,
            typeinfo: vec![],
            sizetypeinfo: 0,
            code: vec![],
            sizecode: 0,
            k: vec![
                Constant::String("EventIds".into()),
                Constant::String("EVENT_TEST".into()),
            ],
            sizek: 2,
            p: vec![],
            child_proto_indices: vec![],
            sizep: 0,
            linedefined: 0,
            debugname: String::new(),
            linegaplog2: 0,
            lineinfo: vec![],
            sizelineinfo: 0,
            abslineinfo: vec![],
        };
        let aux = (2u32 << 30) | (0u32 << 20) | (1u32 << 10);
        match import_path_expr(&proto, aux) {
            Expr::ImportPath(parts) => {
                assert_eq!(parts, vec!["EventIds", "EVENT_TEST"]);
            }
            other => panic!("expected ImportPath, got {:?}", other),
        }
    }
}
