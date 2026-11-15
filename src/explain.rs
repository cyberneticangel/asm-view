//! Turns a disassembled instruction into a short, human-readable comment.
//!
//! The comments are deliberately pseudo-C-ish (`rax = rbx + 8`) because that
//! reads faster than prose when scanning a listing.

use crate::Symbols;

/// Broad category of an instruction, used for coloring.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Jump,
    Call,
    Return,
    Move,
    Arith,
    Logic,
    Compare,
    Stack,
    Nop,
    System,
    Simd,
    Other,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Isa {
    X86,
    Arm64,
    Arm,
    RiscV,
}

pub struct Ctx<'a> {
    pub isa: Isa,
    pub att: bool,
    pub syms: &'a Symbols,
}

/// Split an operand string on top-level commas (ignoring commas inside
/// brackets/parentheses, e.g. AT&T `(%rax,%rbx,4)` or ARM `[x0, #8]`).
pub fn split_operands(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '[' | '(' | '{' => depth += 1,
            ']' | ')' | '}' => depth -= 1,
            ',' if depth == 0 => {
                out.push(cur.trim().to_string());
                cur.clear();
                continue;
            }
            _ => {}
        }
        cur.push(c);
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Find the first hexadecimal literal in an operand string (branch targets).
pub fn find_hex(s: &str) -> Option<u64> {
    let i = s.find("0x")?;
    let digits: String = s[i + 2..]
        .chars()
        .take_while(|c| c.is_ascii_hexdigit())
        .collect();
    u64::from_str_radix(&digits, 16).ok()
}

/// Make an x86 memory operand easier to read:
/// `qword ptr [rbp - 8]` -> `[rbp - 8]` (size is described separately).
fn clean_mem(op: &str) -> String {
    for p in ["byte ptr ", "word ptr ", "dword ptr ", "qword ptr ", "xmmword ptr ",
              "ymmword ptr ", "zmmword ptr ", "tbyte ptr ", "ptr "] {
        if let Some(rest) = op.strip_prefix(p) {
            return rest.to_string();
        }
    }
    op.to_string()
}

fn mem_size(op: &str) -> Option<&'static str> {
    let table = [
        ("byte ptr", "1 byte"),
        ("dword ptr", "4 bytes"),
        ("qword ptr", "8 bytes"),
        ("xmmword ptr", "16 bytes"),
        ("ymmword ptr", "32 bytes"),
        ("zmmword ptr", "64 bytes"),
        ("tbyte ptr", "10 bytes"),
        ("word ptr", "2 bytes"),
    ];
    table.iter().find(|(p, _)| op.starts_with(p)).map(|(_, s)| *s)
}

/// Strip the brackets from a memory operand: `[rbp - 8]` -> `rbp - 8`.
fn addr_expr(op: &str) -> String {
    let m = clean_mem(op);
    let m = m.split_once(':').map(|(_, r)| r).unwrap_or(&m).to_string(); // drop segment
    m.trim_start_matches('[').trim_end_matches(']').to_string()
}

/// Rewrite `[rip + 0x2e5c]` as the absolute address it refers to, e.g. `[0x4010 <global>]`.
fn resolve_rip(ctx: &Ctx, op: &str, next_pc: u64) -> String {
    for (pat, sign) in [("rip + 0x", 1i64), ("rip - 0x", -1), ("0x", 0)] {
        let Some(i) = op.find(pat) else { continue };
        if sign == 0 {
            // AT&T form: 0x2e5c(%rip)
            if !op.contains("(%rip)") && !op.contains("(rip)") {
                return op.to_string();
            }
        }
        let digits: String = op[i + pat.len()..].chars().take_while(|c| c.is_ascii_hexdigit()).collect();
        let Ok(disp) = i64::from_str_radix(&digits, 16) else { return op.to_string() };
        let abs = next_pc.wrapping_add_signed(if sign == -1 { -disp } else { disp });
        let name = ctx.syms.describe(abs).map(|n| format!(" {n}")).unwrap_or_default();
        let prefix = &op[..op.find(['[', '(']).unwrap_or(i).min(i)];
        let prefix = if sign == 0 { &op[..i] } else { prefix };
        return format!("{prefix}[0x{abs:x}{name}]");
    }
    op.to_string()
}

fn target(ctx: &Ctx, op: &str) -> String {
    match find_hex(op) {
        Some(addr) => match ctx.syms.describe(addr) {
            Some(name) => format!("{name} (0x{addr:x})"),
            None => format!("0x{addr:x}"),
        },
        None => format!("address in {}", clean_mem(op)),
    }
}

/// Entry point: describe one instruction.
/// `next_pc` is the address of the following instruction (used for x86 RIP-relative operands).
pub fn explain(ctx: &Ctx, mnemonic: &str, op_str: &str, next_pc: u64) -> (Kind, String) {
    let mut ops = split_operands(op_str);
    if ctx.isa == Isa::X86 {
        ops = ops.into_iter().map(|o| resolve_rip(ctx, &o, next_pc)).collect();
    }
    match ctx.isa {
        Isa::X86 => {
            let mut m = mnemonic.to_string();
            if ctx.att {
                // AT&T puts the destination last and decorates registers/immediates.
                ops.reverse();
                ops = ops
                    .into_iter()
                    .map(|o| o.replace(['%', '$'], ""))
                    .collect();
            }
            let r = x86(ctx, &m, &ops);
            if ctx.att && r.0 == Kind::Other && m.len() > 3 {
                // AT&T size suffixes: movq, addl, ...
                m.pop();
                let r2 = x86(ctx, &m, &ops);
                if r2.0 != Kind::Other {
                    return r2;
                }
            }
            r
        }
        Isa::Arm64 | Isa::Arm => arm(ctx, mnemonic, &ops),
        Isa::RiscV => riscv(ctx, mnemonic, &ops),
    }
}

// ───────────────────────────── x86 / x86-64 ─────────────────────────────

fn cond_x86(cc: &str) -> Option<&'static str> {
    Some(match cc {
        "e" | "z" => "equal / zero",
        "ne" | "nz" => "not equal / not zero",
        "g" | "nle" => "greater (signed)",
        "ge" | "nl" => "greater or equal (signed)",
        "l" | "nge" => "less (signed)",
        "le" | "ng" => "less or equal (signed)",
        "a" | "nbe" => "above (unsigned >)",
        "ae" | "nb" | "nc" => "above or equal (unsigned >=)",
        "b" | "nae" | "c" => "below (unsigned <)",
        "be" | "na" => "below or equal (unsigned <=)",
        "s" => "sign set (negative)",
        "ns" => "sign clear (non-negative)",
        "o" => "overflow",
        "no" => "no overflow",
        "p" | "pe" => "parity even",
        "np" | "po" => "parity odd",
        _ => return None,
    })
}

fn x86(ctx: &Ctx, m: &str, ops: &[String]) -> (Kind, String) {
    use Kind::*;
    let a = ops.first().map(|s| clean_mem(s)).unwrap_or_default();
    let b = ops.get(1).map(|s| clean_mem(s)).unwrap_or_default();
    let c = ops.get(2).map(|s| clean_mem(s)).unwrap_or_default();
    let raw_a = ops.first().cloned().unwrap_or_default();
    let raw_b = ops.get(1).cloned().unwrap_or_default();
    let size = mem_size(&raw_a).or_else(|| mem_size(&raw_b));
    let sz = |s: String| match size {
        Some(sz) => format!("{s}  ({sz})"),
        None => s,
    };

    // Strip common prefixes and describe them.
    for (p, what) in [("lock ", "atomically: "), ("rep ", "repeat rcx times: "),
                      ("repe ", "repeat while equal: "), ("repne ", "repeat while not equal: "),
                      ("bnd ", ""), ("notrack ", "")] {
        if let Some(rest) = m.strip_prefix(p) {
            let (k, s) = x86(ctx, rest, ops);
            return (k, format!("{what}{s}"));
        }
    }

    let r = match m {
        // ── data movement
        "mov" | "movabs" => (Move, sz(format!("{a} = {b}"))),
        "movzx" => (Move, sz(format!("{a} = {b} (zero-extended)"))),
        "movsx" | "movsxd" => (Move, sz(format!("{a} = {b} (sign-extended)"))),
        "lea" => (Move, format!("{a} = {}  (address math, no memory access)", addr_expr(&b))),
        "xchg" => (Move, format!("swap {a} and {b}")),
        "cmpxchg" => (Move, format!("if accumulator == {a}: {a} = {b}, else load {a} into accumulator")),
        "xadd" => (Arith, format!("tmp = {a}; {a} += {b}; {b} = tmp")),
        "bswap" => (Move, format!("reverse byte order of {a}")),
        "cdq" => (Move, "edx:eax = sign-extend eax (prepare for idiv)".into()),
        "cqo" => (Move, "rdx:rax = sign-extend rax (prepare for idiv)".into()),
        "cwd" => (Move, "dx:ax = sign-extend ax".into()),
        "cdqe" => (Move, "rax = sign-extend eax".into()),
        "cwde" => (Move, "eax = sign-extend ax".into()),
        "cbw" => (Move, "ax = sign-extend al".into()),

        // ── stack
        "push" => (Stack, format!("rsp -= 8; [rsp] = {a}  (push onto stack)")),
        "pop" => (Stack, format!("{a} = [rsp]; rsp += 8  (pop from stack)")),
        "leave" => (Stack, "rsp = rbp; pop rbp  (tear down stack frame)".into()),
        "enter" => (Stack, format!("set up stack frame with {a} bytes of locals")),
        "pushfq" | "pushf" => (Stack, "push flags register".into()),
        "popfq" | "popf" => (Stack, "pop flags register".into()),

        // ── arithmetic
        "add" => (Arith, sz(format!("{a} += {b}"))),
        "sub" => (Arith, sz(format!("{a} -= {b}"))),
        "adc" => (Arith, format!("{a} += {b} + carry")),
        "sbb" if a == b => (Arith, format!("{a} = carry ? -1 : 0")),
        "sbb" => (Arith, format!("{a} -= {b} + carry")),
        "inc" => (Arith, sz(format!("{a} += 1"))),
        "dec" => (Arith, sz(format!("{a} -= 1"))),
        "neg" => (Arith, format!("{a} = -{a}")),
        "imul" => match ops.len() {
            1 => (Arith, format!("rdx:rax = rax * {a} (signed)")),
            2 => (Arith, format!("{a} *= {b} (signed)")),
            _ => (Arith, format!("{a} = {b} * {c} (signed)")),
        },
        "mul" => (Arith, format!("rdx:rax = rax * {a} (unsigned)")),
        "idiv" => (Arith, format!("rax = rdx:rax / {a}; rdx = remainder (signed)")),
        "div" => (Arith, format!("rax = rdx:rax / {a}; rdx = remainder (unsigned)")),

        // ── logic / bits
        "xor" if a == b => (Logic, format!("{a} = 0  (xor-with-self zeroing idiom)")),
        "xor" => (Logic, sz(format!("{a} ^= {b}"))),
        "and" => (Logic, sz(format!("{a} &= {b}"))),
        "or" => (Logic, sz(format!("{a} |= {b}"))),
        "not" => (Logic, format!("{a} = ~{a}")),
        "shl" | "sal" => (Logic, format!("{a} <<= {}", if b.is_empty() { "1".into() } else { b.clone() })),
        "shr" => (Logic, format!("{a} >>= {} (logical, zero-fill)", if b.is_empty() { "1".into() } else { b.clone() })),
        "sar" => (Logic, format!("{a} >>= {} (arithmetic, keeps sign)", if b.is_empty() { "1".into() } else { b.clone() })),
        "rol" => (Logic, format!("rotate {a} left by {b}")),
        "ror" => (Logic, format!("rotate {a} right by {b}")),
        "bt" => (Logic, format!("carry = bit {b} of {a}")),
        "bts" => (Logic, format!("carry = bit {b} of {a}; set it")),
        "btr" => (Logic, format!("carry = bit {b} of {a}; clear it")),
        "bsf" | "tzcnt" => (Logic, format!("{a} = index of lowest set bit in {b}")),
        "bsr" => (Logic, format!("{a} = index of highest set bit in {b}")),
        "lzcnt" => (Logic, format!("{a} = number of leading zero bits in {b}")),
        "popcnt" => (Logic, format!("{a} = number of set bits in {b}")),

        // ── compare
        "cmp" => (Compare, format!("compare {a} with {b}  (flags from {a} - {b})")),
        "test" if a == b => (Compare, format!("check whether {a} is zero / negative")),
        "test" => (Compare, format!("flags from {a} & {b}  (bit test)")),

        // ── control flow
        // Indirect through memory: the target is the pointer stored at that address.
        "jmp" if raw_a.contains(['[', '(']) => (Jump, format!("goto the address stored at {}", clean_mem(&raw_a))),
        "call" if raw_a.contains(['[', '(']) => (Call, format!("call function pointer stored at {}", clean_mem(&raw_a))),
        "jmp" => (Jump, format!("goto {}", target(ctx, &raw_a))),
        "call" => (Call, format!("call {}", target(ctx, &raw_a))),
        "ret" | "retq" => (Return, "return to caller (pop return address)".into()),
        "jrcxz" | "jecxz" => (Jump, format!("if rcx == 0 goto {}", target(ctx, &raw_a))),
        "loop" => (Jump, format!("rcx -= 1; if rcx != 0 goto {}", target(ctx, &raw_a))),

        // ── misc / system
        "nop" => (Nop, "no operation (padding / alignment)".into()),
        "endbr64" | "endbr32" => (Nop, "CET: marks a valid indirect-branch target".into()),
        "int3" => (System, "breakpoint trap".into()),
        "ud2" => (System, "deliberately invalid instruction (crash / unreachable)".into()),
        "hlt" => (System, "halt the CPU until next interrupt".into()),
        "syscall" => (System, "system call: number in rax, args in rdi, rsi, rdx, r10, r8, r9".into()),
        "sysenter" => (System, "fast system call (32-bit)".into()),
        "int" => (System, format!("software interrupt {a}{}", if a == "0x80" { " (Linux 32-bit syscall)" } else { "" })),
        "cpuid" => (System, "query CPU features (eax selects leaf)".into()),
        "rdtsc" => (System, "edx:eax = CPU timestamp counter".into()),
        "pause" => (Nop, "spin-loop hint".into()),
        "mfence" | "lfence" | "sfence" => (System, "memory barrier".into()),
        "clc" => (Logic, "carry = 0".into()),
        "stc" => (Logic, "carry = 1".into()),
        "cld" => (Logic, "direction flag = 0 (string ops go forward)".into()),
        "movsb" | "movsd" | "movsq" | "movsw" if ops.len() != 2 => (Move, "copy [rsi] to [rdi], advance both".into()),
        "stosb" | "stosd" | "stosq" | "stosw" => (Move, "store accumulator to [rdi], advance rdi".into()),

        // ── SIMD / floating point (common subset)
        "movss" => (Simd, format!("{a} = {b}  (single float)")),
        "movsd" => (Simd, format!("{a} = {b}  (double float)")),
        "movaps" | "movups" | "movapd" | "movupd" | "movdqa" | "movdqu" | "vmovaps" | "vmovups"
        | "vmovdqa" | "vmovdqu" => (Simd, format!("{a} = {b}  (vector copy)")),
        "movd" | "movq" | "vmovd" | "vmovq" => (Simd, format!("{a} = {b}")),
        "pxor" | "xorps" | "xorpd" | "vpxor" | "vxorps" if a == b => (Simd, format!("{a} = 0  (zero vector register)")),
        "pxor" | "xorps" | "xorpd" => (Simd, format!("{a} ^= {b}  (vector)")),
        "addss" | "addsd" => (Simd, format!("{a} += {b}  (float)")),
        "subss" | "subsd" => (Simd, format!("{a} -= {b}  (float)")),
        "mulss" | "mulsd" => (Simd, format!("{a} *= {b}  (float)")),
        "divss" | "divsd" => (Simd, format!("{a} /= {b}  (float)")),
        "sqrtss" | "sqrtsd" => (Simd, format!("{a} = sqrt({b})")),
        "ucomiss" | "ucomisd" | "comiss" | "comisd" => (Compare, format!("compare floats {a} and {b}")),
        "cvtsi2sd" | "cvtsi2ss" => (Simd, format!("{a} = (float){b}")),
        "cvttsd2si" | "cvttss2si" => (Simd, format!("{a} = (int){b}  (truncate)")),
        "cvtss2sd" => (Simd, format!("{a} = (double){b}")),
        "cvtsd2ss" => (Simd, format!("{a} = (float){b}")),
        "vzeroupper" => (Simd, "clear upper halves of ymm registers (avoid AVX/SSE penalty)".into()),

        _ => (Other, String::new()),
    };
    if r.0 != Other {
        return r;
    }

    // Condition-code families: jcc / setcc / cmovcc.
    if let Some(cc) = m.strip_prefix("cmov").and_then(cond_x86) {
        return (Move, format!("if {cc}: {a} = {b}"));
    }
    if let Some(cc) = m.strip_prefix("set").and_then(cond_x86) {
        return (Compare, format!("{a} = ({cc}) ? 1 : 0"));
    }
    if let Some(cc) = m.strip_prefix('j').and_then(cond_x86) {
        return (Jump, format!("if {cc} goto {}", target(ctx, &raw_a)));
    }

    // Unknown: at least say which family it belongs to.
    let (kind, family) = match m.as_bytes().first() {
        Some(b'f') => (Simd, "x87 floating-point"),
        Some(b'k') => (Simd, "AVX-512 mask register"),
        Some(b'v') => (Simd, "AVX vector"),
        Some(b'p') => (Simd, "SSE packed-integer"),
        _ => (Other, ""),
    };
    if family.is_empty() {
        (Other, String::new())
    } else {
        (kind, format!("{family} instruction `{m}`"))
    }
}

// ───────────────────────────── ARM / AArch64 ─────────────────────────────

fn cond_arm(cc: &str) -> Option<&'static str> {
    Some(match cc {
        "eq" => "equal",
        "ne" => "not equal",
        "gt" => "greater (signed)",
        "ge" => "greater or equal (signed)",
        "lt" => "less (signed)",
        "le" => "less or equal (signed)",
        "hi" => "higher (unsigned >)",
        "hs" | "cs" => "higher or same (unsigned >=)",
        "lo" | "cc" => "lower (unsigned <)",
        "ls" => "lower or same (unsigned <=)",
        "mi" => "negative",
        "pl" => "positive or zero",
        "vs" => "overflow",
        "vc" => "no overflow",
        "al" => "always",
        _ => return None,
    })
}

fn arm(ctx: &Ctx, m: &str, ops: &[String]) -> (Kind, String) {
    use Kind::*;
    let o: Vec<String> = ops.iter().map(|s| s.trim_start_matches('#').to_string()).collect();
    let a = o.first().cloned().unwrap_or_default();
    let b = o.get(1).cloned().unwrap_or_default();
    let c = o.get(2).cloned().unwrap_or_default();
    let mem = |s: &str| s.trim_end_matches('!').to_string();

    let r = match m {
        "mov" | "movz" => (Move, format!("{a} = {b}")),
        "movk" => (Move, format!("insert 16 bits {b} into {a}{}", o.get(2).map(|s| format!(" ({s})")).unwrap_or_default())),
        "movn" => (Move, format!("{a} = ~{b}")),
        "mvn" => (Move, format!("{a} = ~{b}")),
        "adr" => (Move, format!("{a} = address {}", target(ctx, &b))),
        "adrp" => (Move, format!("{a} = 4KiB page address of {}", target(ctx, &b))),
        "ldr" | "ldur" => (Move, format!("{a} = load {}", mem(&b))),
        "ldrb" | "ldurb" => (Move, format!("{a} = load byte {}", mem(&b))),
        "ldrh" | "ldurh" => (Move, format!("{a} = load halfword {}", mem(&b))),
        "ldrsw" => (Move, format!("{a} = load signed word {}", mem(&b))),
        "ldrsb" | "ldrsh" => (Move, format!("{a} = load signed {}", mem(&b))),
        "str" | "stur" => (Move, format!("store {a} to {}", mem(&b))),
        "strb" | "sturb" => (Move, format!("store byte {a} to {}", mem(&b))),
        "strh" | "sturh" => (Move, format!("store halfword {a} to {}", mem(&b))),
        "ldp" => (Stack, format!("{a}, {b} = load pair from {}", mem(&c))),
        "stp" => (Stack, format!("store pair {a}, {b} to {}", mem(&c))),
        "push" => (Stack, format!("push {}", o.join(", "))),
        "pop" => (Stack, format!("pop {}", o.join(", "))),
        "add" => (Arith, format!("{a} = {b} + {c}")),
        "adds" => (Arith, format!("{a} = {b} + {c} (set flags)")),
        "sub" => (Arith, format!("{a} = {b} - {c}")),
        "subs" => (Arith, format!("{a} = {b} - {c} (set flags)")),
        "mul" => (Arith, format!("{a} = {b} * {c}")),
        "madd" => (Arith, format!("{a} = {b} * {c} + {}", o.get(3).cloned().unwrap_or_default())),
        "msub" => (Arith, format!("{a} = {} - {b} * {c}", o.get(3).cloned().unwrap_or_default())),
        "sdiv" => (Arith, format!("{a} = {b} / {c} (signed)")),
        "udiv" => (Arith, format!("{a} = {b} / {c} (unsigned)")),
        "neg" => (Arith, format!("{a} = -{b}")),
        "and" => (Logic, format!("{a} = {b} & {c}")),
        "ands" => (Logic, format!("{a} = {b} & {c} (set flags)")),
        "orr" => (Logic, format!("{a} = {b} | {c}")),
        "eor" => (Logic, format!("{a} = {b} ^ {c}")),
        "lsl" => (Logic, format!("{a} = {b} << {c}")),
        "lsr" => (Logic, format!("{a} = {b} >> {c} (logical)")),
        "asr" => (Logic, format!("{a} = {b} >> {c} (arithmetic)")),
        "sxtw" | "sxth" | "sxtb" => (Move, format!("{a} = sign-extend {b}")),
        "uxtw" | "uxth" | "uxtb" => (Move, format!("{a} = zero-extend {b}")),
        "cmp" => (Compare, format!("compare {a} with {b}  (flags from {a} - {b})")),
        "cmn" => (Compare, format!("compare {a} with -{b}")),
        "tst" => (Compare, format!("flags from {a} & {b}")),
        "cset" => (Compare, format!("{a} = ({}) ? 1 : 0", cond_arm(&b).unwrap_or(&b))),
        "csel" => (Move, format!("{a} = ({}) ? {b} : {c}", cond_arm(o.get(3).map(String::as_str).unwrap_or("")).unwrap_or("cond"))),
        "b" => (Jump, format!("goto {}", target(ctx, &a))),
        "bl" => (Call, format!("call {}", target(ctx, &a))),
        "blr" => (Call, format!("call function pointer in {a}")),
        "br" => (Jump, format!("goto address in {a}")),
        "bx" if a == "lr" => (Return, "return to caller".into()),
        "bx" => (Jump, format!("goto address in {a}")),
        "ret" => (Return, "return to caller (jump to x30/lr)".into()),
        "cbz" => (Jump, format!("if {a} == 0 goto {}", target(ctx, &b))),
        "cbnz" => (Jump, format!("if {a} != 0 goto {}", target(ctx, &b))),
        "tbz" => (Jump, format!("if bit {b} of {a} == 0 goto {}", target(ctx, &c))),
        "tbnz" => (Jump, format!("if bit {b} of {a} != 0 goto {}", target(ctx, &c))),
        "nop" => (Nop, "no operation".into()),
        "paciasp" | "autiasp" | "bti" => (Nop, "pointer-auth / branch-target hardening".into()),
        "svc" => (System, "system call (number in x8 on Linux)".into()),
        "brk" => (System, "breakpoint trap".into()),
        "dmb" | "dsb" | "isb" => (System, "memory / instruction barrier".into()),
        _ => (Other, String::new()),
    };
    if r.0 != Other {
        return r;
    }
    if let Some(cc) = m.strip_prefix("b.").and_then(cond_arm) {
        return (Jump, format!("if {cc} goto {}", target(ctx, &a)));
    }
    // 32-bit ARM conditional branches: beq, bne, ...
    if m.len() == 3
        && let Some(cc) = m.strip_prefix('b').and_then(cond_arm) {
            return (Jump, format!("if {cc} goto {}", target(ctx, &a)));
        }
    (Other, String::new())
}

// ───────────────────────────── RISC-V ─────────────────────────────

fn riscv(ctx: &Ctx, m: &str, o: &[String]) -> (Kind, String) {
    use Kind::*;
    let a = o.first().cloned().unwrap_or_default();
    let b = o.get(1).cloned().unwrap_or_default();
    let c = o.get(2).cloned().unwrap_or_default();
    let m = m.strip_prefix("c.").unwrap_or(m); // compressed forms behave the same
    
    match m {
        "li" => (Move, format!("{a} = {b}")),
        "lui" => (Move, format!("{a} = {b} << 12")),
        "auipc" => (Move, format!("{a} = pc + ({b} << 12)")),
        "mv" => (Move, format!("{a} = {b}")),
        "addi" | "addiw" if b == "sp" || a == "sp" => (Stack, format!("{a} = {b} + {c}")),
        "add" | "addi" | "addw" | "addiw" => (Arith, format!("{a} = {b} + {c}")),
        "sub" | "subw" => (Arith, format!("{a} = {b} - {c}")),
        "mul" | "mulw" => (Arith, format!("{a} = {b} * {c}")),
        "div" | "divw" => (Arith, format!("{a} = {b} / {c} (signed)")),
        "divu" | "divuw" => (Arith, format!("{a} = {b} / {c} (unsigned)")),
        "rem" | "remw" | "remu" | "remuw" => (Arith, format!("{a} = {b} % {c}")),
        "neg" | "negw" => (Arith, format!("{a} = -{b}")),
        "and" | "andi" => (Logic, format!("{a} = {b} & {c}")),
        "or" | "ori" => (Logic, format!("{a} = {b} | {c}")),
        "xor" | "xori" => (Logic, format!("{a} = {b} ^ {c}")),
        "not" => (Logic, format!("{a} = ~{b}")),
        "sll" | "slli" | "sllw" | "slliw" => (Logic, format!("{a} = {b} << {c}")),
        "srl" | "srli" | "srlw" | "srliw" => (Logic, format!("{a} = {b} >> {c} (logical)")),
        "sra" | "srai" | "sraw" | "sraiw" => (Logic, format!("{a} = {b} >> {c} (arithmetic)")),
        "sext.w" => (Move, format!("{a} = sign-extend low 32 bits of {b}")),
        "slt" | "slti" | "sltu" | "sltiu" => (Compare, format!("{a} = ({b} < {c}) ? 1 : 0")),
        "seqz" => (Compare, format!("{a} = ({b} == 0) ? 1 : 0")),
        "snez" => (Compare, format!("{a} = ({b} != 0) ? 1 : 0")),
        "ld" | "lw" | "lh" | "lb" | "lwu" | "lhu" | "lbu" | "ldsp" | "lwsp" => (Move, format!("{a} = load {b}")),
        "sd" | "sw" | "sh" | "sb" | "sdsp" | "swsp" => (Move, format!("store {a} to {b}")),
        "j" => (Jump, format!("goto {}", target(ctx, &a))),
        "jal" if o.len() == 1 => (Call, format!("call {}", target(ctx, &a))),
        "jal" => (Call, format!("{a} = return addr; goto {}", target(ctx, &b))),
        "call" => (Call, format!("call {}", target(ctx, &a))),
        "jr" if a == "ra" => (Return, "return to caller".into()),
        "jr" => (Jump, format!("goto address in {a}")),
        "jalr" => (Call, format!("call function pointer in {}", o.last().cloned().unwrap_or_default())),
        "ret" => (Return, "return to caller (jump to ra)".into()),
        "beq" => (Jump, format!("if {a} == {b} goto {}", target(ctx, &c))),
        "bne" => (Jump, format!("if {a} != {b} goto {}", target(ctx, &c))),
        "blt" | "bltu" => (Jump, format!("if {a} < {b} goto {}", target(ctx, &c))),
        "bge" | "bgeu" => (Jump, format!("if {a} >= {b} goto {}", target(ctx, &c))),
        "bgt" | "bgtu" => (Jump, format!("if {a} > {b} goto {}", target(ctx, &c))),
        "ble" | "bleu" => (Jump, format!("if {a} <= {b} goto {}", target(ctx, &c))),
        "beqz" => (Jump, format!("if {a} == 0 goto {}", target(ctx, &b))),
        "bnez" => (Jump, format!("if {a} != 0 goto {}", target(ctx, &b))),
        "nop" => (Nop, "no operation".into()),
        "ecall" => (System, "system call (number in a7, args in a0-a5)".into()),
        "ebreak" => (System, "breakpoint trap".into()),
        "fence" | "fence.i" => (System, "memory barrier".into()),
        _ => (Other, String::new()),
    }
}
