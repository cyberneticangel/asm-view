//! asm-view: an objdump-style disassembler that annotates every instruction
//! with a plain-language comment, in color.

mod color;
mod explain;
mod source;

use std::collections::{BTreeMap, HashMap};
use std::io::{self, BufWriter, IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use capstone::prelude::*;
use clap::{Parser, ValueEnum};
use object::{Architecture, Object, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind, SymbolKind};

use color::Palette;
use explain::{Ctx, Isa, Kind};

#[derive(Clone, Copy, ValueEnum)]
enum ColorMode {
    Auto,
    Always,
    Never,
}

/// Disassemble a binary like objdump, with a comment explaining every instruction.
#[derive(Parser)]
#[command(version, about)]
struct Args {
    /// ELF, Mach-O, PE or COFF file to disassemble
    file: PathBuf,

    /// Only disassemble this section (repeatable). Default: all executable sections
    #[arg(short = 'j', long = "section")]
    sections: Vec<String>,

    /// Only disassemble this function / symbol (repeatable, substring match with --fuzzy)
    #[arg(short = 'f', long = "function")]
    functions: Vec<String>,

    /// Match --function by substring instead of exact name
    #[arg(long)]
    fuzzy: bool,

    /// Use AT&T syntax for x86 (default: Intel)
    #[arg(long)]
    att: bool,

    /// Hide raw instruction bytes
    #[arg(long)]
    no_bytes: bool,

    /// Interleave source code lines (needs debug info, e.g. built with -g)
    #[arg(short = 'S', long)]
    source: bool,

    /// Show raw mangled symbol names instead of demangling Rust / C++ names
    #[arg(long)]
    no_demangle: bool,

    /// Hide explanatory comments (plain colored disassembly)
    #[arg(long)]
    no_comments: bool,

    /// When to use color
    #[arg(long, value_enum, default_value_t = ColorMode::Auto)]
    color: ColorMode,
}

/// Address -> symbol lookup used for branch targets and function headers.
#[derive(Default)]
pub struct Symbols {
    map: BTreeMap<u64, Sym>,
    demangle: bool,
}

struct Sym {
    /// Name as displayed (demangled unless --no-demangle).
    name: String,
    /// Name exactly as stored in the symbol table.
    raw: String,
    size: u64,
}

impl Sym {
    /// Does a `--function` argument select this symbol?
    fn matches(&self, pat: &str, fuzzy: bool) -> bool {
        if fuzzy {
            return self.name.contains(pat) || self.raw.contains(pat);
        }
        // C++ names demangle with their parameter list, so `ns::f` should
        // match `ns::f(int)` as well.
        let no_params = self.name.split('(').next().unwrap_or("");
        pat == self.name || pat == self.raw || pat == no_params
    }
}

/// Demangle a Rust (legacy or v0) or Itanium C++ symbol name. Anything
/// that isn't mangled is returned unchanged.
fn demangle(raw: &str) -> String {
    // Split off suffixes like `@plt` or `@@GLIBC_2.2.5` so they survive.
    let (base, suffix) = match raw.find('@') {
        Some(i) => raw.split_at(i),
        None => (raw, ""),
    };
    // Rust first: legacy Rust symbols also start with `_ZN`. `{:#}` drops the hash.
    if let Ok(d) = rustc_demangle::try_demangle(base) {
        return format!("{d:#}{suffix}");
    }
    // Mach-O prefixes every symbol with an extra underscore (`__Z...`).
    let cpp = base.strip_prefix('_').filter(|b| b.starts_with("_Z")).unwrap_or(base);
    if cpp.starts_with("_Z")
        && let Some(d) = cpp_demangle::Symbol::new(cpp).ok().and_then(|s| s.demangle().ok())
    {
        return format!("{d}{suffix}");
    }
    raw.to_string()
}

impl Symbols {
    fn insert(&mut self, addr: u64, raw: String, size: u64) {
        if raw.is_empty() || addr == 0 {
            return;
        }
        // Prefer an entry with a known size over one without.
        if matches!(self.map.get(&addr), Some(s) if s.size != 0 && size == 0) {
            return;
        }
        let name = if self.demangle { demangle(&raw) } else { raw.clone() };
        self.map.insert(addr, Sym { name, raw, size });
    }

    /// Render an address as `name` or `name+0x10` if it falls inside a known symbol.
    pub fn describe(&self, addr: u64) -> Option<String> {
        let (&start, Sym { name, size, .. }) = self.map.range(..=addr).next_back()?;
        let off = addr - start;
        if off == 0 {
            Some(format!("<{name}>"))
        } else if off < *size {
            Some(format!("<{name}+0x{off:x}>"))
        } else {
            None
        }
    }

    fn at(&self, addr: u64) -> Option<&str> {
        self.map.get(&addr).map(|s| s.name.as_str())
    }
}

fn collect_symbols(obj: &object::File, demangle: bool) -> Symbols {
    let mut syms = Symbols { demangle, ..Default::default() };
    for s in obj.symbols().chain(obj.dynamic_symbols()) {
        if !matches!(s.kind(), SymbolKind::Text | SymbolKind::Unknown) || s.is_undefined() {
            continue;
        }
        if let Ok(name) = s.name() {
            syms.insert(s.address(), name.to_string(), s.size());
        }
    }

    // Synthesize `name@plt` entries for ELF x86-64 so calls into shared
    // libraries show up as `call <puts@plt>` like objdump does.
    if obj.architecture() == Architecture::X86_64 {
        let dynsyms: HashMap<usize, String> = obj
            .dynamic_symbols()
            .filter_map(|s| Some((s.index().0, s.name().ok()?.to_string())))
            .collect();
        let got = obj.section_by_name(".got.plt").or_else(|| obj.section_by_name(".got"));
        let plt_sec = obj.section_by_name(".plt.sec");
        let plt = obj.section_by_name(".plt");
        if let (Some(got), Some(relocs)) = (got, obj.dynamic_relocations()) {
            let range = got.address()..got.address() + got.size();
            let mut slots: Vec<(u64, String)> = relocs
                .filter(|(off, _)| range.contains(off))
                .filter_map(|(off, r)| match r.target() {
                    RelocationTarget::Symbol(i) => dynsyms.get(&i.0).map(|n| (off, n.clone())),
                    _ => None,
                })
                .collect();
            slots.sort();
            for (i, (_, name)) in slots.into_iter().enumerate() {
                let addr = match (&plt_sec, &plt) {
                    (Some(sec), _) => sec.address() + 16 * i as u64,
                    (None, Some(p)) => p.address() + 16 * (i as u64 + 1),
                    _ => continue,
                };
                syms.insert(addr, format!("{name}@plt"), 16);
            }
        }
    }
    syms
}

fn build_capstone(arch: Architecture, att: bool) -> Result<(Capstone, Isa), String> {
    let cs = match arch {
        Architecture::X86_64 | Architecture::X86_64_X32 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(if att { arch::x86::ArchSyntax::Att } else { arch::x86::ArchSyntax::Intel })
            .build()
            .map(|c| (c, Isa::X86)),
        Architecture::I386 => Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode32)
            .syntax(if att { arch::x86::ArchSyntax::Att } else { arch::x86::ArchSyntax::Intel })
            .build()
            .map(|c| (c, Isa::X86)),
        Architecture::Aarch64 => Capstone::new()
            .arm64()
            .mode(arch::arm64::ArchMode::Arm)
            .build()
            .map(|c| (c, Isa::Arm64)),
        Architecture::Arm => Capstone::new()
            .arm()
            .mode(arch::arm::ArchMode::Arm)
            .build()
            .map(|c| (c, Isa::Arm)),
        Architecture::Riscv64 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV64)
            .extra_mode([arch::riscv::ArchExtraMode::RiscVC].into_iter())
            .build()
            .map(|c| (c, Isa::RiscV)),
        Architecture::Riscv32 => Capstone::new()
            .riscv()
            .mode(arch::riscv::ArchMode::RiscV32)
            .extra_mode([arch::riscv::ArchExtraMode::RiscVC].into_iter())
            .build()
            .map(|c| (c, Isa::RiscV)),
        other => return Err(format!("unsupported architecture: {other:?}")),
    };
    cs.map_err(|e| format!("capstone: {e}"))
}

/// A contiguous byte range to disassemble.
struct Region<'a> {
    addr: u64,
    data: &'a [u8],
}

struct Printer<'a, W: Write> {
    out: W,
    pal: Palette,
    cs: &'a Capstone,
    ctx: Ctx<'a>,
    show_bytes: bool,
    show_comments: bool,
    source: Option<source::SourceMap>,
}

impl<W: Write> Printer<'_, W> {
    fn region(&mut self, r: &Region) -> io::Result<()> {
        let mut off = 0usize;
        while off < r.data.len() {
            let base = r.addr + off as u64;
            let insns = self
                .cs
                .disasm_all(&r.data[off..], base)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let mut consumed = 0usize;
            for insn in insns.iter() {
                self.line(insn.address(), insn.bytes(), insn.mnemonic().unwrap_or("?"), insn.op_str().unwrap_or(""))?;
                consumed += insn.bytes().len();
            }
            off += consumed;
            // Capstone stops at the first undecodable byte; print it and resume.
            if off < r.data.len() {
                let a = r.addr + off as u64;
                self.header_if_symbol(a)?;
                writeln!(
                    self.out,
                    "  {}  {}  {}",
                    self.pal.addr(&format!("{a:>8x}:")),
                    self.pal.bytes(&format!("{:<24}", format!("{:02x}", r.data[off]))),
                    self.pal.bad("(bad)")
                )?;
                off += 1;
            }
        }
        Ok(())
    }

    fn header_if_symbol(&mut self, addr: u64) -> io::Result<()> {
        if let Some(name) = self.ctx.syms.at(addr) {
            writeln!(self.out)?;
            writeln!(self.out, "{}", self.pal.header(&format!("{addr:016x} <{name}>:")))?;
            if let Some(src) = &mut self.source {
                src.reset();
            }
        }
        Ok(())
    }

    fn source_lines(&mut self, addr: u64) -> io::Result<()> {
        let Some(src) = &mut self.source else { return Ok(()) };
        for l in src.lines_for(addr) {
            let s = match l {
                source::SourceLine::File(loc) => self.pal.source_file(&loc),
                source::SourceLine::Text(n, text) => {
                    format!("{} {}", self.pal.addr(&format!("{n:>6} │")), self.pal.source_text(&text))
                }
                source::SourceLine::Missing(file, n) => self.pal.source_file(&format!("{file}:{n}")),
            };
            writeln!(self.out, "{s}")?;
        }
        Ok(())
    }

    fn line(&mut self, addr: u64, bytes: &[u8], mnem: &str, ops: &str) -> io::Result<()> {
        self.header_if_symbol(addr)?;
        self.source_lines(addr)?;
        let (kind, mut comment) = explain::explain(&self.ctx, mnem, ops, addr + bytes.len() as u64);

        let mut s = String::new();
        s.push_str("  ");
        s.push_str(&self.pal.addr(&format!("{addr:>8x}:")));
        s.push_str("  ");
        if self.show_bytes {
            let hex: Vec<String> = bytes.iter().map(|b| format!("{b:02x}")).collect();
            let mut hex = hex.join(" ");
            if hex.len() > 23 {
                hex.truncate(20);
                hex.push_str("...");
            }
            s.push_str(&self.pal.bytes(&format!("{hex:<23}")));
            s.push_str("  ");
        }
        s.push_str(&self.pal.mnemonic(&format!("{mnem:<8}"), kind));
        s.push(' ');

        // Append `<symbol>` after direct branch targets, as objdump does.
        let mut plain_width = ops.chars().count();
        s.push_str(&self.pal.operands(ops));
        // Only direct targets: in `call [rip + 0x40afe]` the number is an offset, not an address.
        if matches!(kind, Kind::Jump | Kind::Call)
            && !ops.contains(['[', '('])
            && let Some(name) = explain::find_hex(ops).and_then(|t| self.ctx.syms.describe(t)) {
                plain_width += 1 + name.chars().count();
                s.push(' ');
                s.push_str(&self.pal.symbol(&name));
            }

        if self.show_comments {
            if comment.is_empty() {
                comment = format!("{mnem} (no description yet)");
            }
            let pad = 40usize.saturating_sub(plain_width).max(1);
            s.push_str(&" ".repeat(pad));
            s.push_str(&self.pal.comment(&format!("; {comment}")));
        }
        writeln!(self.out, "{s}")
    }
}

fn run(args: Args) -> Result<(), String> {
    let data = std::fs::read(&args.file).map_err(|e| format!("{}: {e}", args.file.display()))?;
    let obj = object::File::parse(&*data).map_err(|e| format!("{}: {e}", args.file.display()))?;
    let (cs, isa) = build_capstone(obj.architecture(), args.att)?;
    let syms = collect_symbols(&obj, !args.no_demangle);

    let color = match args.color {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
    };
    let pal = Palette { enabled: color };

    let source = if args.source {
        let map = source::SourceMap::load(&obj);
        if map.is_none() {
            eprintln!("asm-view: warning: no DWARF line info in {} (rebuild with -g); showing assembly only", args.file.display());
        }
        map
    } else {
        None
    };

    let stdout = io::stdout().lock();
    let mut p = Printer {
        out: BufWriter::new(stdout),
        pal,
        cs: &cs,
        ctx: Ctx { isa, att: args.att, syms: &syms },
        show_bytes: !args.no_bytes,
        show_comments: !args.no_comments,
        source,
    };

    let w = |e: io::Error| e.to_string();
    writeln!(
        p.out,
        "{}",
        p.pal.header(&format!("{}:     file format {:?} {:?}", args.file.display(), obj.format(), obj.architecture()))
    )
    .map_err(w)?;

    let mut found_any = false;
    for sec in obj.sections() {
        let name = sec.name().unwrap_or("");
        let wanted = if args.sections.is_empty() {
            sec.kind() == SectionKind::Text
        } else {
            args.sections.iter().any(|s| s == name)
        };
        if !wanted {
            continue;
        }
        let Ok(bytes) = sec.data() else { continue };
        if bytes.is_empty() {
            continue;
        }

        // Narrow to requested functions, if any.
        let regions: Vec<Region> = if args.functions.is_empty() {
            vec![Region { addr: sec.address(), data: bytes }]
        } else {
            let lo = sec.address();
            let hi = lo + bytes.len() as u64;
            syms.map
                .iter()
                .filter(|(a, sym)| {
                    (lo..hi).contains(*a)
                        && args.functions.iter().any(|f| sym.matches(f, args.fuzzy))
                })
                .map(|(&a, Sym { size, .. })| {
                    let start = (a - lo) as usize;
                    let end = if *size == 0 {
                        // Unknown size: run until the next symbol.
                        syms.map.range(a + 1..).next().map(|(&n, _)| (n - lo) as usize).unwrap_or(bytes.len())
                    } else {
                        start + *size as usize
                    }
                    .min(bytes.len());
                    Region { addr: a, data: &bytes[start..end] }
                })
                .collect()
        };
        if regions.is_empty() {
            continue;
        }
        found_any = true;

        writeln!(p.out, "\n{}", p.pal.section(&format!("Disassembly of section {name}:"))).map_err(w)?;
        for r in &regions {
            p.region(r).map_err(w)?;
        }
    }
    p.out.flush().map_err(w)?;

    if !found_any {
        return Err(if args.functions.is_empty() {
            "no matching executable sections found".into()
        } else {
            "no matching functions found (try --fuzzy)".into()
        });
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) if e.contains("Broken pipe") => ExitCode::SUCCESS, // e.g. piping into `head`
        Err(e) => {
            eprintln!("asm-view: {e}");
            ExitCode::FAILURE
        }
    }
}
