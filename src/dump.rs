//! `-s`: dump full section contents in exactly the format of `objdump -s`.
//!
//! Output is deliberately plain (no color) so it can be diffed against objdump.

use std::io::{self, Write};

use object::{Architecture, BinaryFormat, Object, ObjectSection, SectionFlags, SectionKind};

/// The BFD target name objdump prints after "file format".
pub fn bfd_target(obj: &object::File) -> String {
    let le = obj.is_little_endian();
    let arch = obj.architecture();
    let fallback = || format!("{:?}", arch).to_lowercase();
    match obj.format() {
        BinaryFormat::Elf => {
            let bits = if obj.is_64() { 64 } else { 32 };
            let name = match arch {
                Architecture::X86_64 | Architecture::X86_64_X32 => "x86-64".into(),
                Architecture::I386 => "i386".into(),
                Architecture::Aarch64 => format!("{}aarch64", if le { "little" } else { "big" }),
                Architecture::Arm => format!("{}arm", if le { "little" } else { "big" }),
                Architecture::Riscv32 | Architecture::Riscv64 => "littleriscv".into(),
                _ => fallback(),
            };
            format!("elf{bits}-{name}")
        }
        BinaryFormat::Pe | BinaryFormat::Coff => {
            let prefix = if obj.format() == BinaryFormat::Pe { "pei" } else { "pe" };
            let name = match arch {
                Architecture::X86_64 => "x86-64".into(),
                Architecture::I386 => "i386".into(),
                Architecture::Aarch64 => "aarch64-little".into(),
                _ => fallback(),
            };
            format!("{prefix}-{name}")
        }
        BinaryFormat::MachO => {
            let name = match arch {
                Architecture::X86_64 => "x86-64".into(),
                Architecture::I386 => "i386".into(),
                Architecture::Aarch64 => "arm64".into(),
                _ => fallback(),
            };
            format!("mach-o-{name}")
        }
        other => format!("{other:?}").to_lowercase(),
    }
}

/// Does BFD (and so objdump) expose this as a section at all? It consumes
/// non-loaded symbol tables, string tables and relocation sections instead.
/// Loaded ones like `.dynsym` and `.rela.dyn` are still visible.
pub fn bfd_visible(sec: &object::Section) -> bool {
    if sec.kind() != SectionKind::Metadata {
        return true;
    }
    matches!(sec.flags(), SectionFlags::Elf { sh_flags, .. } if sh_flags.contains(object::elf::SHF_ALLOC))
}

fn is_nobits(sec: &object::Section) -> bool {
    matches!(sec.kind(), SectionKind::UninitializedData | SectionKind::UninitializedTls)
}

/// Visible section names, for objdump's "mentioned in a -j option" check.
pub fn visible_names(obj: &object::File) -> Vec<String> {
    obj.sections().filter(bfd_visible).map(|s| section_name(obj, &s)).collect()
}

fn section_name(obj: &object::File, sec: &object::Section) -> String {
    let name = sec.name().unwrap_or("");
    if obj.format() == BinaryFormat::MachO
        && let Ok(Some(seg)) = sec.segment_name()
    {
        return format!("{seg}.{name}");
    }
    name.to_string()
}

/// Number of hex digits objdump uses for addresses in one section: enough
/// for both the start and the end address, and at least 4.
fn addr_width(start: u64, end: u64) -> usize {
    let digits = |v: u64| format!("{v:x}").len();
    digits(start).max(digits(end)).max(4)
}

pub fn run(out: &mut impl Write, obj: &object::File, file: &str, only: &[String]) -> io::Result<bool> {
    write!(out, "\n{file}:     file format {}\n\n", bfd_target(obj))?;
    let mut any = false;
    for sec in obj.sections() {
        let name = section_name(obj, &sec);
        if !only.is_empty() && !only.contains(&name) {
            continue;
        }
        if !bfd_visible(&sec) {
            continue;
        }
        // `.bss`-style sections take no file space. objdump skips them, unless
        // named with -j, in which case it shows them as all zeros.
        let zeros;
        let data: &[u8] = if is_nobits(&sec) {
            if only.is_empty() {
                continue;
            }
            zeros = vec![0u8; sec.size() as usize];
            &zeros
        } else {
            sec.data().unwrap_or_default()
        };
        if data.is_empty() {
            continue;
        }
        any = true;
        writeln!(out, "Contents of section {name}:")?;
        if matches!(sec.flags(), SectionFlags::Elf { sh_flags, .. } if sh_flags.contains(object::elf::SHF_COMPRESSED)) {
            writeln!(out, " NOTE: This section is compressed, but its contents have NOT been expanded for this dump.")?;
        }

        let base = sec.address();
        let width = addr_width(base, base + data.len() as u64);
        for (row, chunk) in data.chunks(16).enumerate() {
            let addr = base + row as u64 * 16;
            // objdump keeps only the low `width` digits of the address.
            let full = format!("{addr:016x}");
            let mut line = format!(" {} ", &full[full.len() - width..]);
            for j in 0..16 {
                match chunk.get(j) {
                    Some(b) => line.push_str(&format!("{b:02x}")),
                    None => line.push_str("  "),
                }
                if j % 4 == 3 {
                    line.push(' ');
                }
            }
            line.push(' ');
            for j in 0..16 {
                line.push(match chunk.get(j) {
                    Some(&b) if (0x20..0x7f).contains(&b) => b as char,
                    Some(_) => '.',
                    None => ' ',
                });
            }
            writeln!(out, "{line}")?;
        }
    }
    Ok(any)
}
