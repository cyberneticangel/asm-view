//! Read-only view of the binary's data sections, used to show the string an
//! address points at (e.g. `lea rdi, [rip + 0xe51]` -> `"%d\n"`).

use object::{Object, ObjectSection, SectionKind};

/// Longest string shown in a comment before it is cut off with `…`.
const MAX_SHOWN: usize = 48;
/// How far to scan for the terminating NUL.
const MAX_SCAN: usize = 4096;

pub struct Memory<'d> {
    /// (start address, contents) of each data section.
    sections: Vec<(u64, &'d [u8])>,
}

impl<'d> Memory<'d> {
    pub fn new(obj: &object::File<'d>) -> Memory<'d> {
        let sections = obj
            .sections()
            .filter(|s| {
                matches!(
                    s.kind(),
                    SectionKind::ReadOnlyString
                        | SectionKind::ReadOnlyData
                        | SectionKind::ReadOnlyDataWithRel
                        | SectionKind::Data
                )
            })
            .filter_map(|s| Some((s.address(), s.data().ok()?)))
            .filter(|(_, d)| !d.is_empty())
            .collect();
        Memory { sections }
    }

    fn bytes_at(&self, addr: u64) -> Option<&'d [u8]> {
        self.sections.iter().find_map(|&(start, data)| {
            let off = addr.checked_sub(start)? as usize;
            (off < data.len()).then(|| &data[off..])
        })
    }

    /// If `addr` points at a printable C string, return it quoted and escaped.
    pub fn string_at(&self, addr: u64) -> Option<String> {
        let bytes = self.bytes_at(addr)?;
        let scan = &bytes[..bytes.len().min(MAX_SCAN)];
        let len = scan.iter().position(|&b| b == 0)?; // must be NUL-terminated
        let s = std::str::from_utf8(&scan[..len]).ok()?;

        // Reject things that are probably not text: too short, or containing
        // control characters other than common whitespace. A single character
        // is too often just a number (0x41 = "A") to be worth showing.
        if s.chars().count() < 2
            || s.chars().any(|c| c.is_control() && !matches!(c, '\n' | '\t' | '\r'))
        {
            return None;
        }

        let mut out = String::from("\"");
        for (i, c) in s.chars().enumerate() {
            if i == MAX_SHOWN {
                out.push('…');
                break;
            }
            match c {
                '\n' => out.push_str("\\n"),
                '\t' => out.push_str("\\t"),
                '\r' => out.push_str("\\r"),
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                c => out.push(c),
            }
        }
        out.push('"');
        Some(out)
    }
}
