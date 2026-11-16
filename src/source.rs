//! Source line interleaving (like `objdump -S`), driven by DWARF line tables.

use std::collections::HashMap;
use std::rc::Rc;

use gimli::Section;
use object::{Object, ObjectSection};

type Reader = gimli::EndianRcSlice<gimli::RunTimeEndian>;

/// When jumping forward this many lines or fewer within a file, print the
/// skipped lines too (declarations, braces, etc.), like objdump does.
const MAX_GAP: u32 = 8;

pub struct SourceMap {
    ctx: addr2line::Context<Reader>,
    /// Cached file contents; `None` if the file couldn't be read.
    files: HashMap<String, Option<Vec<String>>>,
    /// Location of the previously printed source line.
    last: Option<(String, u32)>,
    /// Highest line printed so far, per file.
    highest: HashMap<String, u32>,
}

/// What to print before an instruction.
pub enum SourceLine {
    /// A new file (or a return to one after a different file): `path:line`.
    File(String),
    /// One line of source text with its line number.
    Text(u32, String),
    /// The source file couldn't be read; show the location only.
    Missing(String, u32),
}

impl SourceMap {
    /// Load DWARF line info from the object. Returns `None` if it has none.
    pub fn load(obj: &object::File) -> Option<SourceMap> {
        let endian = if obj.is_little_endian() {
            gimli::RunTimeEndian::Little
        } else {
            gimli::RunTimeEndian::Big
        };
        let load = |id: gimli::SectionId| -> Result<Reader, gimli::Error> {
            // `uncompressed_data` handles `.zdebug_*` / SHF_COMPRESSED sections.
            let data = obj
                .section_by_name(id.name())
                .and_then(|s| s.uncompressed_data().ok())
                .unwrap_or_default();
            Ok(gimli::EndianRcSlice::new(Rc::from(&*data), endian))
        };
        let dwarf = gimli::Dwarf::load(load).ok()?;
        if dwarf.debug_line.reader().is_empty() {
            return None;
        }
        let ctx = addr2line::Context::from_dwarf(dwarf).ok()?;
        Some(SourceMap {
            ctx,
            files: HashMap::new(),
            last: None,
            highest: HashMap::new(),
        })
    }

    /// Forget the previous location, so the next instruction always prints
    /// its source line. Called at the start of each function.
    pub fn reset(&mut self) {
        self.last = None;
    }

    /// Source lines to show before the instruction at `addr`. Empty if the
    /// instruction belongs to the same line as the previous one.
    pub fn lines_for(&mut self, addr: u64) -> Vec<SourceLine> {
        let Ok(Some(loc)) = self.ctx.find_location(addr) else { return Vec::new() };
        let (Some(file), Some(line)) = (loc.file, loc.line) else { return Vec::new() };
        if line == 0 {
            return Vec::new(); // compiler-generated code with no source line
        }
        let file = file.to_string();
        if self.last.as_ref() == Some(&(file.clone(), line)) {
            return Vec::new();
        }

        let mut out = Vec::new();
        let same_file = self.last.as_ref().is_some_and(|(f, _)| *f == file);
        if !same_file {
            out.push(SourceLine::File(format!("{}:{line}", display_path(&file))));
        }

        let text = self
            .files
            .entry(file.clone())
            .or_insert_with(|| {
                std::fs::read_to_string(&file)
                    .ok()
                    .map(|s| s.lines().map(|l| l.replace('\t', "    ")).collect())
            })
            .as_ref();

        match text {
            None => {
                // Only mention the missing file once per switch into it.
                if same_file {
                    out.push(SourceLine::Missing(display_path(&file), line));
                }
            }
            Some(lines) => {
                let highest = self.highest.get(&file).copied().unwrap_or(0);
                let start = if line > highest && line - highest <= MAX_GAP && highest > 0 {
                    highest + 1
                } else {
                    line
                };
                for n in start..=line {
                    if let Some(t) = lines.get(n as usize - 1) {
                        // Skip blank filler lines, but always show the target line.
                        if n == line || !t.trim().is_empty() {
                            out.push(SourceLine::Text(n, t.clone()));
                        }
                    }
                }
            }
        }

        let h = self.highest.entry(file.clone()).or_insert(0);
        *h = (*h).max(line);
        self.last = Some((file, line));
        out
    }
}

/// Show paths under the current directory relative to it, to keep lines short.
fn display_path(file: &str) -> String {
    std::env::current_dir()
        .ok()
        .and_then(|cwd| std::path::Path::new(file).strip_prefix(cwd).ok().map(|p| p.display().to_string()))
        .unwrap_or_else(|| file.to_string())
}
