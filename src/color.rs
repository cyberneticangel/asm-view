//! Minimal ANSI coloring. No external crate needed.

use crate::explain::Kind;

#[derive(Clone, Copy)]
pub struct Palette {
    pub enabled: bool,
}

const RESET: &str = "\x1b[0m";

impl Palette {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    pub fn addr(&self, s: &str) -> String {
        self.paint("2", s)
    }
    pub fn bytes(&self, s: &str) -> String {
        self.paint("90", s)
    }
    pub fn header(&self, s: &str) -> String {
        self.paint("1;97", s)
    }
    pub fn section(&self, s: &str) -> String {
        self.paint("1;4;36", s)
    }
    pub fn symbol(&self, s: &str) -> String {
        self.paint("33", s)
    }
    pub fn comment(&self, s: &str) -> String {
        self.paint("3;32", s)
    }
    pub fn bad(&self, s: &str) -> String {
        self.paint("1;31", s)
    }

    pub fn mnemonic(&self, s: &str, kind: Kind) -> String {
        let code = match kind {
            Kind::Jump => "1;33",
            Kind::Call => "1;35",
            Kind::Return => "1;31",
            Kind::Move => "34",
            Kind::Arith => "32",
            Kind::Logic => "36",
            Kind::Compare => "1;36",
            Kind::Stack => "35",
            Kind::Nop => "2",
            Kind::System => "1;91",
            Kind::Simd => "94",
            Kind::Other => "0",
        };
        self.paint(code, s)
    }

    /// Highlight immediates / numbers inside an operand string.
    pub fn operands(&self, s: &str) -> String {
        if !self.enabled {
            return s.to_string();
        }
        let mut out = String::with_capacity(s.len() * 2);
        let mut tok = String::new();
        let flush = |tok: &mut String, out: &mut String| {
            if tok.is_empty() {
                return;
            }
            let t = tok.trim_start_matches('#').trim_start_matches('$');
            let is_num = t.starts_with("0x")
                || (!t.is_empty() && t.chars().all(|c| c.is_ascii_digit()));
            if is_num {
                out.push_str(&self.paint("93", tok));
            } else {
                out.push_str(tok);
            }
            tok.clear();
        };
        for c in s.chars() {
            if c.is_ascii_alphanumeric() || c == '#' || c == '$' || c == '_' || c == '.' {
                tok.push(c);
            } else {
                flush(&mut tok, &mut out);
                if c == '[' || c == ']' || c == '(' || c == ')' {
                    out.push_str(&self.paint("90", &c.to_string()));
                } else {
                    out.push(c);
                }
            }
        }
        flush(&mut tok, &mut out);
        out
    }
}
