# asm-view

An objdump-style disassembler for the terminal that adds a plain-language comment to every instruction, with color.

```
$ asm-view ./fib -f main
000000000000119b <main>:
    119b:  85 ff                 test     edi, edi                  ; check whether edi is zero / negative
    119d:  7e 3c                 jle      0x11db <main+0x40>        ; if less or equal (signed) goto <main+0x40> (0x11db)
    119f:  41 54                 push     r12                       ; rsp -= 8; [rsp] = r12  (push onto stack)
    11a3:  44 8d 24 7f           lea      r12d, [rdi + rdi*2]       ; r12d = rdi + rdi*2  (address math, no memory access)
    11ac:  48 8d 2d 51 0e 00 00  lea      rbp, [rip + 0xe51]        ; rbp = 0x2004  (address math, no memory access)
    11c4:  e8 67 fe ff ff        call     0x1030 <printf@plt>       ; call <printf@plt> (0x1030)
    11c9:  83 c3 03              add      ebx, 3                    ; ebx += 3
    11cf:  75 e2                 jne      0x11b3 <main+0x18>        ; if not equal / not zero goto <main+0x18> (0x11b3)
    11da:  c3                    ret                                ; return to caller (pop return address)
```

## Features

- **Comments for every instruction**, written as pseudo-C (`ebx += eax`, `if greater (signed) goto …`) so a listing reads quickly. Common idioms get called out, such as `xor eax, eax` zeroing a register.
- **Color by instruction type**: jumps, calls, returns, moves, arithmetic, logic, compares, stack operations and SIMD each get their own color, and numbers in operands are highlighted.
- **Symbol names everywhere**: jump and call targets are labeled with the function they land in, `rip`-relative addresses are resolved to absolute ones, and calls into shared libraries show up as `name@plt`.
- **Rust and C++ demangling**, so you see `geo::P::area(int) const` instead of `_ZNK3geo1P4areaEi`.
- **Many formats and architectures**: ELF, Mach-O and PE/COFF files; x86, x86-64, ARM, AArch64 and RISC-V.

## Installation

You need a Rust toolchain and a C compiler (`cc` or `clang`), because the [capstone](https://www.capstone-engine.org/) disassembly engine is built from C source.

```sh
git clone https://github.com/cyberneticangel/asm-view
cd asm-view
cargo install --path .
```

## Usage

```
asm-view [OPTIONS] <FILE>
```

| Option | What it does |
| --- | --- |
| `-f, --function <NAME>` | Only show this function. Repeatable. |
| `--fuzzy` | Make `-f` match any part of the name |
| `-j, --section <NAME>` | Only show this section. Repeatable. Default: all executable sections |
| `--att` | Use AT&T syntax on x86 (default: Intel) |
| `--no-bytes` | Hide the raw instruction bytes |
| `--no-comments` | Hide the comments, for plain colored disassembly |
| `--no-demangle` | Show raw mangled symbol names |
| `--color <auto\|always\|never>` | When to use color (default: `auto`) |

### Examples

Disassemble a whole binary, paging through it with color kept:

```sh
asm-view --color always /usr/bin/ls | less -R
```

Look at a single function:

```sh
asm-view ./myprog -f main
```

Several functions at once:

```sh
asm-view ./myprog -f main -f parse_args
```

Find functions when you only remember part of the name. This is handy for Rust, where names include the module path:

```sh
asm-view target/release/myapp -f myapp::main --fuzzy
```

C++ functions can be selected by their full name, their name without parameters, or their mangled name:

```sh
asm-view ./shapes -f 'geo::P::area'
asm-view ./shapes -f 'geo::P::area(int) const'
asm-view ./shapes -f _ZNK3geo1P4areaEi
```

```
0000000000001296 <geo::P::area(int) const>:
    1296:  mov      eax, esi                      ; eax = esi
    1298:  imul     eax, dword ptr [rdi]          ; eax *= [rdi] (signed)
    129b:  ret                                    ; return to caller (pop return address)
```

Use AT&T syntax and hide the bytes for a compact view:

```sh
asm-view ./fib -f fib --att --no-bytes
```

```
0000000000001159 <fib>:
    1163:  movl     %edi, %ebx                    ; ebx = edi
    1165:  cmpl     $1, %edi                      ; compare edi with 1  (flags from edi - 1)
```

Only show certain sections, such as the PLT stubs that calls into shared libraries go through:

```sh
asm-view ./myprog -j .plt -j .plt.sec
```

Plain text for saving or diffing:

```sh
asm-view ./myprog --color never > myprog.asm
```

Color turns off automatically when output isn't a terminal, or when the `NO_COLOR` environment variable is set.

## Limitations

- Comments are most complete for x86-64. ARM and RISC-V cover common instructions but haven't been tested as thoroughly.
- A few less common instructions (some x87 and AVX-512 ones) get only a family label, like "x87 floating-point instruction `fxch`".
- `name@plt` labels are only generated for x86-64 ELF binaries.
- Raw binaries with no file header aren't supported.

## License

[GNU Affero General Public License v3.0](LICENSE)
