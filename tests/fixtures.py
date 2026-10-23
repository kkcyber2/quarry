"""Build real container files in memory, byte by byte.

Triage logic can only be tested against real structures. These builders emit
genuine headers with the specific properties under test (a W^X segment, a
packed section, a zip-slip entry), so the tests exercise the parser rather than
a mock of it.
"""
from __future__ import annotations

import io
import struct
import zipfile


def elf64(segment_flags=(0x5,), extra: bytes = b"") -> bytes:
    """A minimal ELF64. ``segment_flags`` becomes one PT_LOAD per entry."""
    e_ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    e_type = 3                          # ET_DYN
    e_machine = 0x3E                    # x86-64
    n_ph = len(segment_flags)
    phoff = 64
    ehsize = 64
    phentsize = 56

    header = e_ident + struct.pack(
        "<HHIQQQIHHHHHH",
        e_type, e_machine, 1,
        0,                  # e_entry
        phoff,              # e_phoff
        0,                  # e_shoff
        0,                  # e_flags
        ehsize, phentsize, n_ph, 64, 0, 0,
    )
    body = bytearray()
    for i, flags in enumerate(segment_flags):
        body += struct.pack(
            "<IIQQQQQQ",
            1,              # PT_LOAD
            flags,
            0,              # p_offset
            0,              # p_vaddr
            0,              # p_paddr
            0x100,          # p_filesz
            0x100,          # p_memsz
            0x1000,         # p_align
        )
    return header + bytes(body) + b"\x90" * 200 + extra


def pe32(sections, overlay: bytes = b"", machine: int = 0x14C) -> bytes:
    """A minimal PE32. ``sections`` is a list of (name, chars, body)."""
    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    nsect = len(sections)
    opt_size = 224
    lfanew = 0x40
    pe = bytearray()
    pe += b"PE\x00\x00"
    pe += struct.pack("<HHIIIHH", machine, nsect, 0, 0, 0, opt_size, 0x0102)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x10B)          # PE32 magic
    pe += opt

    sect_table = bytearray()
    bodies = bytearray()
    raw_ptr = 0x40 + len(pe) + nsect * 40
    raw_ptr = (raw_ptr + 0x1FF) & ~0x1FF

    for name, chars, body in sections:
        pad = (len(bodies) + raw_ptr)
        pad = (pad + 0x1FF) & ~0x1FF
        bodies += b"\x00" * (pad - (raw_ptr + len(bodies)))
        off = raw_ptr + len(bodies)
        nm = name.encode()[:8].ljust(8, b"\x00")
        sect_table += nm + struct.pack(
            "<IIIIIIHHI",
            len(body), 0x1000, len(body), off, 0, 0, 0, 0, chars,
        )
        bodies += body

    return bytes(dos) + bytes(pe) + bytes(sect_table) + bytes(bodies) + overlay


def packed_body(n: int = 8192) -> bytes:
    """High-entropy bytes that are deterministic (so entropy is stable)."""
    out = bytearray()
    x = 0x12345678
    for _ in range(n):
        x = (1103515245 * x + 12345) & 0xFFFFFFFF
        out.append((x >> 16) & 0xFF)
    return bytes(out)


def zip_with(entries, name="a.zip") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, data in entries:
            zf.writestr(path, data)
    return buf.getvalue()


def pdf_with(tokens=(), copies: int = 1) -> bytes:
    body = b"%PDF-1.7\n"
    for t in tokens:
        body += b"<< " + t.encode() + b" >>\n"
    body += b"stream\n...\nendstream\n"
    body += b"%%EOF\n" * copies
    return body


def ole_with(vba: bool = False) -> bytes:
    head = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504
    return head + (b"_VBA_PROJECT" if vba else b"WordDocument")
