"""Container parsing: PE, ELF, ZIP, PDF, OLE — by structure, not by extension.

Triage tools that trust the file extension miss the entire point: a `.jpg` that
is really a PE is the suspicious case. Every detector here reads magic bytes and
the structural headers, and reports what it actually found.
"""
from __future__ import annotations

import math
import struct
from dataclasses import dataclass, field


@dataclass
class Section:
    name: str
    offset: int
    size: int
    entropy: float = 0.0
    characteristics: int = 0


@dataclass
class Finding:
    kind: str
    detail: str
    severity: str = "info"          # info | low | medium | high

    def as_dict(self) -> dict:
        return {"kind": self.kind, "detail": self.detail, "severity": self.severity}


@dataclass
class Report:
    format: str
    size: int
    sections: list[Section] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    meta: dict = field(default_factory=dict)

    def add(self, kind: str, detail: str, severity: str = "info") -> None:
        self.findings.append(Finding(kind, detail, severity))

    def as_dict(self) -> dict:
        return {
            "format": self.format,
            "size": self.size,
            "sections": [
                {"name": s.name, "offset": s.offset, "size": s.size, "entropy": round(s.entropy, 3)}
                for s in self.sections
            ],
            "findings": [f.as_dict() for f in self.findings],
            "meta": self.meta,
        }


def shannon(data: bytes) -> float:
    """Entropy in bits per byte, 0..8.

    Packed or encrypted payloads sit near 8; ordinary code sits around 5-6.5.
    This is a signal, not a verdict -- an embedded PNG is also high-entropy.
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    total = 0.0
    for c in counts:
        if c:
            p = c / n
            total -= p * math.log2(p)
    return total


# ------------------------------------------------------------------------ detect
PE_MAGIC = b"MZ"
ELF_MAGIC = b"\x7fELF"
ZIP_MAGIC = b"PK\x03\x04"
PDF_MAGIC = b"%PDF"
OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"


def detect(data: bytes) -> str:
    if data.startswith(ELF_MAGIC):
        return "elf"
    if data.startswith(PE_MAGIC):
        return "pe"
    if data.startswith(PDF_MAGIC):
        return "pdf"
    if data.startswith(OLE_MAGIC):
        return "ole"
    if data.startswith(ZIP_MAGIC) or data.startswith(b"PK\x05\x06"):
        return "zip"
    return "unknown"


# --------------------------------------------------------------------------- ELF
ET_EXEC, ET_DYN = 2, 3
PT_LOAD = 1


def analyse_elf(data: bytes) -> Report:
    r = Report(format="elf", size=len(data))
    if len(data) < 52:
        r.add("truncated", "shorter than an ELF header", "high")
        return r

    is64 = data[4] == 2
    endian = "<" if data[5] == 1 else ">"
    r.meta["bits"] = 64 if is64 else 32
    r.meta["endian"] = "little" if endian == "<" else "big"

    if is64:
        e_type, = struct.unpack_from(endian + "H", data, 16)
        e_phoff, = struct.unpack_from(endian + "Q", data, 32)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 54)
    else:
        e_type, = struct.unpack_from(endian + "H", data, 16)
        e_phoff, = struct.unpack_from(endian + "I", data, 28)
        e_phentsize, e_phnum = struct.unpack_from(endian + "HH", data, 42)

    r.meta["type"] = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}.get(e_type, str(e_type))

    if e_type == ET_DYN:
        r.add("pie", "position-independent executable (expected for modern binaries)", "info")
    if e_phnum == 0:
        r.add("no-programs", "no program headers: not loadable", "medium")

    # Program headers: look for a writable+executable segment (W^X violation).
    for i in range(min(e_phnum, 64)):
        base = e_phoff + i * e_phentsize
        if base + e_phentsize > len(data):
            r.add("truncated-phdr", f"program header {i} lies beyond EOF", "high")
            break
        if is64:
            p_type, p_flags = struct.unpack_from(endian + "II", data, base)
            p_offset, = struct.unpack_from(endian + "Q", data, base + 8)
        else:
            p_type, p_offset = struct.unpack_from(endian + "II", data, base)
            p_flags, = struct.unpack_from(endian + "I", data, base + 24)
        if p_type == PT_LOAD:
            wx = (p_flags & 0x2) and (p_flags & 0x1)      # W and X both set
            if wx:
                r.add(
                    "wx-segment",
                    f"LOAD segment at offset {p_offset} is both writable and executable",
                    "high",
                )

    # Packed binaries often carry these section names even with symbols stripped.
    for marker in (b".upx", b"UPX0", b"UPX1"):
        if marker in data[:65536]:
            r.add("packed", f"packer marker {marker.decode(errors='replace')} present", "medium")
            break

    if b"/bin/sh" in data:
        r.add("shell-string", "references /bin/sh", "low")
    return r


# ---------------------------------------------------------------------------- PE
def analyse_pe(data: bytes) -> Report:
    r = Report(format="pe", size=len(data))
    if len(data) < 0x40:
        r.add("truncated", "shorter than a DOS header", "high")
        return r

    e_lfanew, = struct.unpack_from("<I", data, 0x3C)
    r.meta["pe_offset"] = e_lfanew
    if e_lfanew + 24 > len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        r.add("no-pe-signature", f"no PE signature at 0x{e_lfanew:x}", "high")
        r.meta["dos_stub_only"] = True
        return r

    machine, nsect = struct.unpack_from("<HH", data, e_lfanew + 4)
    r.meta["machine"] = {
        0x14C: "x86",
        0x8664: "x64",
        0xAA64: "arm64",
    }.get(machine, hex(machine))

    opt_size, = struct.unpack_from("<H", data, e_lfanew + 20)
    characteristics, = struct.unpack_from("<H", data, e_lfanew + 22)
    r.meta["characteristics"] = hex(characteristics)

    opt = e_lfanew + 24
    if opt + 2 <= len(data):
        magic, = struct.unpack_from("<H", data, opt)
        r.meta["optional_magic"] = {0x10B: "pe32", 0x20B: "pe32+"}.get(magic, hex(magic))

    sect = opt + opt_size
    for i in range(min(nsect, 96)):
        base = sect + i * 40
        if base + 40 > len(data):
            r.add("truncated-sections", f"section header {i} lies beyond EOF", "high")
            break
        raw_name = data[base : base + 8].rstrip(b"\0")
        name = raw_name.decode("latin-1", errors="replace")
        vsize, vaddr, rsize, roff = struct.unpack_from("<IIII", data, base + 8)
        chars, = struct.unpack_from("<I", data, base + 36)
        body = data[roff : roff + rsize] if roff < len(data) else b""
        ent = shannon(body)
        r.sections.append(Section(name, roff, rsize, ent, chars))

        # The classic packer/dropper signal: executable section, very high entropy.
        executable = bool(chars & 0x20000000)
        writable = bool(chars & 0x80000000)
        if executable and writable:
            r.add("wx-section", f"section {name!r} is writable and executable", "high")
        if executable and ent > 7.2 and rsize > 4096:
            r.add(
                "high-entropy-code",
                f"section {name!r} is executable with entropy {ent:.2f} (packed or encrypted)",
                "medium",
            )

    low = {s.name.lower() for s in r.sections}
    if ".upx0" in low or ".upx1" in low:
        r.add("packed", "UPX sections present", "medium")
    if b"kernel32.dll" in data.lower() or b"loadlibrarya" in data.lower():
        r.add("loader-imports", "imports dynamic loading primitives", "low")

    # Overlay: anything past the end of the last section's raw data. Counting from
    # the last section (rather than sampling the final kilobyte) is what makes this
    # correct for a small payload appended after a large section.
    if r.sections:
        end = max(s.offset + s.size for s in r.sections)
        extra = data[end:]
        if len(extra) > 64 and extra.strip(b"\0"):
            r.add("overlay", f"{len(extra)} bytes appended after the last section", "low")
    return r


# --------------------------------------------------------------------------- PDF
def analyse_pdf(data: bytes) -> Report:
    r = Report(format="pdf", size=len(data))
    r.meta["version"] = data[5:8].decode("latin-1", errors="replace").strip()
    for token, kind, sev in (
        (b"/JavaScript", "pdf-js", "high"),
        (b"/JS", "pdf-js-short", "medium"),
        (b"/OpenAction", "pdf-auto-action", "high"),
        (b"/Launch", "pdf-launch", "high"),
        (b"/EmbeddedFile", "pdf-embedded-file", "medium"),
        (b"/URI", "pdf-external-uri", "info"),
    ):
        if token in data:
            count = data.count(token)
            r.add(kind, f"contains {token.decode()} ({count} occurrence(s))", sev)

    # An object stream count mismatch is the usual signature of an incremental
    # update that appended content to a signed document.
    if b"%%EOF" in data:
        eofs = data.count(b"%%EOF")
        r.meta["eof_markers"] = eofs
        if eofs > 1:
            r.add("incremental-update", f"{eofs} %%EOF markers: document was edited after creation", "medium")
    return r


# --------------------------------------------------------------------------- ZIP
def analyse_zip(data: bytes) -> Report:
    r = Report(format="zip", size=len(data))
    import io
    import zipfile

    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile as exc:
        r.add("bad-zip", f"not a readable zip: {exc}", "high")
        return r

    names = zf.namelist()
    r.meta["entries"] = len(names)
    r.meta["files"] = names[:40]

    for n in names:
        # Zip-slip: an entry that escapes the extraction root.
        if n.startswith("/") or ".." in n.split("/"):
            r.add("zip-slip", f"entry escapes the archive root: {n!r}", "high")
        if n.lower().endswith((".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".hta")):
            r.add("executable-entry", f"contains an executable entry: {n!r}", "medium")

    # Macro-enabled Office documents.
    if any(n.startswith("word/") for n in names) and any(
        n.lower().endswith("vbaproject.bin") for n in names
    ):
        r.add("office-macro", "OOXML document contains a VBA project", "high")
    return r


# ----------------------------------------------------------------------- router
def analyse(data: bytes) -> Report:
    kind = detect(data)
    if kind == "elf":
        return analyse_elf(data)
    if kind == "pe":
        return analyse_pe(data)
    if kind == "pdf":
        return analyse_pdf(data)
    if kind == "zip":
        return analyse_zip(data)
    if kind == "ole":
        r = Report(format="ole", size=len(data))
        if b"VBA" in data or b"_VBA_PROJECT" in data:
            r.add("office-macro", "OLE document contains a VBA project", "high")
        else:
            r.add("ole-legacy", "legacy OLE container (pre-2007 Office, or MSI)", "info")
        return r
    r = Report(format="unknown", size=len(data))
    r.add("unknown-format", "no known container signature", "info")
    return r
