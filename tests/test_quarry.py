"""Triage tests against real container bytes."""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from fixtures import (  # noqa: E402
    elf64,
    ole_with,
    packed_body,
    pdf_with,
    pe32,
    zip_with,
)

from quarry.containers import analyse, detect, shannon  # noqa: E402


def kinds(report):
    return {f.kind for f in report.findings}


def sev(report, kind):
    return next((f.severity for f in report.findings if f.kind == kind), None)


# --------------------------------------------------------------------- entropy
class TestEntropy:
    def test_empty_is_zero(self):
        assert shannon(b"") == 0.0

    def test_all_identical_bytes_is_zero(self):
        assert shannon(b"\x00" * 4096) == 0.0

    def test_uniform_distribution_is_eight_bits(self):
        assert shannon(bytes(range(256))) == pytest.approx(8.0, abs=1e-9)

    def test_two_symbols_is_one_bit(self):
        assert shannon(b"ab" * 512) == pytest.approx(1.0, abs=1e-9)

    def test_random_looking_data_is_high(self):
        assert shannon(packed_body(4096)) > 7.0


# ---------------------------------------------------------------------- detect
class TestDetect:
    def test_elf(self):
        assert detect(elf64()) == "elf"

    def test_pe(self):
        assert detect(pe32([(".text", 0x60000020, b"\x90" * 64)])) == "pe"

    def test_pdf(self):
        assert detect(b"%PDF-1.7\n") == "pdf"

    def test_zip(self):
        assert detect(zip_with([("a", "b")])) == "zip"

    def test_ole(self):
        assert detect(ole_with()) == "ole"

    def test_unknown(self):
        assert detect(b"just text") == "unknown"

    def test_extension_is_irrelevant_a_pe_named_jpg_is_still_a_pe(self):
        # The whole point: detection reads magic bytes, never the filename.
        assert detect(pe32([(".text", 0x60000020, b"\x90")])) == "pe"


# ------------------------------------------------------------------------- ELF
class TestElf:
    def test_pie_is_noted_but_not_flagged_high(self):
        r = analyse(elf64())
        assert r.format == "elf"
        assert "pie" in kinds(r)
        assert sev(r, "pie") == "info"

    def test_executable_writable_segment_is_high(self):
        # flags 0x7 = R|W|X
        r = analyse(elf64(segment_flags=(0x7,)))
        assert "wx-segment" in kinds(r)
        assert sev(r, "wx-segment") == "high"

    def test_read_execute_segment_is_clean(self):
        # flags 0x5 = R|X -- every normal binary has this and it must NOT flag
        r = analyse(elf64(segment_flags=(0x5,)))
        assert "wx-segment" not in kinds(r)

    def test_bits_reported(self):
        assert analyse(elf64()).meta["bits"] == 64

    def test_packer_marker_detected(self):
        r = analyse(elf64(extra=b"UPX0" + b"\x00" * 32))
        assert "packed" in kinds(r)

    def test_shell_reference_is_low_not_critical(self):
        r = analyse(elf64(extra=b"/bin/sh"))
        assert sev(r, "shell-string") == "low"

    def test_truncated_header_is_high(self):
        r = analyse(b"\x7fELF\x02\x01")
        assert "truncated" in kinds(r)
        assert sev(r, "truncated") == "high"


# -------------------------------------------------------------------------- PE
class TestPe:
    def test_machine_and_type_reported(self):
        r = analyse(pe32([(".text", 0x60000020, b"\x90" * 64)]))
        assert r.format == "pe"
        assert r.meta["machine"] == "x86"
        assert r.meta["optional_magic"] == "pe32"

    def test_sections_are_listed_with_entropy(self):
        r = analyse(pe32([(".text", 0x60000020, b"\x90" * 2048)]))
        assert [s.name for s in r.sections] == [".text"]
        assert 0 <= r.sections[0].entropy <= 8

    def test_executable_writable_section_is_high(self):
        # 0xE0000020 = CODE | EXECUTE | READ | WRITE
        r = analyse(pe32([(".evil", 0xE0000020, b"\x90" * 512)]))
        assert "wx-section" in kinds(r)
        assert sev(r, "wx-section") == "high"

    def test_normal_code_section_is_clean(self):
        r = analyse(pe32([(".text", 0x60000020, b"\x90" * 512)]))
        assert "wx-section" not in kinds(r)
        assert "high-entropy-code" not in kinds(r)

    def test_high_entropy_executable_section_is_flagged(self):
        r = analyse(pe32([(".text", 0x60000020, packed_body(8192))]))
        assert "high-entropy-code" in kinds(r)
        assert sev(r, "high-entropy-code") == "medium"

    def test_high_entropy_but_non_executable_is_not_flagged(self):
        # A resources section is legitimately high entropy.
        r = analyse(pe32([(".rsrc", 0x40000040, packed_body(8192))]))
        assert "high-entropy-code" not in kinds(r)

    def test_upx_sections_detected(self):
        r = analyse(pe32([(".UPX0", 0xE0000080, b"\x00" * 512)]))
        assert "packed" in kinds(r)

    def test_overlay_detected(self):
        r = analyse(pe32([(".text", 0x60000020, b"\x90" * 512)], overlay=b"PAYLOAD" * 100))
        assert "overlay" in kinds(r)

    def test_no_pe_signature_is_high(self):
        dos = bytearray(0x40)
        dos[0:2] = b"MZ"
        r = analyse(bytes(dos) + b"\x00" * 64)
        assert "no-pe-signature" in kinds(r)
        assert sev(r, "no-pe-signature") == "high"

    def test_tiny_file_is_high(self):
        r = analyse(b"MZ")
        assert "truncated" in kinds(r)


# ------------------------------------------------------------------------- PDF
class TestPdf:
    def test_version_is_reported(self):
        assert analyse(b"%PDF-1.7\n%%EOF\n").meta["version"].startswith("1.7")

    def test_javascript_is_high(self):
        r = analyse(pdf_with(["/JavaScript"]))
        assert sev(r, "pdf-js") == "high"

    def test_open_action_is_high(self):
        assert sev(analyse(pdf_with(["/OpenAction"])), "pdf-auto-action") == "high"

    def test_embedded_file_is_medium(self):
        assert sev(analyse(pdf_with(["/EmbeddedFile"])), "pdf-embedded-file") == "medium"

    def test_clean_pdf_has_no_high_findings(self):
        r = analyse(pdf_with(["/Type /Page"], copies=1))
        assert all(f.severity != "high" for f in r.findings)

    def test_multiple_eof_markers_signals_incremental_update(self):
        r = analyse(pdf_with(["/Type /Page"], copies=3))
        assert r.meta["eof_markers"] == 3
        assert sev(r, "incremental-update") == "medium"

    def test_single_eof_is_not_an_update(self):
        assert "incremental-update" not in kinds(analyse(pdf_with(["/Type /Page"], copies=1)))


# ------------------------------------------------------------------------- ZIP
class TestZip:
    def test_entries_counted(self):
        r = analyse(zip_with([("a.txt", "x"), ("b.txt", "y")]))
        assert r.meta["entries"] == 2

    def test_zip_slip_entry_is_high(self):
        r = analyse(zip_with([("../../etc/passwd", "root:x:0:0")]))
        assert "zip-slip" in kinds(r)
        assert sev(r, "zip-slip") == "high"

    def test_absolute_path_entry_is_high(self):
        r = analyse(zip_with([("/tmp/evil", "x")]))
        assert "zip-slip" in kinds(r)

    def test_normal_relative_paths_are_clean(self):
        r = analyse(zip_with([("src/app/main.py", "print(1)")]))
        assert "zip-slip" not in kinds(r)

    def test_executable_entry_is_medium(self):
        r = analyse(zip_with([("install.exe", "MZ")]))
        assert sev(r, "executable-entry") == "medium"

    def test_ooxml_with_macro_is_high(self):
        r = analyse(
            zip_with([("word/document.xml", "<x/>"), ("word/vbaProject.bin", "VBA")])
        )
        assert sev(r, "office-macro") == "high"

    def test_ooxml_without_macro_is_clean(self):
        r = analyse(zip_with([("word/document.xml", "<x/>")]))
        assert "office-macro" not in kinds(r)

    def test_bad_zip_is_high(self):
        r = analyse(b"PK\x03\x04garbage")
        assert sev(r, "bad-zip") == "high"


# ------------------------------------------------------------------------- OLE
class TestOle:
    def test_macro_is_high(self):
        r = analyse(ole_with(vba=True))
        assert r.format == "ole"
        assert sev(r, "office-macro") == "high"

    def test_plain_ole_is_informational(self):
        r = analyse(ole_with(vba=False))
        assert sev(r, "ole-legacy") == "info"
        assert "office-macro" not in kinds(r)


# ---------------------------------------------------------------------- router
class TestRouter:
    def test_unknown_returns_a_report_not_an_exception(self):
        r = analyse(b"random bytes here")
        assert r.format == "unknown"
        assert "unknown-format" in kinds(r)

    def test_every_report_serialises(self):
        for blob in (
            elf64(),
            pe32([(".text", 0x60000020, b"\x90" * 64)]),
            pdf_with(["/JavaScript"]),
            zip_with([("a", "b")]),
            ole_with(True),
            b"nothing",
        ):
            payload = analyse(blob).as_dict()
            assert set(payload) == {"format", "size", "sections", "findings", "meta"}

    def test_size_is_reported_accurately(self):
        blob = elf64()
        assert analyse(blob).size == len(blob)
