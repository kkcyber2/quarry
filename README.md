# quarry

Structural file triage. Reads containers by their bytes, never their extension.

The suspicious case in triage is not a file called `malware.exe`. It is a file called `holiday.jpg` that is really a PE with a writable-and-executable section. quarry detects by magic bytes and parses the real headers, so the extension is irrelevant.

**KK (Conan Sultan Khan)** · [github.com/kkcyber2](https://github.com/kkcyber2) · kkdev9715@gmail.com

## Run it

```bash
python -m quarry scan ./downloads
python -m quarry scan suspicious.jpg --min-severity medium
python -m quarry scan ./samples --json --fail-on
python -m quarry entropy payload.bin
```

No dependencies. Python 3.10+.

```
/tmp/qs/disguised.jpg  [pe, 9244 bytes]
  !!high   wx-section: section '.evil' is writable and executable
  ! medium high-entropy-code: section '.evil' is executable with entropy 7.97 (packed or encrypted)
  · low    overlay: 540 bytes appended after the last section

/tmp/qs/archive.zip  [zip, 235 bytes]
  !!high   zip-slip: entry escapes the archive root: '../../etc/passwd'
  ! medium executable-entry: contains an executable entry: 'install.exe'
```

`--fail-on` exits 1 when anything medium or above is found, so it drops into a CI job or a download gate as-is.

## What is actually checked

**ELF** — header and endianness, `ET_DYN`/PIE, per-segment `PT_LOAD` flags, and the `W|X` combination on a single segment (a genuine hardening failure, not a heuristic). Packer markers, `/bin/sh` references, truncated headers.

**PE** — DOS stub, `e_lfanew`, PE signature, machine and optional-header magic, section table with per-section Shannon entropy. Flags writable-and-executable sections, and separately flags **executable sections above 7.2 bits/byte** — the signature of a packed or encrypted payload. Overlay is measured from the end of the last section, not sampled from the tail.

**PDF** — `/JavaScript`, `/OpenAction`, `/Launch`, `/EmbeddedFile`, `/URI`, and multiple `%%EOF` markers (an incremental update after signing).

**ZIP/OOXML** — zip-slip entries (absolute paths and `..` traversal), executable entries, and `vbaProject.bin` inside a `word/` package.

**OLE** — `_VBA_PROJECT` detection for legacy macro documents.

## The entropy call, and why it is not a verdict

High entropy means packed, encrypted, or compressed — and a legitimate PNG is all three. So entropy is only reported as `high-entropy-code` when the section is **also executable and larger than 4 KB**. There is a test asserting that a high-entropy `.rsrc` section is *not* flagged, because a triage tool that cries wolf on resources is a tool nobody runs.

## Tests

```bash
python -m pytest tests/ -q
# 49 passed
```

Every fixture is a **real container built byte by byte** (`tests/fixtures.py` emits genuine ELF program headers, PE section tables, real zip archives, real PDF structure) — so the parser is exercised against actual layout, not a mock of it. Fixtures deliberately include the negative cases: an `R|X` segment must not flag, a `.text` section must not flag, a macro-free OOXML must not flag.

## Structure

```
quarry/containers.py  magic-byte detection, ELF/PE/PDF/ZIP/OLE parsers, entropy
quarry/cli.py         scan (file or directory), entropy, --json, --fail-on
tests/fixtures.py     real container builders
tests/test_quarry.py  49 tests, positive and negative
```

## Licence

MIT — see [LICENSE](LICENSE).
