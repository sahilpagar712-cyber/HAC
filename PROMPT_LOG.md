# RedactZero — Prompt Log & Architectural Decisions

## Hackathon Submission Metadata
- **Application:** RedactZero — Client-Side PII Data Sanitization & Privacy Compliance Workbench
- **Stack:** React 18, Vite, Tailwind CSS, Lucide React
- **Architecture:** 100% Client-Side / Zero Backend / Zero Network Egress
- **Timestamp:** 2026-11-27

---

## Original Prompt Summary
Build a complete, production-ready, zero-backend, client-side **PII Data Sanitization & Privacy Compliance Web Application** named **RedactZero** with:
1. Clean multi-file React + Vite + Tailwind CSS + Lucide React structure (`src/engine/luhn.js`, `src/engine/piiDetector.js`, `src/engine/redactor.js`, `src/data/sampleDatasets.js`, `src/components/Navbar.jsx`, `src/components/InputPanel.jsx`, `src/components/AuditBar.jsx`, `src/components/DiffView.jsx`, `src/components/PseudonymDrawer.jsx`, `src/App.jsx`).
2. Deterministic PII detection with exact `[start, end)` offsets and overlap resolution across Emails, International/Regional Phones, IPv4/IPv6 (rejecting software version strings like `v2.4.1.0`), Indian PAN (strict 4th-character entity code validation), Indian Aadhaar (`XXXX XXXX XXXX` and `XXXXXXXXXXXX`, rejecting leading `0` or `1` per UIDAI rules), and Credit Card numbers gated by standalone Luhn Mod-10 checksum validation (`luhnRejectedCount` tracking).
3. Three live-switching redaction modes: **Full Mask** (per-type & uniform `[REDACTED]`), **Partial Mask** (verification context), and **Consistent Pseudonymization** (deterministic in-memory `Map` with collapsible inspector & purge button).
4. Synchronized side-by-side diff viewer with color-coded entity highlights and validation tooltips, local `.txt`/`.csv` `FileReader` drag-and-drop preserving delimiters and output extensions, and zero-PII `audit_report.json` export.

---

## Key Architectural Decisions

### 1. Strict Zero-Network-Egress Guarantee
- **Content Security Policy (`index.html`):** Enforces `connect-src 'none'` and avoids external font/CDN fetches so inspecting the browser DevTools Network tab proves zero outbound requests at runtime.
- **Local File & Export Pipeline:** File ingestion uses the browser's `FileReader` API exclusively; exports use `Blob` + `URL.createObjectURL` and `navigator.clipboard.writeText`.
- **Zero-PII Audit Reports:** `audit_report.json` strictly serializes aggregate counts, active mode, document character/line metrics, and Luhn rejection totals—never raw input or matched PII values.

### 2. Deterministic Detection & False-Positive Gating (`src/engine/piiDetector.js`, `src/engine/luhn.js`)
- **Luhn Gate Before Classification:** All 13–19 digit grouped or contiguous card-like candidates pass through `isValidLuhn()` in `luhn.js`. Failing candidates (e.g., decoy order IDs, tracking numbers, `0000-0000-0000-0000`) are rejected and counted in `luhnRejectedCount` so security analysts see false positives prevented in real time.
- **Aadhaar vs. 16-Digit Decoy Isolation:** Spaced 12-digit Aadhaar patterns use negative lookahead/lookbehind against trailing/leading 4-digit groups (`(?<!\d{4}[ -])` and `(?![ -]\d{4})`), ensuring a Luhn-rejected 16-digit decoy never has its first 12 digits misclassified as an Aadhaar number.
- **IPv4/IPv6 Strictness:** IPv4 enforces `0–255` octets and rejects `v`-prefixed or `version`-prefixed software versions (`v2.4.1.0`). IPv6 validates RFC-4291 hextet structure and `::` compression rules, eliminating false positives on timestamps (`12:34:56`) and MAC addresses (`00:1A:2B:3C:4D:5E`).
- **Overlap Resolution:** Matches are sorted by `start` ascending, span length descending, and category priority descending so string slicing and diff highlighting remain 100% corruption-free.

### 3. Single-Pass Synchronized Diff Segments (`src/engine/redactor.js`, `src/components/DiffView.jsx`)
- Instead of maintaining separate transformation strings and re-tokenizing for the diff view, `redactText()` emits an ordered `segments` array pairing `originalText` and `sanitizedText` per chunk.
- Both diff panes render from the exact same `segments` structure and synchronize scrolling via a `requestAnimationFrame`-guarded scroll lock.

### 4. Deterministic Session Pseudonymization (`src/components/PseudonymDrawer.jsx`)
- Maintains an in-memory `Map` keyed by `${type}::${rawValue}` across mode switches within the active session, guaranteeing that repeated occurrences (e.g., `priya.sharma@novacloud.io` across multiple log lines) consistently resolve to `EMAIL_01`.
- Includes an instant **Purge Session Map** action and a **Hide/Show Raw Values** privacy toggle for live demos.
