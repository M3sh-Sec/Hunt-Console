# Hunt Console

## About this tool

Hunt Console turns threat intelligence into detection queries. Feed it a
PCAP capture, a threat intel report (PDF/DOCX/HTML/text), a list of
IOCs/ATT&CK technique IDs you already have, or a live alert pulled from
Microsoft Sentinel/Defender or CrowdStrike Falcon — it normalizes whatever
you give it into a common internal format, then generates ready-to-run
detection queries in three languages at once:

- **KQL** — for Microsoft Sentinel / Defender Advanced Hunting
- **SPL** — for Splunk
- **Sigma** — a platform-agnostic rule format convertible to most other SIEMs

Every generated query comes with a plain-language explanation (what it
searches, what a match means, what data source it needs, common false
positives, and a suggested next step) and is validated against a known
field schema before it's handed to you. Nothing is generated from
unreviewed input — you always get a chance to check what was extracted
before any query is built.

The tool ships two ways to use it:

- **A command-line tool** (`huntconsole`) — the full pipeline, including
  PCAP parsing, report ingestion, and live alert pulls.
- **A browser-based GUI** ("Hunt Console") — a self-contained interactive
  tool for the manual-entry and paste-a-report workflows, with your saved
  hunts stored privately (segregated per user, never shared).

Both produce the same kind of output: validated KQL/SPL/Sigma queries plus
explanations, ready to paste into your SIEM.

---

## Installing and running the CLI

### Linux / macOS

You need **Python 3.10 or newer**. Check with `python3 --version`.

1. Download `install-linux.sh`.
2. Run it:
   ```bash
   bash install-linux.sh
   ```
   This creates an isolated environment at `~/.huntconsole`, installs the
   tool into it, and symlinks the `huntconsole` command into
   `~/.local/bin`. It needs internet access the first time (to fetch
   ordinary Python build tooling) — if you're on a machine with no
   internet access at all, use `--offline` instead (requires
   `setuptools`/`wheel` already available on the system).
3. If the installer tells you `~/.local/bin` isn't on your `PATH`, add
   the line it prints to your shell profile (`~/.bashrc`, `~/.zshrc`,
   etc.), then open a new terminal.
4. Confirm it worked:
   ```bash
   huntconsole --help
   ```

Optional flags:
- `--prefix DIR` — install somewhere other than `~/.huntconsole`
- `--with-connectors` — also installs the extra packages needed for live
  Sentinel/Defender/CrowdStrike alert pulls (not needed for PCAP, report,
  or manual-entry workflows)
- `--offline` — skip the normal internet-based install step (air-gapped
  machines only)

### Windows

You need **Python 3.10 or newer** installed from
[python.org](https://python.org), with "Add python.exe to PATH" checked
during setup.

1. Download `install-windows.ps1` **and** `install-windows.cmd` — keep
   both files in the same folder.
2. **Double-click `install-windows.cmd`.**
   (Don't double-click the `.ps1` file directly — Windows blocks
   PowerShell scripts from running that way by default. The `.cmd` file
   handles that for you, for this one run only, without changing any
   system-wide settings.)
3. A console window opens and runs the installer. It creates an isolated
   environment at `%USERPROFILE%\.huntconsole` and a launcher at
   `%USERPROFILE%\bin\huntconsole.bat`.
4. If it tells you that folder isn't on your `PATH`, either add it using
   the command it prints, or just call the launcher by its full path
   (also printed at the end) for now.
5. Confirm it worked by opening a new terminal (PowerShell or Command
   Prompt) and running:
   ```
   huntconsole --help
   ```
   or, if `PATH` isn't set up yet:
   ```
   %USERPROFILE%\bin\huntconsole.bat --help
   ```

Optional flags (add after `install-windows.cmd`, e.g.
`install-windows.cmd -WithConnectors`):
- `-Prefix DIR` — install somewhere other than the default
- `-WithConnectors` — installs the extras needed for live alert pulls
- `-Offline` — skip the normal internet-based install step (air-gapped
  machines only, requires `setuptools`/`wheel` already available)

### Using the GUI instead

The browser GUI needs no installation. Open it wherever you were given
access to it (e.g., as a Claude artifact). Nothing to download, nothing to
run locally.

---

## Step-by-step: using the CLI

Every command below writes its output to a folder (`./hunt_output` by
default, override with `--out`) and asks you to confirm before generating
queries — add `--auto-approve` to skip that prompt for scripted use.

### 1. Hunting from IOCs and ATT&CK techniques you already have

```bash
huntconsole manual --json iocs.json --ttp T1071.001,T1105 --target kql,spl,sigma
```

`iocs.json` looks like:
```json
[
  { "type": "ip", "value": "203.0.113.5" },
  { "type": "domain", "value": "evil.example.com" },
  { "type": "sha256", "value": "aaaaaaaa...64 hex chars" }
]
```

You can use `--csv` or `--stix` instead of `--json` (a CSV needs `type`
and `value` columns; `--stix` takes a STIX 2.x bundle JSON file).

1. The tool prints a summary of what it parsed — indicator count, ATT&CK
   context, any warnings about entries it couldn't map.
2. It asks: `Proceed to generate queries from this (unreviewed) IR? [y/N]`
   — type `y` (or pass `--auto-approve` up front to skip this).
3. It writes one query file per platform/table into your output folder,
   plus an `_ir.json` snapshot and a bundled `_hunt_package.md` containing
   every query and its explanation in one document.

### 2. Hunting from a threat intel report

```bash
huntconsole report advisory.pdf --title "Vendor Advisory" --target kql
```

Works with `.pdf`, `.docx`, `.html`, or plain text files, or a URL:
```bash
huntconsole report --url https://vendor.example.com/advisory --target kql,sigma
```

The tool extracts IOCs (IPs, domains, URLs, hashes, CVEs, emails —
including "defanged" ones like `185[.]220[.]101[.]1`) and mentioned ATT&CK
technique IDs automatically, shows you what it found, then follows the
same review-and-generate flow as above.

### 3. Hunting from a packet capture

```bash
huntconsole pcap capture.pcap --target kql --auto-approve
```

Parsing happens in an isolated subprocess with a timeout, so a malformed
or oversized capture can't hang or crash the tool. It extracts destination
IPs, DNS queries, TLS SNI values, and HTTP hosts observed in the capture,
deduplicates them, and follows the same review-and-generate flow.

### 4. Pulling a live alert (optional — requires setup)

Only if you installed with `--with-connectors` / `-WithConnectors` and
have credentials for Sentinel or CrowdStrike:

```bash
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export SENTINEL_WORKSPACE_ID=...
export SENTINEL_SUBSCRIPTION_ID=...
export SENTINEL_RESOURCE_GROUP=...
export SENTINEL_WORKSPACE_NAME=...

huntconsole alert --platform sentinel --alert-id <alert-id> --target kql
```

See `connectors/registry.yaml` in the source for the exact environment
variables and minimum required permissions for each platform.

### 5. Loading the real MITRE ATT&CK reference (optional)

By default, ATT&CK technique context (name, tactic, description) comes
from a small built-in set of common techniques. For full coverage,
download `enterprise-attack.json` from
[github.com/mitre-attack/attack-stix-data](https://github.com/mitre-attack/attack-stix-data)
and load it once:

```bash
huntconsole load-attck-bundle enterprise-attack.json
```

### Reading the output

Each run produces, in your `--out` folder:
- One query file per platform per table/index/category (e.g.
  `..._kql_DeviceNetworkEvents.kql`, `..._sigma_network_connection.yml`)
- `..._ir.json` — the normalized data the queries were built from
- `..._hunt_package.md` — everything bundled into one document: every
  query, its validation status, and its full explanation

---

## Step-by-step: using the GUI

1. **Open the GUI.** You'll land on the **Input** step.
2. **Give the hunt a name** at the top (used for the query title and the
   downloadable hunt package filename).
3. **Add indicators**, either way:
   - Paste report text into the box and click **Extract indicators** — it
     pulls out IPs, domains, URLs, hashes, emails, and ATT&CK technique
     IDs automatically (including defanged IOCs). Click **load example**
     first if you want to see this in action before using your own data.
   - Or add them one at a time under **Add indicator manually** — pick a
     type, type the value, click **Add**. Add ATT&CK technique IDs the
     same way (e.g. `T1071.001`).
4. Click **Continue to review**.
5. **Review step**: check the table — each indicator shows what field
   it mapped to and whether that mapping succeeded. Remove anything that
   doesn't belong with the **×**. If you added ATT&CK technique IDs,
   you'll see their name and tactic here too.
6. **Tick the review checkbox.** This is a deliberate gate — nothing
   generates until you confirm you've looked at the list.
7. Click **Generate queries →**.
8. **Queries step**: switch between the **KQL**, **SPL**, and **Sigma**
   tabs. For each query card:
   - **Copy** to copy the query text
   - **What does this query do?** expands the full explanation (summary,
     expected output, data source requirements, false-positive guidance,
     triage hint, ATT&CK context)
   - Any caveats (e.g. an indicator that didn't map to that platform) are
     shown directly under the query
9. Click **Hunt package (.md)** at any time to download everything —
   every query across every platform plus its explanation — as one
   Markdown file.

### Saving and reloading hunts (GUI only)

- Click **Save** (top right) at any point to store the current hunt.
  First save asks nothing extra — it's saved under its current name.
- Saved hunts appear in the **Saved hunts** panel on the Input step, with
  their indicator/TTP counts and last-saved time. Click **Load** to bring
  one back, or the trash icon to delete it.
- Storage is private to you — it's never visible to anyone else using the
  same GUI.
- Loading a saved hunt always sends you back to the Review step and
  un-checks the review box, even if it was checked when you saved it —
  you're asked to re-confirm the indicators are still what you want to
  hunt for before queries can be generated again.
- Click **New** to clear everything and start a fresh hunt.

---

## Security posture

- **PCAP parsing** runs in an isolated subprocess (`multiprocessing`,
  `spawn` context) with a wall-clock timeout, a memory cap, and a
  packet-count cap — a malformed or hostile capture file cannot hang or
  crash the main process.
- **Report ingestion** (PDF/DOCX/HTML/URL) enforces file-size limits,
  zip-bomb guards on DOCX, and SSRF protections on URL fetches
  (https-only, private/loopback/reserved IP ranges blocked, no
  auto-redirect-following).
- **Every generated query** is validated against a known field schema
  before being written out, and every value interpolated into a query
  passes through a shared sanitizer to prevent injection — verified in
  this project's history against real parsers (PyYAML for Sigma output,
  structural checks for KQL/SPL).
- **No connector can remediate, isolate, contain, or otherwise modify**
  anything on a source platform (Sentinel, Defender, CrowdStrike, etc.) —
  read-only by design, enforced by a test that scans the codebase for
  forbidden method names.
- **Saved GUI hunts are segregated per user** (never shared) and
  contained (deleting or updating one hunt cannot affect another) — see
  `gui/HuntConsole.jsx`'s storage layer.

## A few things worth knowing before you rely on this

- The CLI's core commands (`pcap`, `manual`, `report`,
  `load-attck-bundle`) need no third-party packages — pure Python
  standard library. Only `alert` needs the optional extras.
- PDF text extraction is a lightweight, dependency-free extractor. It
  handles normal text-based PDFs well; scanned/image-only PDFs won't
  extract (no OCR).
- The GUI and the CLI are two separate implementations of the same logic,
  not one calling the other — useful to know if you ever see a subtle
  difference in output between them.
- Live alert pulls (`alert` command) require your own Sentinel/Defender
  or CrowdStrike credentials and have not been tested against a live
  tenant in the environment this tool was built in — review the
  connector code and required permissions in `connectors/registry.yaml`
  before pointing it at production credentials.
