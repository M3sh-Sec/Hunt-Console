import React, { useState, useMemo, useCallback, useEffect } from "react";
import { Shield, Plus, X, Copy, Check, ChevronDown, ChevronUp, AlertTriangle, Download, Terminal, ScanSearch, FileText, Radio, Save, FolderOpen, Trash2, FilePlus2, Lock } from "lucide-react";

/* ============================================================================
   DESIGN TOKENS
   Subject: SOC threat-hunting console. Deep midnight-indigo ground (not the
   common near-black), amber as the single "signal detected" accent, cyan as
   quiet secondary/info. Monospace carries every piece of real data (IOC
   values, query text, IDs) — the display face is reserved for UI chrome only,
   so the eye learns to trust monospace = "this is the actual artifact."
   ============================================================================ */

const TOKENS = {
  bg: "#0E1420",
  panel: "#161D2E",
  panelAlt: "#1C2438",
  border: "#28324A",
  borderLight: "#374361",
  text: "#E7EAF2",
  textMuted: "#8A93AC",
  textFaint: "#5B6480",
  accent: "#F2A93B",
  accentDim: "#8A6A2E",
  accent2: "#4FD1C5",
  danger: "#E2574C",
  success: "#59C97C",
};

/* ============================================================================
   DOMAIN DATA — ported from the Python backend's field-mapping tables so the
   GUI produces the same shape of output as the CLI/backends do.
   ============================================================================ */

const IOC_TYPES = [
  { value: "ip", label: "IP address" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "sha256", label: "SHA-256 hash" },
  { value: "sha1", label: "SHA-1 hash" },
  { value: "md5", label: "MD5 hash" },
  { value: "email", label: "Email address" },
];

const ENTITY_TYPE_TO_FIELD = {
  ip: "network.dst_ip",
  domain: "dns.query",
  url: "url.full",
  sha256: "file.hash_sha256",
  sha1: "file.hash_sha1",
  md5: "file.hash_md5",
  email: "email.sender",
};

const MITRE_LOOKUP = {
  "T1071.001": { name: "Application Layer Protocol: Web Protocols", tactic: "Command and Control", desc: "Adversaries communicate using web protocols (HTTP/HTTPS) to blend C2 traffic with normal web traffic." },
  "T1059.001": { name: "Command and Scripting Interpreter: PowerShell", tactic: "Execution", desc: "Adversaries abuse PowerShell for execution, often to run malicious scripts or commands." },
  "T1105": { name: "Ingress Tool Transfer", tactic: "Command and Control", desc: "Adversaries transfer tools or files from an external system onto a compromised host." },
  "T1486": { name: "Data Encrypted for Impact", tactic: "Impact", desc: "Adversaries encrypt data on target systems to interrupt availability, typical of ransomware." },
  "T1027": { name: "Obfuscated Files or Information", tactic: "Defense Evasion", desc: "Adversaries obfuscate content to make it harder to discover or analyze." },
  "T1566.001": { name: "Phishing: Spearphishing Attachment", tactic: "Initial Access", desc: "Adversaries send emails with malicious attachments to gain initial access." },
};

const KQL_FIELD_MAP = {
  "network.dst_ip": { table: "DeviceNetworkEvents", column: "RemoteIP" },
  "dns.query": { table: "DeviceNetworkEvents", column: "RemoteUrl" },
  "url.full": { table: "DeviceNetworkEvents", column: "RemoteUrl" },
  "file.hash_sha256": { table: "DeviceFileEvents", column: "SHA256" },
  "file.hash_sha1": { table: "DeviceFileEvents", column: "SHA1" },
  "file.hash_md5": { table: "DeviceFileEvents", column: "MD5" },
  "email.sender": { table: "SigninLogs", column: "UserPrincipalName" },
};

const KQL_KNOWLEDGE = {
  DeviceNetworkEvents: {
    expected: "Each row is one network connection event. A match means a monitored device made or received a connection matching the indicator(s).",
    dataSource: "Requires Microsoft Defender for Endpoint with device network event collection enabled.",
    fp: "Shared/CDN-hosted IPs or domains can trigger matches unrelated to the intended threat.",
  },
  DeviceFileEvents: {
    expected: "Each row is one file-system event. A match means a file with a matching hash was observed on a monitored device.",
    dataSource: "Requires Microsoft Defender for Endpoint with file event collection enabled.",
    fp: "Hash-based conditions are reliable; filename-based ones are not (not used by this tab).",
  },
  SigninLogs: {
    expected: "Each row is one Azure AD sign-in event. A match means a sign-in occurred involving the specified identity.",
    dataSource: "Requires Azure AD sign-in logs ingested into the Sentinel workspace.",
    fp: "Legitimate travel or shared devices can produce sign-ins that look anomalous by location alone.",
  },
};

const SPL_FIELD_MAP = {
  "network.dst_ip": { index: "network", sourcetype: "stream:tcp", field: "dest_ip" },
  "dns.query": { index: "network", sourcetype: "stream:dns", field: "query" },
  "url.full": { index: "network", sourcetype: "stream:http", field: "url" },
  "file.hash_sha256": { index: "endpoint", sourcetype: "XmlWinEventLog:Sysmon", field: "file_hash_sha256" },
  "file.hash_sha1": { index: "endpoint", sourcetype: "XmlWinEventLog:Sysmon", field: "file_hash_sha1" },
  "file.hash_md5": { index: "endpoint", sourcetype: "XmlWinEventLog:Sysmon", field: "file_hash_md5" },
  "email.sender": { index: "auth", sourcetype: "WinEventLog:Security", field: "user" },
};

const SPL_KNOWLEDGE = {
  "network:stream:tcp": { expected: "Each row is one TCP connection captured by Splunk Stream.", dataSource: "Requires the Splunk Stream app onboarded; field names assume default CIM-style extraction.", fp: "Shared/CDN-hosted IPs can trigger unrelated matches." },
  "network:stream:dns": { expected: "Each row is one DNS query/response record.", dataSource: "Requires Splunk Stream DNS capture onboarded.", fp: "Legitimate CDNs can share infrastructure with malicious domains." },
  "network:stream:http": { expected: "Each row is one HTTP transaction record.", dataSource: "Requires Splunk Stream HTTP capture onboarded.", fp: "Proxies and shared egress IPs can make attribution ambiguous." },
  "endpoint:XmlWinEventLog:Sysmon": { expected: "Each row is one Sysmon event.", dataSource: "Requires Sysmon deployed and forwarded via a Windows TA.", fp: "Review full context before escalating on hash matches alone." },
  "auth:WinEventLog:Security": { expected: "Each row is one Windows Security event log entry.", dataSource: "Requires Windows Security event log forwarding onboarded.", fp: "Service accounts can produce frequent legitimate matches." },
};

const SIGMA_FIELD_MAP = {
  "network.dst_ip": { category: "network_connection", field: "DestinationIp" },
  "dns.query": { category: "dns_query", field: "query" },
  "url.full": { category: "proxy", field: "cs-uri-query" },
  "file.hash_sha256": { category: "file_event", field: "Hashes" },
  "file.hash_sha1": { category: "file_event", field: "Hashes" },
  "file.hash_md5": { category: "file_event", field: "Hashes" },
  "email.sender": { category: "process_creation", field: "User" },
};

const SIGMA_KNOWLEDGE = {
  network_connection: { expected: "Platform-agnostic rule — convert with pySigma before running. A match means a host connected to a matching indicator.", dataSource: "Requires network connection telemetry ingested by your SIEM.", fp: "Shared/CDN-hosted IPs can trigger unrelated matches." },
  dns_query: { expected: "Platform-agnostic rule — convert before running. A match means a host queried a matching domain.", dataSource: "Requires DNS query telemetry ingested by your SIEM.", fp: "Legitimate CDNs can share infrastructure with malicious domains." },
  proxy: { expected: "Platform-agnostic rule — convert before running. A match means a host requested a matching URL.", dataSource: "Requires proxy/web-request telemetry ingested by your SIEM.", fp: "Shared egress IPs can make attribution ambiguous." },
  file_event: { expected: "Platform-agnostic rule — convert before running. A match means a matching file hash was observed.", dataSource: "Requires file event (Sysmon EventID 11 or equivalent) telemetry.", fp: "Hash matches are reliable; verify host context before escalating." },
  process_creation: { expected: "Platform-agnostic rule — convert before running.", dataSource: "Requires process creation telemetry.", fp: "Review full context before escalating." },
};

const TRIAGE_HINTS = {
  high: "If this returns results, prioritize triage this shift. Pivot to related tables/indexes on the same host before escalating.",
  medium: "If this returns results, review during normal triage queue. Correlate with other alerts on the same entity.",
};

/* ============================================================================
   SANITIZATION — mirrors backends/base.py's shared choke point: strip
   characters that could break out of a query-language string literal.
   ============================================================================ */

function sanitizeValue(v) {
  return String(v).replace(/["'`;|<>{}\\]/g, "").replace(/[\n\r]/g, " ");
}

function yamlQuote(v) {
  return '"' + String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n") + '"';
}

/* ============================================================================
   CLIENT-SIDE IOC EXTRACTION — mirrors report_parser/ioc_extraction.py:
   regex matching + defanging, so pasting raw report text works the same way
   the Python report parser's Stage 1 extraction does.
   ============================================================================ */

function defang(text) {
  return text
    .replace(/\[\.\]/g, ".").replace(/\(\.\)/g, ".").replace(/\{\.\}/g, ".")
    .replace(/hxxps:\/\//gi, "https://").replace(/hxxp:\/\//gi, "http://")
    .replace(/\[:\]/g, ":").replace(/\[at\]/gi, "@").replace(/\(at\)/gi, "@");
}

function extractIocsFromText(rawText) {
  const text = defang(rawText);
  const found = [];
  const seen = new Set();

  const push = (type, value) => {
    const key = type + ":" + value.toLowerCase();
    if (seen.has(key)) return;
    seen.add(key);
    found.push({ type, value });
  };

  const urlRe = /https?:\/\/[^\s"'<>)\]]+/gi;
  const urlSpans = [];
  let m;
  while ((m = urlRe.exec(text)) !== null) {
    push("url", m[0]);
    urlSpans.push([m.index, m.index + m[0].length]);
  }

  const insideUrl = (pos) => urlSpans.some(([s, e]) => pos >= s && pos < e);

  const ipRe = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/g;
  while ((m = ipRe.exec(text)) !== null) push("ip", m[0]);

  const domainRe = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|info|io|co|ru|cn|top|xyz|club|online|site|link|icu|cc)\b/gi;
  while ((m = domainRe.exec(text)) !== null) {
    if (!insideUrl(m.index)) push("domain", m[0].toLowerCase().replace(/\.$/, ""));
  }

  const sha256Re = /\b[a-fA-F0-9]{64}\b/g;
  while ((m = sha256Re.exec(text)) !== null) push("sha256", m[0].toLowerCase());
  const sha1Re = /\b[a-fA-F0-9]{40}\b/g;
  while ((m = sha1Re.exec(text)) !== null) push("sha1", m[0].toLowerCase());
  const md5Re = /\b[a-fA-F0-9]{32}\b/g;
  while ((m = md5Re.exec(text)) !== null) push("md5", m[0].toLowerCase());

  const emailRe = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;
  while ((m = emailRe.exec(text)) !== null) push("email", m[0]);

  const ttpRe = /\bT\d{4}(?:\.\d{3})?\b/g;
  const ttps = new Set();
  while ((m = ttpRe.exec(text)) !== null) ttps.add(m[0].toUpperCase());

  return { iocs: found, ttps: Array.from(ttps) };
}

/* ============================================================================
   QUERY RENDERERS — mirror backends/ms_kql.py, backends/splunk_spl.py,
   backends/sigma.py. All GUI-generated conditions are EQUALS (an indicator
   list, not arbitrary boolean logic), which simplifies the port while still
   producing the exact same query shape those backends emit for this case.
   ============================================================================ */

function renderKql(indicators, ttps, name) {
  const byTable = {};
  const unmapped = [];
  for (const ind of indicators) {
    const field = ENTITY_TYPE_TO_FIELD[ind.type];
    const mapping = field ? KQL_FIELD_MAP[field] : null;
    if (!mapping) { unmapped.push(ind); continue; }
    (byTable[mapping.table] ||= { column: mapping.column, values: [] }).values.push(ind.value);
  }
  return Object.entries(byTable).map(([table, { column, values }]) => {
    const clauses = values.map((v) => `${column} == "${sanitizeValue(v)}"`).join(" or ");
    const text = `${table}\n| where TimeGenerated > ago(24h)\n| where (${clauses})`;
    return { key: table, title: table, text, caveats: unmapped.length ? [`${unmapped.length} indicator(s) had no KQL field mapping and were omitted.`] : [] };
  });
}

function renderSpl(indicators, ttps, name) {
  const byKey = {};
  const unmapped = [];
  for (const ind of indicators) {
    const field = ENTITY_TYPE_TO_FIELD[ind.type];
    const mapping = field ? SPL_FIELD_MAP[field] : null;
    if (!mapping) { unmapped.push(ind); continue; }
    const key = `${mapping.index}:${mapping.sourcetype}`;
    (byKey[key] ||= { index: mapping.index, sourcetype: mapping.sourcetype, field: mapping.field, values: [] }).values.push(ind.value);
  }
  return Object.entries(byKey).map(([key, { index, sourcetype, field, values }]) => {
    const clauses = values.map((v) => `${field}=="${sanitizeValue(v)}"`).join(" OR ");
    const text = `search index="${index}" sourcetype="${sourcetype}" earliest="-24h" latest="now"\n| where (${clauses})`;
    return { key, title: key, text, caveats: unmapped.length ? [`${unmapped.length} indicator(s) had no SPL field mapping and were omitted.`] : [] };
  });
}

function renderSigma(indicators, ttps, name) {
  const byCategory = {};
  const unmapped = [];
  for (const ind of indicators) {
    const field = ENTITY_TYPE_TO_FIELD[ind.type];
    const mapping = field ? SIGMA_FIELD_MAP[field] : null;
    if (!mapping) { unmapped.push(ind); continue; }
    (byCategory[mapping.category] ||= { field: mapping.field, values: [] }).values.push(ind.value);
  }
  return Object.entries(byCategory).map(([category, { field, values }]) => {
    const cleanValues = values.map(sanitizeValue);
    const valueYaml = cleanValues.length === 1
      ? " " + yamlQuote(cleanValues[0])
      : "\n" + cleanValues.map((v) => `      - ${yamlQuote(v)}`).join("\n");
    const tags = ttps.map((t) => `attack.${t.toLowerCase()}`);
    const tagsYaml = tags.length ? "\n" + tags.map((t) => `  - ${yamlQuote(t)}`).join("\n") : " []";
    const text =
      `title: ${yamlQuote(name || "Hunt")}\n` +
      `status: "experimental"\n` +
      `logsource:\n  category: ${yamlQuote(category)}\n` +
      `detection:\n  selection1:\n    ${field}:${valueYaml}\n  condition: selection1\n` +
      `tags:${tagsYaml}\n` +
      `level: "medium"\n` +
      `falsepositives:\n  - "Unknown"`;
    return { key: category, title: category, text, caveats: unmapped.length ? [`${unmapped.length} indicator(s) had no Sigma field mapping and were omitted.`] : [] };
  });
}

function buildExplanation(platform, tableKey, ttps, indicatorCount) {
  const knowledgeMap = platform === "kql" ? KQL_KNOWLEDGE : platform === "spl" ? SPL_KNOWLEDGE : SIGMA_KNOWLEDGE;
  const k = knowledgeMap[tableKey] || {};
  const mitreCtx = ttps.map((id) => ({ id, ...(MITRE_LOOKUP[id] || { name: "(not in local ATT&CK reference)", tactic: "unknown", desc: "Verify against the full MITRE ATT&CK bundle." }) }));
  return {
    summary: `Searches ${tableKey} for any of ${indicatorCount} indicator(s) over the last 24 hours.`,
    expected: k.expected || "Each row is a matching event; a returned row means the indicator was observed.",
    dataSource: k.dataSource || "Verify this data source is enabled in your environment.",
    fp: k.fp || "Review matches in context before escalating.",
    triage: TRIAGE_HINTS.medium,
    mitreCtx,
  };
}

/* ============================================================================
   PERSISTENT STORAGE — segregated and contained.

   "Segregated": every call below passes shared=false explicitly (never
   omitted, never true) — hunts are personal to the current user and are
   never visible to any other user of this artifact. This is a deliberate,
   explicit choice at every call site rather than relying on the API's
   default, so a future edit can't silently flip a hunt to shared.

   "Contained": each hunt is its own key (`hunt:<uuid>`), so loading,
   saving, or deleting one hunt can never touch another's data. A single
   small index key (`hunts-index`) tracks id/name/timestamp/counts only —
   never full indicator values — so listing saved hunts doesn't require
   fetching (and doesn't risk partially-corrupting) every hunt's full data.
   Indicator values and query text never leave this key space; nothing here
   is written anywhere outside window.storage.
   ============================================================================ */

const HUNT_KEY_PREFIX = "hunt:";
const HUNT_INDEX_KEY = "hunts-index";

function huntKey(id) {
  return `${HUNT_KEY_PREFIX}${id}`;
}

function buildHuntRecord({ id, name, indicators, ttps }) {
  return {
    id,
    name,
    indicators,
    ttps,
    savedAt: new Date().toISOString(),
  };
}

function buildIndexEntry(record) {
  return {
    id: record.id,
    name: record.name,
    savedAt: record.savedAt,
    indicatorCount: record.indicators.length,
    ttpCount: record.ttps.length,
  };
}

function upsertIndex(index, entry) {
  const withoutExisting = index.filter((e) => e.id !== entry.id);
  return [entry, ...withoutExisting].sort((a, b) => (a.savedAt < b.savedAt ? 1 : -1));
}

function removeFromIndex(index, id) {
  return index.filter((e) => e.id !== id);
}

async function storageListHunts() {
  try {
    const result = await window.storage.get(HUNT_INDEX_KEY, false);
    if (!result || !result.value) return [];
    const parsed = JSON.parse(result.value);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return []; // key doesn't exist yet — no saved hunts, not an error condition
  }
}

async function storageSaveHunt({ id, name, indicators, ttps }) {
  const record = buildHuntRecord({ id, name, indicators, ttps });
  const saveResult = await window.storage.set(huntKey(id), JSON.stringify(record), false);
  if (!saveResult) throw new Error("storage.set returned no result while saving the hunt");

  const currentIndex = await storageListHunts();
  const nextIndex = upsertIndex(currentIndex, buildIndexEntry(record));
  const indexResult = await window.storage.set(HUNT_INDEX_KEY, JSON.stringify(nextIndex), false);
  if (!indexResult) throw new Error("storage.set returned no result while updating the hunt index");

  return record;
}

async function storageLoadHunt(id) {
  const result = await window.storage.get(huntKey(id), false);
  if (!result || !result.value) throw new Error(`hunt ${id} not found in storage`);
  return JSON.parse(result.value);
}

async function storageDeleteHunt(id) {
  await window.storage.delete(huntKey(id), false);
  const currentIndex = await storageListHunts();
  const nextIndex = removeFromIndex(currentIndex, id);
  await window.storage.set(HUNT_INDEX_KEY, JSON.stringify(nextIndex), false);
}

/* ============================================================================
   UI PRIMITIVES
   ============================================================================ */

function GlobalStyle() {
  return (
    <style>{`
      @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600&display=swap');
      .hc-root * { box-sizing: border-box; }
      .hc-root { font-family: 'Inter', sans-serif; color: ${TOKENS.text}; }
      .hc-display { font-family: 'Space Grotesk', sans-serif; }
      .hc-mono { font-family: 'IBM Plex Mono', monospace; }
      .hc-scroll::-webkit-scrollbar { height: 6px; width: 6px; }
      .hc-scroll::-webkit-scrollbar-thumb { background: ${TOKENS.borderLight}; border-radius: 3px; }
      @keyframes hc-pulse { 0%, 100% { opacity: 0.35; } 50% { opacity: 1; } }
      .hc-pulse-dot { animation: hc-pulse 2.2s ease-in-out infinite; }
      .hc-btn { transition: background-color .15s ease, border-color .15s ease, color .15s ease, transform .1s ease; }
      .hc-btn:active { transform: scale(0.98); }
      .hc-fade-in { animation: hc-fadein .25s ease both; }
      @keyframes hc-fadein { from { opacity: 0; transform: translateY(4px);} to { opacity: 1; transform: translateY(0);} }
    `}</style>
  );
}

function SignalTrace() {
  // Signature element: a thin "signal trace" strip evoking a packet/waveform
  // capture — ties the visual identity directly to the tool's subject matter.
  return (
    <svg width="100%" height="20" viewBox="0 0 800 20" preserveAspectRatio="none" style={{ display: "block" }}>
      <polyline
        points="0,10 40,10 55,3 70,17 85,10 140,10 155,4 165,16 180,10 260,10 275,2 290,18 305,10 420,10 435,5 448,15 462,10 560,10 575,3 588,17 602,10 800,10"
        fill="none"
        stroke={TOKENS.accent}
        strokeWidth="1.4"
        opacity="0.55"
      />
    </svg>
  );
}

function Badge({ children, tone = "muted" }) {
  const map = {
    muted: { bg: "transparent", border: TOKENS.border, color: TOKENS.textMuted },
    accent: { bg: "rgba(242,169,59,0.12)", border: TOKENS.accentDim, color: TOKENS.accent },
    success: { bg: "rgba(89,201,124,0.12)", border: "#2E6B45", color: TOKENS.success },
    danger: { bg: "rgba(226,87,76,0.12)", border: "#7A3530", color: TOKENS.danger },
    cyan: { bg: "rgba(79,209,197,0.12)", border: "#2E6B67", color: TOKENS.accent2 },
  }[tone];
  return (
    <span
      className="hc-mono"
      style={{
        display: "inline-flex", alignItems: "center", gap: 4, padding: "2px 8px",
        fontSize: 11, borderRadius: 4, border: `1px solid ${map.border}`,
        background: map.bg, color: map.color, letterSpacing: 0.3, whiteSpace: "nowrap",
      }}
    >
      {children}
    </span>
  );
}

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      className="hc-btn"
      onClick={() => {
        navigator.clipboard?.writeText(text).catch(() => {});
        setCopied(true);
        setTimeout(() => setCopied(false), 1500);
      }}
      style={{
        display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", fontSize: 12,
        borderRadius: 6, border: `1px solid ${TOKENS.border}`, background: TOKENS.panelAlt,
        color: copied ? TOKENS.success : TOKENS.textMuted, cursor: "pointer",
      }}
    >
      {copied ? <Check size={13} /> : <Copy size={13} />}
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

/* ============================================================================
   MAIN APP
   ============================================================================ */

export default function HuntConsole() {
  const [step, setStep] = useState(1);
  const [huntId, setHuntId] = useState(null);
  const [huntName, setHuntName] = useState("Untitled hunt");
  const [indicators, setIndicators] = useState([]);
  const [ttps, setTtps] = useState([]);
  const [newType, setNewType] = useState("ip");
  const [newValue, setNewValue] = useState("");
  const [newTtp, setNewTtp] = useState("");
  const [pasteText, setPasteText] = useState("");
  const [reviewed, setReviewed] = useState(false);
  const [activeTab, setActiveTab] = useState("kql");
  const [expanded, setExpanded] = useState({});

  const [savedHunts, setSavedHunts] = useState([]);
  const [huntsLoading, setHuntsLoading] = useState(true);
  const [storageBusy, setStorageBusy] = useState(false);
  const [storageStatus, setStorageStatus] = useState(null); // { type: 'success'|'error', message }
  const [lastSavedAt, setLastSavedAt] = useState(null);

  const refreshHuntList = useCallback(async () => {
    setHuntsLoading(true);
    const list = await storageListHunts();
    setSavedHunts(list);
    setHuntsLoading(false);
  }, []);

  useEffect(() => {
    refreshHuntList();
  }, [refreshHuntList]);

  const flashStatus = (type, message) => {
    setStorageStatus({ type, message });
    setTimeout(() => setStorageStatus(null), 3500);
  };

  const saveCurrentHunt = async () => {
    setStorageBusy(true);
    try {
      const id = huntId || crypto.randomUUID();
      const record = await storageSaveHunt({ id, name: huntName || "Untitled hunt", indicators, ttps });
      setHuntId(id);
      setLastSavedAt(record.savedAt);
      await refreshHuntList();
      flashStatus("success", "Hunt saved.");
    } catch (err) {
      flashStatus("error", `Save failed: ${err.message || err}`);
    } finally {
      setStorageBusy(false);
    }
  };

  const loadSavedHunt = async (id) => {
    setStorageBusy(true);
    try {
      const record = await storageLoadHunt(id);
      setHuntId(record.id);
      setHuntName(record.name);
      setIndicators(record.indicators || []);
      setTtps(record.ttps || []);
      setLastSavedAt(record.savedAt);
      setReviewed(false); // loaded data always requires fresh review before generating queries
      setStep(2);
      flashStatus("success", `Loaded "${record.name}".`);
    } catch (err) {
      flashStatus("error", `Load failed: ${err.message || err}`);
    } finally {
      setStorageBusy(false);
    }
  };

  const deleteSavedHunt = async (id, name) => {
    setStorageBusy(true);
    try {
      await storageDeleteHunt(id);
      if (id === huntId) {
        setHuntId(null);
        setLastSavedAt(null);
      }
      await refreshHuntList();
      flashStatus("success", `Deleted "${name}".`);
    } catch (err) {
      flashStatus("error", `Delete failed: ${err.message || err}`);
    } finally {
      setStorageBusy(false);
    }
  };

  const startNewHunt = () => {
    setHuntId(null);
    setHuntName("Untitled hunt");
    setIndicators([]);
    setTtps([]);
    setReviewed(false);
    setLastSavedAt(null);
    setStep(1);
  };

  const addIndicator = useCallback(() => {
    const v = newValue.trim();
    if (!v) return;
    setIndicators((prev) => [...prev, { id: crypto.randomUUID(), type: newType, value: v }]);
    setNewValue("");
  }, [newType, newValue]);

  const removeIndicator = (id) => setIndicators((prev) => prev.filter((i) => i.id !== id));

  const addTtp = useCallback(() => {
    const id = newTtp.trim().toUpperCase();
    if (!/^T\d{4}(\.\d{3})?$/.test(id)) return;
    setTtps((prev) => (prev.includes(id) ? prev : [...prev, id]));
    setNewTtp("");
  }, [newTtp]);

  const removeTtp = (id) => setTtps((prev) => prev.filter((t) => t !== id));

  const runExtraction = () => {
    const { iocs, ttps: foundTtps } = extractIocsFromText(pasteText);
    setIndicators((prev) => {
      const existing = new Set(prev.map((p) => p.type + ":" + p.value.toLowerCase()));
      const additions = iocs
        .filter((i) => !existing.has(i.type + ":" + i.value.toLowerCase()))
        .map((i) => ({ id: crypto.randomUUID(), type: i.type, value: i.value }));
      return [...prev, ...additions];
    });
    setTtps((prev) => Array.from(new Set([...prev, ...foundTtps])));
  };

  const loadExample = () => {
    setHuntName("Operation Example — C2 beacon hunt");
    setPasteText(
      "Threat Report: Operation Example\nThe actor used T1071.001 for command and control, beaconing to " +
      "203.0.113.5 and evil-example.com over HTTPS. A dropped payload had hash " +
      "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3. This activity is also associated with T1105."
    );
  };

  const results = useMemo(() => {
    if (!reviewed || indicators.length === 0) return null;
    return {
      kql: renderKql(indicators, ttps, huntName),
      spl: renderSpl(indicators, ttps, huntName),
      sigma: renderSigma(indicators, ttps, huntName),
    };
  }, [reviewed, indicators, ttps, huntName]);

  const downloadHuntPackage = () => {
    if (!results) return;
    let md = `# Hunt Package: ${huntName}\n\nGenerated: ${new Date().toISOString()}\n\n`;
    md += `## Indicators (${indicators.length})\n\n`;
    indicators.forEach((i) => (md += `- \`${i.type}\`: ${i.value}\n`));
    md += `\n## ATT&CK techniques\n\n`;
    ttps.forEach((t) => (md += `- ${t}: ${MITRE_LOOKUP[t]?.name || "(not in local reference)"}\n`));
    ["kql", "spl", "sigma"].forEach((platform) => {
      md += `\n## ${platform.toUpperCase()}\n`;
      results[platform].forEach((q) => {
        const expl = buildExplanation(platform, q.key, ttps, indicators.length);
        md += `\n### ${q.title}\n\n\`\`\`${platform}\n${q.text}\n\`\`\`\n\n${expl.summary}\n\n**Expected output:** ${expl.expected}\n\n**Data source:** ${expl.dataSource}\n`;
      });
    });
    const blob = new Blob([md], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${huntName.toLowerCase().replace(/[^a-z0-9]+/g, "-")}-hunt-package.md`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const canReview = indicators.length > 0;

  return (
    <div className="hc-root" style={{ background: TOKENS.bg, minHeight: "100vh", padding: "0 0 48px" }}>
      <GlobalStyle />

      {/* Header */}
      <div style={{ borderBottom: `1px solid ${TOKENS.border}`, padding: "22px 28px 0" }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <div style={{ width: 30, height: 30, borderRadius: 7, background: TOKENS.panelAlt, border: `1px solid ${TOKENS.border}`, display: "flex", alignItems: "center", justifyContent: "center" }}>
              <Radio size={16} color={TOKENS.accent} />
            </div>
            <div>
              <div className="hc-display" style={{ fontSize: 17, fontWeight: 600, letterSpacing: 0.2 }}>Hunt Console</div>
              <div className="hc-mono" style={{ fontSize: 11, color: TOKENS.textFaint }}>IOC / TTP → detection query, in-browser</div>
            </div>
          </div>
          <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
            <span className="hc-pulse-dot" style={{ width: 6, height: 6, borderRadius: "50%", background: TOKENS.accent, display: "inline-block" }} />
            <span className="hc-mono" style={{ fontSize: 11, color: TOKENS.textMuted }}>
              {indicators.length} indicator{indicators.length !== 1 ? "s" : ""} · {ttps.length} technique{ttps.length !== 1 ? "s" : ""}
            </span>
            <div style={{ width: 1, height: 16, background: TOKENS.border }} />
            <button
              onClick={saveCurrentHunt}
              disabled={storageBusy || indicators.length === 0}
              className="hc-btn"
              style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, border: `1px solid ${TOKENS.border}`, background: TOKENS.panelAlt, color: indicators.length === 0 ? TOKENS.textFaint : TOKENS.text, fontSize: 11.5, cursor: indicators.length === 0 ? "not-allowed" : "pointer" }}
            >
              <Save size={12} /> {huntId ? "Save" : "Save as new"}
            </button>
            <button onClick={startNewHunt} className="hc-btn" style={{ display: "flex", alignItems: "center", gap: 5, padding: "5px 10px", borderRadius: 6, border: `1px solid ${TOKENS.border}`, background: "none", color: TOKENS.textMuted, fontSize: 11.5, cursor: "pointer" }}>
              <FilePlus2 size={12} /> New
            </button>
          </div>
        </div>
        {storageStatus && (
          <div className="hc-fade-in hc-mono" style={{ marginTop: 10, fontSize: 11.5, color: storageStatus.type === "error" ? TOKENS.danger : TOKENS.success }}>
            {storageStatus.message}
          </div>
        )}
        <div style={{ marginTop: 14 }}><SignalTrace /></div>
      </div>

      <div style={{ maxWidth: 980, margin: "0 auto", padding: "28px 28px 0" }}>
        {/* Step nav */}
        <div style={{ display: "flex", gap: 6, marginBottom: 24 }}>
          {[
            { n: 1, label: "Input" },
            { n: 2, label: "Review" },
            { n: 3, label: "Queries" },
          ].map((s) => (
            <button
              key={s.n}
              className="hc-btn"
              onClick={() => setStep(s.n)}
              disabled={s.n === 3 && !reviewed}
              style={{
                flex: 1, padding: "10px 14px", borderRadius: 8, cursor: s.n === 3 && !reviewed ? "not-allowed" : "pointer",
                border: `1px solid ${step === s.n ? TOKENS.accentDim : TOKENS.border}`,
                background: step === s.n ? "rgba(242,169,59,0.08)" : TOKENS.panel,
                color: step === s.n ? TOKENS.accent : (s.n === 3 && !reviewed ? TOKENS.textFaint : TOKENS.textMuted),
                fontSize: 13, fontWeight: 600, display: "flex", alignItems: "center", justifyContent: "center", gap: 8,
              }}
            >
              <span className="hc-mono" style={{ fontSize: 11, opacity: 0.7 }}>{String(s.n).padStart(2, "0")}</span>
              {s.label}
            </button>
          ))}
        </div>

        {/* STEP 1: INPUT */}
        {step === 1 && (
          <div className="hc-fade-in" style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            <div style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, padding: 18 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <FolderOpen size={15} color={TOKENS.accent2} />
                <span className="hc-display" style={{ fontSize: 13, fontWeight: 600 }}>Saved hunts</span>
                <span title="Personal to you — never shared with other users of this artifact" style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 4 }}>
                  <Lock size={11} color={TOKENS.textFaint} />
                  <span className="hc-mono" style={{ fontSize: 10, color: TOKENS.textFaint }}>private storage</span>
                </span>
              </div>
              {huntsLoading ? (
                <div className="hc-mono" style={{ fontSize: 12, color: TOKENS.textFaint }}>Loading…</div>
              ) : savedHunts.length === 0 ? (
                <div className="hc-mono" style={{ fontSize: 12, color: TOKENS.textFaint }}>No saved hunts yet. Build one below, then click Save.</div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {savedHunts.map((h) => (
                    <div key={h.id} style={{ display: "flex", alignItems: "center", gap: 10, padding: "8px 10px", borderRadius: 6, background: h.id === huntId ? "rgba(242,169,59,0.06)" : TOKENS.panelAlt, border: `1px solid ${h.id === huntId ? TOKENS.accentDim : TOKENS.border}` }}>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{h.name}</div>
                        <div className="hc-mono" style={{ fontSize: 10.5, color: TOKENS.textFaint }}>
                          {h.indicatorCount} indicator{h.indicatorCount !== 1 ? "s" : ""} · {h.ttpCount} TTP{h.ttpCount !== 1 ? "s" : ""} · {new Date(h.savedAt).toLocaleString()}
                        </div>
                      </div>
                      <button onClick={() => loadSavedHunt(h.id)} disabled={storageBusy} className="hc-btn" style={{ padding: "5px 10px", borderRadius: 5, border: `1px solid ${TOKENS.border}`, background: "none", color: TOKENS.accent2, fontSize: 11, cursor: "pointer" }}>Load</button>
                      <button onClick={() => deleteSavedHunt(h.id, h.name)} disabled={storageBusy} className="hc-btn" style={{ padding: 5, borderRadius: 5, border: `1px solid ${TOKENS.border}`, background: "none", color: TOKENS.danger, cursor: "pointer", display: "flex" }}><Trash2 size={12} /></button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <div style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, padding: 18 }}>
              <label className="hc-mono" style={{ fontSize: 11, color: TOKENS.textMuted, display: "block", marginBottom: 6 }}>HUNT NAME</label>
              <input
                value={huntName}
                onChange={(e) => setHuntName(e.target.value)}
                className="hc-display"
                style={{ width: "100%", background: TOKENS.panelAlt, border: `1px solid ${TOKENS.border}`, borderRadius: 6, padding: "10px 12px", color: TOKENS.text, fontSize: 15, fontWeight: 600 }}
              />
            </div>

            <div style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, padding: 18 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <ScanSearch size={15} color={TOKENS.accent2} />
                <span className="hc-display" style={{ fontSize: 13, fontWeight: 600 }}>Paste report text</span>
                <span className="hc-mono" style={{ fontSize: 10, color: TOKENS.textFaint }}>defanged IOCs supported</span>
                <button onClick={loadExample} className="hc-btn hc-mono" style={{ marginLeft: "auto", fontSize: 11, color: TOKENS.accent2, background: "none", border: "none", cursor: "pointer" }}>load example</button>
              </div>
              <textarea
                value={pasteText}
                onChange={(e) => setPasteText(e.target.value)}
                placeholder="Paste threat report text, advisory content, or notes here — IOCs and ATT&CK technique IDs will be extracted automatically."
                className="hc-mono"
                style={{ width: "100%", minHeight: 110, background: TOKENS.panelAlt, border: `1px solid ${TOKENS.border}`, borderRadius: 6, padding: 12, color: TOKENS.text, fontSize: 12.5, resize: "vertical" }}
              />
              <button
                onClick={runExtraction}
                disabled={!pasteText.trim()}
                className="hc-btn"
                style={{ marginTop: 10, padding: "9px 16px", borderRadius: 6, border: `1px solid ${TOKENS.accentDim}`, background: "rgba(242,169,59,0.1)", color: TOKENS.accent, fontSize: 12.5, fontWeight: 600, cursor: pasteText.trim() ? "pointer" : "not-allowed", opacity: pasteText.trim() ? 1 : 0.4 }}
              >
                Extract indicators
              </button>
            </div>

            <div style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, padding: 18 }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
                <Plus size={15} color={TOKENS.accent} />
                <span className="hc-display" style={{ fontSize: 13, fontWeight: 600 }}>Add indicator manually</span>
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <select
                  value={newType}
                  onChange={(e) => setNewType(e.target.value)}
                  className="hc-mono"
                  style={{ background: TOKENS.panelAlt, border: `1px solid ${TOKENS.border}`, borderRadius: 6, padding: "9px 10px", color: TOKENS.text, fontSize: 12.5 }}
                >
                  {IOC_TYPES.map((t) => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
                <input
                  value={newValue}
                  onChange={(e) => setNewValue(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addIndicator()}
                  placeholder="value, e.g. 203.0.113.5"
                  className="hc-mono"
                  style={{ flex: 1, minWidth: 200, background: TOKENS.panelAlt, border: `1px solid ${TOKENS.border}`, borderRadius: 6, padding: "9px 10px", color: TOKENS.text, fontSize: 12.5 }}
                />
                <button onClick={addIndicator} className="hc-btn" style={{ padding: "9px 16px", borderRadius: 6, border: `1px solid ${TOKENS.border}`, background: TOKENS.panelAlt, color: TOKENS.text, fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}>Add</button>
              </div>

              <div style={{ display: "flex", gap: 8, marginTop: 14, flexWrap: "wrap" }}>
                <input
                  value={newTtp}
                  onChange={(e) => setNewTtp(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && addTtp()}
                  placeholder="ATT&CK technique, e.g. T1071.001"
                  className="hc-mono"
                  style={{ flex: 1, minWidth: 200, background: TOKENS.panelAlt, border: `1px solid ${TOKENS.border}`, borderRadius: 6, padding: "9px 10px", color: TOKENS.text, fontSize: 12.5 }}
                />
                <button onClick={addTtp} className="hc-btn" style={{ padding: "9px 16px", borderRadius: 6, border: `1px solid ${TOKENS.border}`, background: TOKENS.panelAlt, color: TOKENS.text, fontSize: 12.5, fontWeight: 600, cursor: "pointer" }}>Add TTP</button>
              </div>

              {(indicators.length > 0 || ttps.length > 0) && (
                <div style={{ marginTop: 16, display: "flex", flexWrap: "wrap", gap: 6 }}>
                  {indicators.map((i) => (
                    <span key={i.id} className="hc-mono" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11.5, padding: "4px 8px", borderRadius: 5, border: `1px solid ${TOKENS.border}`, color: TOKENS.textMuted }}>
                      <span style={{ color: TOKENS.accent2 }}>{i.type}</span>{i.value}
                      <X size={11} style={{ cursor: "pointer" }} onClick={() => removeIndicator(i.id)} />
                    </span>
                  ))}
                  {ttps.map((t) => (
                    <span key={t} className="hc-mono" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: 11.5, padding: "4px 8px", borderRadius: 5, border: `1px solid ${TOKENS.accentDim}`, color: TOKENS.accent }}>
                      {t}
                      <X size={11} style={{ cursor: "pointer" }} onClick={() => removeTtp(t)} />
                    </span>
                  ))}
                </div>
              )}
            </div>

            <button
              onClick={() => setStep(2)}
              disabled={!canReview}
              className="hc-btn"
              style={{ alignSelf: "flex-end", padding: "11px 22px", borderRadius: 8, border: "none", background: canReview ? TOKENS.accent : TOKENS.panelAlt, color: canReview ? "#1A1204" : TOKENS.textFaint, fontSize: 13, fontWeight: 700, cursor: canReview ? "pointer" : "not-allowed" }}
            >
              Continue to review →
            </button>
          </div>
        )}

        {/* STEP 2: REVIEW */}
        {step === 2 && (
          <div className="hc-fade-in" style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            <div style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, overflow: "hidden" }}>
              <div style={{ padding: "14px 18px", borderBottom: `1px solid ${TOKENS.border}`, display: "flex", alignItems: "center", gap: 8 }}>
                <Terminal size={15} color={TOKENS.accent2} />
                <span className="hc-display" style={{ fontSize: 13, fontWeight: 600 }}>IR preview — {indicators.length} indicator(s)</span>
              </div>
              <div className="hc-scroll" style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse" }}>
                  <thead>
                    <tr className="hc-mono" style={{ fontSize: 10.5, color: TOKENS.textFaint, textAlign: "left" }}>
                      <th style={{ padding: "8px 18px" }}>TYPE</th>
                      <th style={{ padding: "8px 18px" }}>VALUE</th>
                      <th style={{ padding: "8px 18px" }}>MAPPED IR FIELD</th>
                      <th style={{ padding: "8px 18px" }}>CONFIDENCE</th>
                      <th style={{ padding: "8px 18px" }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {indicators.map((i) => {
                      const field = ENTITY_TYPE_TO_FIELD[i.type];
                      return (
                        <tr key={i.id} className="hc-mono" style={{ fontSize: 12.5, borderTop: `1px solid ${TOKENS.border}` }}>
                          <td style={{ padding: "9px 18px" }}><Badge tone="cyan">{i.type}</Badge></td>
                          <td style={{ padding: "9px 18px", color: TOKENS.text }}>{i.value}</td>
                          <td style={{ padding: "9px 18px", color: TOKENS.textMuted }}>{field || "—"}</td>
                          <td style={{ padding: "9px 18px" }}>{field ? <Badge tone="success">mapped</Badge> : <Badge tone="danger">unmapped</Badge>}</td>
                          <td style={{ padding: "9px 18px", textAlign: "right" }}>
                            <X size={13} style={{ cursor: "pointer", color: TOKENS.textFaint }} onClick={() => removeIndicator(i.id)} />
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {ttps.length > 0 && (
              <div style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, padding: 18 }}>
                <div className="hc-display" style={{ fontSize: 13, fontWeight: 600, marginBottom: 12 }}>ATT&CK context</div>
                <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
                  {ttps.map((t) => {
                    const info = MITRE_LOOKUP[t];
                    return (
                      <div key={t} style={{ display: "flex", gap: 10, alignItems: "baseline" }}>
                        <span className="hc-mono" style={{ fontSize: 12, color: TOKENS.accent, minWidth: 82 }}>{t}</span>
                        {info ? (
                          <span style={{ fontSize: 12.5, color: TOKENS.textMuted }}><span style={{ color: TOKENS.text }}>{info.name}</span> · {info.tactic}</span>
                        ) : (
                          <span style={{ fontSize: 12.5, color: TOKENS.textFaint }}>not in local ATT&CK reference — verify manually</span>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
            )}

            <div style={{ background: TOKENS.panel, border: `1px solid ${reviewed ? TOKENS.accentDim : TOKENS.border}`, borderRadius: 10, padding: 18, display: "flex", alignItems: "center", gap: 12 }}>
              <input type="checkbox" id="reviewed" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} style={{ width: 16, height: 16, accentColor: TOKENS.accent }} />
              <label htmlFor="reviewed" style={{ fontSize: 13, cursor: "pointer" }}>
                I've reviewed these indicators and confirm they're ready for query generation.
                <div className="hc-mono" style={{ fontSize: 10.5, color: TOKENS.textFaint, marginTop: 2 }}>Nothing is generated from unreviewed input — this matches the review gate enforced in the CLI/backend.</div>
              </label>
            </div>

            <button
              onClick={() => setStep(3)}
              disabled={!reviewed}
              className="hc-btn"
              style={{ alignSelf: "flex-end", padding: "11px 22px", borderRadius: 8, border: "none", background: reviewed ? TOKENS.accent : TOKENS.panelAlt, color: reviewed ? "#1A1204" : TOKENS.textFaint, fontSize: 13, fontWeight: 700, cursor: reviewed ? "pointer" : "not-allowed" }}
            >
              Generate queries →
            </button>
          </div>
        )}

        {/* STEP 3: QUERIES */}
        {step === 3 && results && (
          <div className="hc-fade-in" style={{ display: "flex", flexDirection: "column", gap: 18 }}>
            <div style={{ display: "flex", gap: 6 }}>
              {["kql", "spl", "sigma"].map((tab) => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  className="hc-btn hc-mono"
                  style={{
                    padding: "8px 16px", borderRadius: 6, fontSize: 12, fontWeight: 600, cursor: "pointer",
                    border: `1px solid ${activeTab === tab ? TOKENS.accentDim : TOKENS.border}`,
                    background: activeTab === tab ? "rgba(242,169,59,0.1)" : TOKENS.panel,
                    color: activeTab === tab ? TOKENS.accent : TOKENS.textMuted,
                  }}
                >
                  {tab === "kql" ? "Sentinel / Defender (KQL)" : tab === "spl" ? "Splunk (SPL)" : "Sigma (YAML)"}
                </button>
              ))}
              <button
                onClick={downloadHuntPackage}
                className="hc-btn"
                style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 6, padding: "8px 14px", borderRadius: 6, border: `1px solid ${TOKENS.border}`, background: TOKENS.panelAlt, color: TOKENS.text, fontSize: 12, fontWeight: 600, cursor: "pointer" }}
              >
                <Download size={13} /> Hunt package (.md)
              </button>
            </div>

            {results[activeTab].length === 0 ? (
              <div style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, padding: 24, textAlign: "center", color: TOKENS.textFaint, fontSize: 13 }}>
                <AlertTriangle size={16} style={{ marginBottom: 6 }} />
                <div>No indicators mapped to a known field for this platform.</div>
              </div>
            ) : (
              results[activeTab].map((q) => {
                const expl = buildExplanation(activeTab, q.key, ttps, indicators.length);
                const isOpen = expanded[activeTab + q.key];
                return (
                  <div key={q.key} style={{ background: TOKENS.panel, border: `1px solid ${TOKENS.border}`, borderRadius: 10, overflow: "hidden" }}>
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "10px 14px", borderBottom: `1px solid ${TOKENS.border}`, background: TOKENS.panelAlt }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span style={{ display: "flex", gap: 5 }}>
                          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#E2574C", opacity: 0.5 }} />
                          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#F2A93B", opacity: 0.5 }} />
                          <span style={{ width: 8, height: 8, borderRadius: "50%", background: "#59C97C", opacity: 0.5 }} />
                        </span>
                        <span className="hc-mono" style={{ fontSize: 12, color: TOKENS.textMuted }}>{q.title}</span>
                      </div>
                      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <Badge tone="success">validated</Badge>
                        <CopyButton text={q.text} />
                      </div>
                    </div>
                    <pre className="hc-mono hc-scroll" style={{ margin: 0, padding: 16, fontSize: 12.5, lineHeight: 1.6, color: TOKENS.text, overflowX: "auto", whiteSpace: "pre" }}>{q.text}</pre>
                    {q.caveats.length > 0 && (
                      <div style={{ padding: "0 16px 12px", display: "flex", flexDirection: "column", gap: 4 }}>
                        {q.caveats.map((c, idx) => (
                          <div key={idx} style={{ display: "flex", gap: 6, fontSize: 11.5, color: TOKENS.danger }}>
                            <AlertTriangle size={12} style={{ flexShrink: 0, marginTop: 2 }} />{c}
                          </div>
                        ))}
                      </div>
                    )}
                    <button
                      onClick={() => setExpanded((prev) => ({ ...prev, [activeTab + q.key]: !prev[activeTab + q.key] }))}
                      className="hc-btn"
                      style={{ width: "100%", display: "flex", alignItems: "center", justifyContent: "center", gap: 6, padding: "8px", background: "none", border: "none", borderTop: `1px solid ${TOKENS.border}`, color: TOKENS.textMuted, fontSize: 11.5, cursor: "pointer" }}
                    >
                      {isOpen ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                      {isOpen ? "Hide explanation" : "What does this query do?"}
                    </button>
                    {isOpen && (
                      <div className="hc-fade-in" style={{ padding: 18, borderTop: `1px solid ${TOKENS.border}`, display: "flex", flexDirection: "column", gap: 12, fontSize: 12.5 }}>
                        <div><span style={{ color: TOKENS.accent2, fontWeight: 600 }}>Summary — </span><span style={{ color: TOKENS.textMuted }}>{expl.summary}</span></div>
                        <div><span style={{ color: TOKENS.accent2, fontWeight: 600 }}>Expected output — </span><span style={{ color: TOKENS.textMuted }}>{expl.expected}</span></div>
                        <div><span style={{ color: TOKENS.accent2, fontWeight: 600 }}>Data source requirements — </span><span style={{ color: TOKENS.textMuted }}>{expl.dataSource}</span></div>
                        <div><span style={{ color: TOKENS.accent2, fontWeight: 600 }}>False positive guidance — </span><span style={{ color: TOKENS.textMuted }}>{expl.fp}</span></div>
                        <div><span style={{ color: TOKENS.accent2, fontWeight: 600 }}>Triage hint — </span><span style={{ color: TOKENS.textMuted }}>{expl.triage}</span></div>
                        {expl.mitreCtx.length > 0 && (
                          <div>
                            <span style={{ color: TOKENS.accent2, fontWeight: 600 }}>MITRE ATT&CK — </span>
                            <div style={{ marginTop: 4, display: "flex", flexDirection: "column", gap: 3 }}>
                              {expl.mitreCtx.map((m) => (
                                <div key={m.id} className="hc-mono" style={{ fontSize: 11.5, color: TOKENS.textMuted }}>
                                  <span style={{ color: TOKENS.accent }}>{m.id}</span> {m.name} ({m.tactic})
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {step === 3 && !results && (
          <div style={{ textAlign: "center", padding: 40, color: TOKENS.textFaint, fontSize: 13 }}>
            Complete review first — <button onClick={() => setStep(2)} style={{ background: "none", border: "none", color: TOKENS.accent2, cursor: "pointer" }}>go back</button>
          </div>
        )}
      </div>
    </div>
  );
}
