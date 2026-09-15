import { fetchJson } from "./http.js";
import { inScope, normalizeDomain } from "./scope.js";

function uniq(arr) {
  return [...new Set((arr || []).filter(Boolean))];
}

export const SOURCE_CATALOG = [
  { id: "crtsh", phase: "subdomains", free: true, needsKey: false, label: "crt.sh CT logs" },
  { id: "certspotter", phase: "subdomains", free: true, needsKey: false, label: "Cert Spotter" },
  { id: "hackertarget", phase: "subdomains", free: true, needsKey: false, label: "HackerTarget hostsearch" },
  { id: "anubis", phase: "subdomains", free: true, needsKey: false, label: "Anubis DB" },
  { id: "threatminer", phase: "subdomains", free: true, needsKey: false, label: "ThreatMiner" },
  { id: "otx", phase: "osint", free: true, needsKey: false, label: "AlienVault OTX" },
  { id: "wayback", phase: "content", free: true, needsKey: false, label: "Wayback CDX" },
  { id: "urlscan", phase: "osint", free: true, needsKey: false, label: "urlscan.io" },
  { id: "rdap", phase: "osint", free: true, needsKey: false, label: "RDAP / WHOIS" },
  { id: "doh", phase: "dns", free: true, needsKey: false, label: "Cloudflare DoH" },
  { id: "hackertarget_dns", phase: "dns", free: true, needsKey: false, label: "HackerTarget DNS" },
  { id: "pagelinks", phase: "content", free: true, needsKey: false, label: "HackerTarget pagelinks" },
  { id: "securitytrails", phase: "subdomains", free: false, needsKey: "SECURITYTRAILS_API_KEY", label: "SecurityTrails" },
  { id: "github_code", phase: "osint", free: true, needsKey: "GITHUB_TOKEN", label: "GitHub code search" },
  { id: "virustotal", phase: "osint", free: false, needsKey: "VIRUSTOTAL_API_KEY", label: "VirusTotal domain" }
];

export async function runSource(id, domain) {
  const d = normalizeDomain(domain);
  const map = {
    crtsh, certspotter, hackertarget, anubis, threatminer, otx, wayback, urlscan,
    rdap, doh, hackertarget_dns, pagelinks, securitytrails, github_code, virustotal
  };
  if (!map[id]) return { source: id, ok: false, error: "unknown source", data: {} };
  return map[id](d);
}

async function crtsh(domain) {
  const r = await fetchJson(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`);
  const names = [];
  for (const row of r.json || []) {
    const raw = `${row.name_value || ""}\n${row.common_name || ""}`;
    for (const part of raw.split(/[\n,\s]+/)) {
      const n = part.replace(/^\*\./, "").toLowerCase();
      if (inScope(n, domain)) names.push(n);
    }
  }
  return { source: "crtsh", ok: r.ok, error: r.ok ? null : r.text.slice(0, 160), data: { subdomains: uniq(names).slice(0, 2500) } };
}

async function certspotter(domain) {
  const r = await fetchJson(`https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`);
  const names = [];
  for (const row of r.json || []) {
    for (const n of row.dns_names || []) {
      const clean = String(n).replace(/^\*\./, "").toLowerCase();
      if (inScope(clean, domain)) names.push(clean);
    }
  }
  return { source: "certspotter", ok: r.status !== 0, error: r.status >= 400 ? r.text.slice(0, 160) : null, data: { subdomains: uniq(names) } };
}

async function hackertarget(domain) {
  const r = await fetchJson(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`);
  const subdomains = [];
  const records = [];
  if (!r.ok || /error|limit/i.test(r.text)) {
    return { source: "hackertarget", ok: false, error: r.text.slice(0, 160), data: {} };
  }
  for (const line of r.text.split("\n")) {
    const [host, ip] = line.split(",");
    if (host && inScope(host, domain)) {
      subdomains.push(host.toLowerCase());
      if (ip) records.push({ host: host.toLowerCase(), ip: ip.trim() });
    }
  }
  return { source: "hackertarget", ok: true, data: { subdomains: uniq(subdomains), hosts: records } };
}

async function anubis(domain) {
  const r = await fetchJson(`https://jonlu.ca/anubis/subdomains/${encodeURIComponent(domain)}`);
  const list = Array.isArray(r.json) ? r.json : [];
  return { source: "anubis", ok: r.ok, error: r.ok ? null : r.text.slice(0, 160), data: { subdomains: uniq(list.map((x) => String(x).toLowerCase()).filter((n) => inScope(n, domain))) } };
}

async function threatminer(domain) {
  const r = await fetchJson(`https://api.threatminer.org/v2/domain.php?q=${encodeURIComponent(domain)}&rt=5`);
  const list = r.json?.results || [];
  return { source: "threatminer", ok: r.ok, data: { subdomains: uniq(list.map((x) => String(x).toLowerCase()).filter((n) => inScope(n, domain))) } };
}

async function otx(domain) {
  const r = await fetchJson(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`);
  const pdns = r.json?.passive_dns || [];
  const subdomains = [];
  const hosts = [];
  for (const row of pdns) {
    const host = (row.hostname || "").toLowerCase();
    if (inScope(host, domain)) {
      subdomains.push(host);
      if (row.address) hosts.push({ host, ip: row.address });
    }
  }
  const gen = await fetchJson(`https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/general`);
  return {
    source: "otx",
    ok: r.ok,
    data: {
      subdomains: uniq(subdomains),
      hosts,
      pulseCount: gen.json?.pulse_info?.count || 0
    }
  };
}

async function wayback(domain) {
  const r = await fetchJson(`https://web.archive.org/cdx/search/cdx?url=*.${encodeURIComponent(domain)}/*&output=json&fl=original&collapse=urlkey&limit=250`);
  const rows = Array.isArray(r.json) ? r.json.slice(1) : [];
  const urls = rows.map((x) => x[0]).filter(Boolean);
  const paths = uniq(urls.map((u) => {
    try { return new URL(u).pathname; } catch { return null; }
  })).slice(0, 400);
  const interesting = urls.filter((u) => /admin|api|graphql|swagger|debug|backup|\.git|\.env|token|config|internal|actuator/i.test(u)).slice(0, 100);
  return { source: "wayback", ok: r.ok, data: { urls: urls.slice(0, 250), paths, interesting } };
}

async function urlscan(domain) {
  const headers = {};
  if (process.env.URLSCAN_API_KEY) headers["API-Key"] = process.env.URLSCAN_API_KEY;
  const r = await fetchJson(`https://urlscan.io/api/v1/search/?q=domain:${encodeURIComponent(domain)}&size=50`, { headers });
  const results = r.json?.results || [];
  const subdomains = results.map((x) => x.page?.domain).filter((n) => n && inScope(n, domain));
  return { source: "urlscan", ok: r.ok, error: r.ok ? null : r.text.slice(0, 160), data: { subdomains: uniq(subdomains), scans: results.slice(0, 20).map((x) => ({ url: x.page?.url, ip: x.page?.ip, server: x.page?.server })) } };
}

async function rdap(domain) {
  const r = await fetchJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`);
  const emails = [];
  const nameservers = (r.json?.nameservers || []).map((n) => n.ldhName || n.ldhname).filter(Boolean);
  const walk = (obj) => {
    if (!obj || typeof obj !== "object") return;
    if (Array.isArray(obj)) return obj.forEach(walk);
    for (const [k, v] of Object.entries(obj)) {
      if (typeof v === "string" && /@/.test(v)) emails.push(v.toLowerCase());
      else walk(v);
    }
  };
  walk(r.json?.entities);
  return { source: "rdap", ok: r.ok, data: { nameservers, emails: uniq(emails), status: r.json?.status || [] } };
}

async function doh(domain) {
  const types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"];
  const records = {};
  for (const type of types) {
    const r = await fetchJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
      headers: { accept: "application/dns-json" }
    });
    records[type] = (r.json?.Answer || []).map((a) => a.data);
  }
  return { source: "doh", ok: true, data: { records } };
}

async function hackertargetDns(domain) {
  const r = await fetchJson(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`);
  if (/error|limit/i.test(r.text)) return { source: "hackertarget_dns", ok: false, error: r.text.slice(0, 160), data: {} };
  return { source: "hackertarget_dns", ok: true, data: { raw: r.text.slice(0, 4000) } };
}

async function pagelinks(domain) {
  const r = await fetchJson(`https://api.hackertarget.com/pagelinks/?q=${encodeURIComponent("https://" + domain)}`);
  if (/error|limit/i.test(r.text)) return { source: "pagelinks", ok: false, error: r.text.slice(0, 160), data: {} };
  const urls = r.text.split("\n").map((x) => x.trim()).filter((u) => /^https?:/i.test(u)).slice(0, 200);
  return { source: "pagelinks", ok: true, data: { urls, interesting: urls.filter((u) => /admin|api|graphql|debug|backup/i.test(u)) } };
}

async function securitytrails(domain) {
  const key = process.env.SECURITYTRAILS_API_KEY;
  if (!key) return { source: "securitytrails", ok: false, skipped: true, error: "no SECURITYTRAILS_API_KEY", data: {} };
  const r = await fetchJson(`https://api.securitytrails.com/v1/domain/${encodeURIComponent(domain)}/subdomains`, {
    headers: { APIKEY: key }
  });
  const subs = (r.json?.subdomains || []).map((s) => `${s}.${domain}`);
  return { source: "securitytrails", ok: r.ok, error: r.ok ? null : r.text.slice(0, 160), data: { subdomains: subs.slice(0, 2500) } };
}

async function githubCode(domain) {
  const token = process.env.GITHUB_TOKEN;
  const q = encodeURIComponent(`"${domain}" (password OR api_key OR secret OR token)`);
  const headers = { accept: "application/vnd.github+json" };
  if (token) headers.authorization = `Bearer ${token}`;
  const r = await fetchJson(`https://api.github.com/search/code?q=${q}&per_page=10`, { headers });
  const items = r.json?.items || [];
  return {
    source: "github_code",
    ok: r.status === 200,
    error: r.status === 200 ? null : `GitHub ${r.status}`,
    data: {
      count: r.json?.total_count || 0,
      hits: items.map((i) => ({ repo: i.repository?.full_name, path: i.path, url: i.html_url }))
    }
  };
}

async function virustotal(domain) {
  const key = process.env.VIRUSTOTAL_API_KEY;
  if (!key) return { source: "virustotal", ok: false, skipped: true, error: "no VIRUSTOTAL_API_KEY", data: {} };
  const r = await fetchJson(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
    headers: { "x-apikey": key }
  });
  return { source: "virustotal", ok: r.ok, data: { stats: r.json?.data?.attributes?.last_analysis_stats || {} } };
}
