import { fetchJson } from "./http.js";
import { vendorFromCname } from "./takeover.js";

export async function dnsIntel(host) {
  const types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT"];
  const records = {};
  for (const type of types) {
    const r = await fetchJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=${type}`, {
      headers: { accept: "application/dns-json" }
    }, 7000);
    records[type] = (r.json?.Answer || []).map((a) => String(a.data).replace(/\.$/, ""));
  }
  const txt = records.TXT || [];
  const spf = txt.filter((t) => /v=spf1/i.test(t));
  const dmarcR = await fetchJson(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent("_dmarc." + host)}&type=TXT`, {
    headers: { accept: "application/dns-json" }
  }, 7000);
  const dmarc = (dmarcR.json?.Answer || []).map((a) => String(a.data));
  const findings = [];
  if (!spf.length) {
    findings.push(f("medium", "Missing SPF", host, "No v=spf1 TXT on apex. Spoofing surface.", "CWE-290"));
  } else if (spf.some((s) => /\+all|\s\+all/i.test(s))) {
    findings.push(f("medium", "SPF +all", host, spf.join(" | "), "CWE-290"));
  }
  if (!dmarc.length) {
    findings.push(f("low", "Missing DMARC", host, "No _dmarc TXT.", "CWE-290"));
  } else if (dmarc.some((d) => /p=none/i.test(d))) {
    findings.push(f("info", "DMARC p=none", host, dmarc.join(" | "), "CWE-290"));
  }
  const cnames = records.CNAME || [];
  for (const c of cnames) {
    const vendor = vendorFromCname(c);
    if (vendor) {
      findings.push(f("medium", `CNAME to claimable service (${vendor})`, host, `CNAME ${c}`, "CWE-284"));
    }
  }
  return { host, records, spf, dmarc, findings };
}

function f(severity, title, asset, evidence, cwe) {
  return {
    id: `${title}-${asset}`,
    severity,
    title,
    asset,
    evidence,
    cwe,
    tags: ["dns"],
    status: "new",
    verified: false
  };
}
