import { TEMPLATES, PACKS } from "./templates.js";
import { CANON } from "./takeover.js";

function pick(pack) {
  const ids = PACKS[pack] || PACKS.quick;
  return TEMPLATES.filter((t) => ids.includes(t.id));
}

function matchOne(matcher, res) {
  const body = res.body || "";
  const headers = res.headers || {};
  if (matcher.type === "status") return matcher.status.includes(res.status);
  if (matcher.type === "word") return matcher.words.every((w) => body.toLowerCase().includes(String(w).toLowerCase()));
  if (matcher.type === "regex") {
    try { return new RegExp(matcher.regex).test(body); } catch { return false; }
  }
  if (matcher.type === "header") {
    const val = headers[(matcher.header || "").toLowerCase()] || "";
    try { return new RegExp(matcher.regex, "i").test(val); } catch { return false; }
  }
  if (matcher.type === "binary") return body.includes(matcher.magic);
  return false;
}

export async function scanHost({ host, pack = "quick", timeoutMs = 5000 }) {
  const templates = pick(pack);
  const findings = [];
  const executed = [];
  for (const t of templates) {
    const url = `https://${host}${t.path}`;
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetch(url, {
        method: t.method || "GET",
        redirect: "manual",
        signal: ctrl.signal,
        headers: {
          "user-agent": "xalgo-ops/1.1 authorized-scan",
          accept: "*/*",
          ...(t.headers || {})
        },
        body: t.body
      });
      const headers = Object.fromEntries([...res.headers.entries()].map(([k, v]) => [k.toLowerCase(), v]));
      let body = "";
      try { body = (await res.text()).slice(0, 2500); } catch {}
      const result = { status: res.status, headers, body };
      const ok = (t.matchers || []).every((m) => matchOne(m, result));
      executed.push({ id: t.id, status: res.status, hit: ok });
      if (ok) {
        findings.push({
          id: `${t.id}-${host}`,
          template: t.id,
          severity: t.severity,
          title: t.name,
          asset: url,
          evidence: `status=${res.status} body=${body.replace(/\s+/g, " ").slice(0, 180)}`,
          tags: t.tags,
          status: "new",
          verified: false,
          cwe: "CWE-200"
        });
      }
      for (const fp of CANON) {
        if (fp.body.test(body)) {
          findings.push({
            id: `takeover-${fp.vendor}-${host}`,
            template: "takeover-fingerprint",
            severity: "high",
            title: `Possible takeover fingerprint (${fp.vendor})`,
            asset: url,
            evidence: body.slice(0, 160),
            tags: ["takeover"],
            status: "new",
            verified: false,
            cwe: "CWE-284"
          });
        }
      }
    } catch {
      executed.push({ id: t.id, status: 0, hit: false });
    } finally {
      clearTimeout(timer);
    }
  }
  return { host, pack, templates: templates.length, executed, findings };
}
