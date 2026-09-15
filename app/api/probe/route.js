import { isValidDomain, normalizeDomain } from "../../../lib/scope";
import { findingsFromProbe } from "../../../lib/findings";

export const runtime = "nodejs";
export const maxDuration = 15;

const PATHS = [
  "/",
  "/robots.txt",
  "/sitemap.xml",
  "/security.txt",
  "/.well-known/security.txt",
  "/.git/HEAD",
  "/.env",
  "/swagger.json",
  "/swagger/v1/swagger.json",
  "/openapi.json",
  "/api",
  "/api/docs",
  "/graphql"
];

export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const domain = normalizeDomain(body.domain);
  const host = normalizeDomain(body.host || body.domain);
  const authorized = Boolean(body.authorized);
  if (!authorized) return Response.json({ error: "authorized required" }, { status: 403 });
  if (!isValidDomain(domain) || !isValidDomain(host)) {
    return Response.json({ error: "Invalid host" }, { status: 400 });
  }
  if (!host.endsWith(domain) && host !== domain) {
    return Response.json({ error: "Host is out of scope of domain" }, { status: 400 });
  }

  const probes = [];
  const findings = [];
  for (const path of PATHS) {
    const urls = [`https://${host}${path}`, `http://${host}${path}`];
    let done = false;
    for (const url of urls) {
      if (done) break;
      const ctrl = new AbortController();
      const t = setTimeout(() => ctrl.abort(), 6000);
      try {
        const res = await fetch(url, {
          method: path === "/graphql" ? "POST" : "GET",
          redirect: "manual",
          signal: ctrl.signal,
          headers: {
            "user-agent": "xalgo-ops/1.0 authorized-recon",
            accept: "*/*",
            origin: `https://${host}`,
            ...(path === "/graphql" ? { "content-type": "application/json" } : {})
          },
          body: path === "/graphql" ? JSON.stringify({ query: "{__typename}" }) : undefined
        });
        const text = await res.text().catch(() => "");
        const headers = Object.fromEntries(res.headers.entries());
        const snippet = text.slice(0, 400);
        const probe = {
          url,
          path,
          status: res.status,
          headers,
          bodySnippet: snippet,
          server: headers.server || headers["x-powered-by"] || null
        };
        probes.push(probe);
        findings.push(...findingsFromProbe(probe));
        done = res.status > 0;
      } catch {
        probes.push({ url, path, status: 0, headers: {}, bodySnippet: "", error: "timeout/network" });
      } finally {
        clearTimeout(t);
      }
    }
  }

  const internetdb = [];
  const ips = new Set();
  try {
    const dns = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(host)}&type=A`, {
      headers: { accept: "application/dns-json" }
    });
    const j = await dns.json();
    for (const a of j.Answer || []) if (a.type === 1) ips.add(a.data);
  } catch {}
  for (const ip of [...ips].slice(0, 3)) {
    try {
      const r = await fetch(`https://internetdb.shodan.io/${ip}`);
      if (r.ok) internetdb.push({ ip, ...(await r.json()) });
    } catch {}
  }

  return Response.json({ host, probes, findings, internetdb });
}
