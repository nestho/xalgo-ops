import { isValidDomain, normalizeDomain } from "../../../lib/scope";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function POST(req) {
  const worker = process.env.WORKER_URL;
  if (!worker) {
    return Response.json({ skipped: true, error: "WORKER_URL not set", findings: [] });
  }
  const body = await req.json().catch(() => ({}));
  const domain = normalizeDomain(body.domain);
  const host = normalizeDomain(body.host || body.domain);
  if (!body.authorized) return Response.json({ error: "authorized required" }, { status: 403 });
  if (!isValidDomain(domain) || !isValidDomain(host)) return Response.json({ error: "invalid host" }, { status: 400 });
  if (host !== domain && !host.endsWith("." + domain)) return Response.json({ error: "host out of scope" }, { status: 400 });
  try {
    const res = await fetch(`${worker.replace(/\/$/, "")}/nuclei`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "x-worker-token": process.env.WORKER_TOKEN || ""
      },
      body: JSON.stringify({ target: `https://${host}`, authorized: true, tags: body.tags || "misconfig,exposure,cve,tech" })
    });
    const j = await res.json().catch(() => ({}));
    return Response.json({ ok: res.ok, ...j });
  } catch (e) {
    return Response.json({ ok: false, error: String(e.message || e), findings: [] }, { status: 502 });
  }
}
