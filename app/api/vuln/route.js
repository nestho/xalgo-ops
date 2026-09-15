import { isValidDomain, normalizeDomain } from "../../../lib/scope";
import { scanHost } from "../../../lib/scanner";

export const runtime = "nodejs";
export const maxDuration = 15;

export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const domain = normalizeDomain(body.domain);
  const host = normalizeDomain(body.host || body.domain);
  const pack = body.pack === "full" ? "full" : body.pack === "secrets" ? "secrets" : body.pack === "panels" ? "panels" : "quick";
  if (!body.authorized) return Response.json({ error: "authorized required" }, { status: 403 });
  if (!isValidDomain(domain) || !isValidDomain(host)) return Response.json({ error: "invalid host" }, { status: 400 });
  if (host !== domain && !host.endsWith("." + domain)) return Response.json({ error: "host out of scope" }, { status: 400 });
  const result = await scanHost({ host, pack });
  return Response.json(result);
}
