import { isValidDomain, normalizeDomain } from "../../../lib/scope";
import { dnsIntel } from "../../../lib/dnsintel";

export const runtime = "nodejs";
export const maxDuration = 15;

export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const domain = normalizeDomain(body.domain);
  const host = normalizeDomain(body.host || body.domain);
  if (!body.authorized) return Response.json({ error: "authorized required" }, { status: 403 });
  if (!isValidDomain(domain) || !isValidDomain(host)) return Response.json({ error: "invalid host" }, { status: 400 });
  if (host !== domain && !host.endsWith("." + domain)) return Response.json({ error: "host out of scope" }, { status: 400 });
  const result = await dnsIntel(host);
  return Response.json(result);
}
