import { runSource, SOURCE_CATALOG } from "../../../lib/sources";
import { isValidDomain, normalizeDomain } from "../../../lib/scope";

export const runtime = "nodejs";
export const maxDuration = 15;

export async function GET() {
  return Response.json({ sources: SOURCE_CATALOG });
}

export async function POST(req) {
  let body = {};
  try { body = await req.json(); } catch {
    return Response.json({ error: "invalid json body" }, { status: 400 });
  }
  const domain = normalizeDomain(body.domain);
  const source = String(body.source || "");
  if (!body.authorized) {
    return Response.json({ error: "authorized must be true" }, { status: 403 });
  }
  if (!isValidDomain(domain)) {
    return Response.json({ error: `invalid domain: ${domain}` }, { status: 400 });
  }
  if (!SOURCE_CATALOG.some((s) => s.id === source)) {
    return Response.json({ error: `unknown source: ${source}` }, { status: 400 });
  }
  try {
    const result = await runSource(source, domain);
    return Response.json({ domain, ...result });
  } catch (e) {
    return Response.json({ domain, source, ok: false, error: String(e && e.message ? e.message : e), data: {} }, { status: 200 });
  }
}
