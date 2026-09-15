import { runSource, SOURCE_CATALOG } from "../../../lib/sources";
import { isValidDomain, normalizeDomain } from "../../../lib/scope";

export const runtime = "nodejs";
export const maxDuration = 15;

export async function GET() {
  return Response.json({ sources: SOURCE_CATALOG });
}

export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const domain = normalizeDomain(body.domain);
  const source = String(body.source || "");
  const authorized = Boolean(body.authorized);
  if (!authorized) {
    return Response.json({ error: "Scan refused: authorized must be true. Only use this on programs you are allowed to test." }, { status: 403 });
  }
  if (!isValidDomain(domain)) {
    return Response.json({ error: "Invalid domain" }, { status: 400 });
  }
  if (!SOURCE_CATALOG.some((s) => s.id === source)) {
    return Response.json({ error: "Unknown source" }, { status: 400 });
  }
  const result = await runSource(source, domain);
  return Response.json({ domain, ...result });
}
