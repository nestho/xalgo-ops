import { SOURCE_CATALOG } from "../../../lib/sources";

export const runtime = "nodejs";

export async function GET() {
  const keys = {
    xai: Boolean(process.env.XAI_API_KEY),
    openai: Boolean(process.env.OPENAI_API_KEY),
    groq: Boolean(process.env.GROQ_API_KEY),
    securitytrails: Boolean(process.env.SECURITYTRAILS_API_KEY),
    shodan: Boolean(process.env.SHODAN_API_KEY),
    virustotal: Boolean(process.env.VIRUSTOTAL_API_KEY),
    github: Boolean(process.env.GITHUB_TOKEN),
    urlscan: Boolean(process.env.URLSCAN_API_KEY)
  };
  return Response.json({
    ok: true,
    name: "xalgo-ops",
    mode: "passive+light-http",
    llm: keys.xai || keys.openai || keys.groq,
    keys,
    sources: SOURCE_CATALOG
  });
}
