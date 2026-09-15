import { buildReport } from "../../../lib/report";

export const runtime = "nodejs";
export const maxDuration = 20;

export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const domain = body.domain || "";
  const summary = body.summary || {};
  const findings = body.findings || [];
  const local = buildReport({ domain, summary, findings, usedLlmLabel: "local writer" });
  const llm = await maybeLlm(domain, summary, findings);
  return Response.json({ usedLlm: Boolean(llm), report: llm || local });
}

async function maybeLlm(domain, summary, findings) {
  const xai = process.env.XAI_API_KEY;
  const openai = process.env.OPENAI_API_KEY;
  const groq = process.env.GROQ_API_KEY;
  if (!xai && !openai && !groq) return null;
  let url = "https://api.openai.com/v1/chat/completions";
  let key = openai;
  let model = process.env.OPENAI_MODEL || "gpt-4o-mini";
  if (xai) {
    url = "https://api.x.ai/v1/chat/completions";
    key = xai;
    model = process.env.XAI_MODEL || "grok-4-fast-reasoning";
  } else if (groq) {
    url = "https://api.groq.com/openai/v1/chat/completions";
    key = groq;
    model = process.env.GROQ_MODEL || "llama-3.3-70b-versatile";
  }
  const prompt = `Bug bounty recon report. Target ${domain}.
Summary: ${JSON.stringify(summary).slice(0, 7000)}
Findings: ${JSON.stringify(findings).slice(0, 8000)}
Write markdown: snapshot, ranked attack paths, reproduction notes, what is unproven. No exploit payloads.`;
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
      body: JSON.stringify({
        model,
        temperature: 0.2,
        messages: [
          { role: "system", content: "Evidence-first bounty hunter. Do not invent vulns." },
          { role: "user", content: prompt }
        ]
      })
    });
    const j = await res.json();
    return j.choices?.[0]?.message?.content || null;
  } catch {
    return null;
  }
}
