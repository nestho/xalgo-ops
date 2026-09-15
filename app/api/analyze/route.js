export const runtime = "nodejs";
export const maxDuration = 20;

export async function POST(req) {
  const body = await req.json().catch(() => ({}));
  const domain = body.domain || "";
  const summary = body.summary || {};
  const findings = body.findings || [];

  const local = localReport(domain, summary, findings);
  const llm = await maybeLlm(domain, summary, findings);
  return Response.json({
    usedLlm: Boolean(llm),
    report: llm || local
  });
}

function localReport(domain, summary, findings) {
  const crit = findings.filter((f) => f.severity === "critical" || f.severity === "high");
  const lines = [];
  lines.push(`# xalgo-ops report — ${domain}`);
  lines.push("");
  lines.push("Authorized testing only. This is a passive + light HTTP pass, not a full pentest.");
  lines.push("");
  lines.push(`- Subdomains: ${summary.subdomainCount || 0}`);
  lines.push(`- URLs from archives: ${summary.urlCount || 0}`);
  lines.push(`- Findings: ${findings.length} (${crit.length} high/critical)`);
  lines.push("");
  lines.push("## Priority attack paths");
  if (!findings.length) {
    lines.push("1. Probe interesting hostnames (dev/stage/admin/vpn) with authenticated session tests.");
    lines.push("2. Diff archive URLs vs live paths for forgotten endpoints.");
    lines.push("3. Map APIs from JS and OpenAPI, then test IDOR/BOLA on object IDs.");
  } else {
    findings.slice(0, 12).forEach((f, i) => {
      lines.push(`${i + 1}. **${f.severity.toUpperCase()} — ${f.title}** on \`${f.asset}\``);
      lines.push(`   Evidence: ${f.evidence}`);
    });
  }
  lines.push("");
  lines.push("## What this scan did not do");
  lines.push("No nmap, nuclei, sqlmap, XSS fuzzing, or exploit verification. Those need a VPS worker (Xalgorix / reconFTW / Osmedeus / Vigolium), not Vercel serverless.");
  return lines.join("\n");
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
  } else if (process.env.OPENAI_BASE_URL) {
    url = process.env.OPENAI_BASE_URL.replace(/\/$/, "") + "/chat/completions";
  }

  const prompt = `You are a bug bounty hunter writing an attack plan from PASSIVE recon only.
Target: ${domain}
Summary JSON: ${JSON.stringify(summary).slice(0, 8000)}
Findings JSON: ${JSON.stringify(findings).slice(0, 8000)}
Write markdown: executive snapshot, ranked attack paths, what to verify next, and what is NOT proven. No exploit payloads. No claims of confirmed RCE/SQLi without evidence.`;

  try {
    const res = await fetch(url, {
      method: "POST",
      headers: {
        authorization: `Bearer ${key}`,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        model,
        temperature: 0.2,
        messages: [
          { role: "system", content: "Concise offensive recon analyst. Evidence over hype." },
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
