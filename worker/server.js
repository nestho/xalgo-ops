import http from "node:http";
import { spawn } from "node:child_process";

const PORT = Number(process.env.PORT || 8787);
const TOKEN = process.env.WORKER_TOKEN || "";
const NUCLEI = process.env.NUCLEI_BIN || "nuclei";

function readBody(req) {
  return new Promise((resolve, reject) => {
    let d = "";
    req.on("data", (c) => { d += c; if (d.length > 1e6) req.destroy(); });
    req.on("end", () => {
      try { resolve(JSON.parse(d || "{}")); } catch (e) { reject(e); }
    });
  });
}

function runNuclei(target, tags) {
  return new Promise((resolve) => {
    const args = ["-u", target, "-jsonl", "-silent", "-nc", "-timeout", "8", "-retries", "1"];
    if (tags) args.push("-tags", tags);
    const child = spawn(NUCLEI, args, { stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    let err = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 180000);
    child.stdout.on("data", (c) => { out += c; });
    child.stderr.on("data", (c) => { err += c; });
    child.on("close", (code) => {
      clearTimeout(timer);
      const findings = [];
      for (const line of out.split("\n")) {
        if (!line.trim()) continue;
        try {
          const j = JSON.parse(line);
          findings.push({
            id: `${j["template-id"]}-${j.host || target}`,
            template: j["template-id"],
            severity: j.info?.severity || "info",
            title: j.info?.name || j["template-id"],
            asset: j.matched_at || j.host || target,
            evidence: JSON.stringify(j["extracted-results"] || j["matcher-name"] || "").slice(0, 200),
            tags: j.info?.tags || ["nuclei"],
            status: "new",
            verified: false
          });
        } catch {}
      }
      resolve({ code, findings, stderr: err.slice(0, 1000) });
    });
    child.on("error", (e) => resolve({ code: -1, findings: [], stderr: String(e) }));
  });
}

const server = http.createServer(async (req, res) => {
  const hdr = (req.headers["x-worker-token"] || "");
  if (TOKEN && hdr !== TOKEN) {
    res.writeHead(401); res.end("unauthorized"); return;
  }
  if (req.method === "GET" && req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, nuclei: NUCLEI }));
    return;
  }
  if (req.method === "POST" && req.url === "/nuclei") {
    try {
      const body = await readBody(req);
      if (!body.authorized) { res.writeHead(403); res.end("authorized required"); return; }
      const target = String(body.target || "");
      if (!/^https?:\/\/[a-z0-9.-]+/i.test(target) && !/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(target)) {
        res.writeHead(400); res.end("bad target"); return;
      }
      const result = await runNuclei(target.startsWith("http") ? target : `https://${target}`, body.tags || "misconfig,exposure,cve,tech");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify(result));
    } catch (e) {
      res.writeHead(500); res.end(String(e.message || e));
    }
    return;
  }
  res.writeHead(404); res.end("not found");
});

server.listen(PORT, () => console.log(`xalgo-ops worker :${PORT}`));
