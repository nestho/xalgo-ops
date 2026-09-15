"use client";
import { useEffect, useMemo, useState } from "react";

const PHASES = [
  { id: "osint", label: "OSINT" },
  { id: "subdomains", label: "Subdomains" },
  { id: "dns", label: "DNS" },
  { id: "content", label: "Archives" },
  { id: "probe", label: "HTTP probe" },
  { id: "report", label: "Report" }
];

export default function Page() {
  const [tab, setTab] = useState("workbench");
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [health, setHealth] = useState(null);
  const [running, setRunning] = useState(false);
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState({});
  const [assets, setAssets] = useState({ subdomains: [], hosts: [], urls: [], emails: [], paths: [], interesting: [], github: [], internetdb: [] });
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState("");
  const [usedLlm, setUsedLlm] = useState(false);

  useEffect(() => {
    fetch("/api/health").then((r) => r.json()).then(setHealth).catch(() => {});
    const saved = localStorage.getItem("xalgo-ops");
    if (saved) {
      try {
        const j = JSON.parse(saved);
        setDomain(j.domain || "");
        setAssets(j.assets || { subdomains: [], hosts: [], urls: [], emails: [], paths: [], interesting: [], github: [], internetdb: [] });
        setFindings(j.findings || []);
        setReport(j.report || "");
      } catch {}
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("xalgo-ops", JSON.stringify({ domain, assets, findings, report }));
  }, [domain, assets, findings, report]);

  const sources = health?.sources || [];

  function log(msg) {
    setLogs((l) => [`${new Date().toISOString().slice(11, 19)}  ${msg}`, ...l].slice(0, 80));
  }

  function merge(next) {
    setAssets((prev) => {
      const u = (a, b) => [...new Set([...(a || []), ...(b || [])])];
      return {
        subdomains: u(prev.subdomains, next.subdomains).sort(),
        hosts: [...prev.hosts, ...(next.hosts || [])].slice(0, 2000),
        urls: u(prev.urls, next.urls),
        emails: u(prev.emails, next.emails),
        paths: u(prev.paths, next.paths),
        interesting: u(prev.interesting, next.interesting),
        github: [...prev.github, ...(next.github || [])],
        internetdb: [...prev.internetdb, ...(next.internetdb || [])]
      };
    });
    if (next.findings?.length) {
      setFindings((prev) => {
        const map = new Map(prev.map((f) => [f.id, f]));
        next.findings.forEach((f) => map.set(f.id, f));
        return [...map.values()];
      });
    }
  }

  async function run() {
    if (!authorized) {
      log("Refused: tick authorized scope first.");
      return;
    }
    if (!domain.trim()) return;
    setRunning(true);
    setReport("");
    log(`Pipeline start for ${domain}`);
    for (const src of sources) {
      setStatus((s) => ({ ...s, [src.id]: "on" }));
      try {
        const res = await fetch("/api/source", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ domain, source: src.id, authorized: true })
        });
        const j = await res.json();
        if (!res.ok || j.skipped) {
          setStatus((s) => ({ ...s, [src.id]: "fail" }));
          log(`${src.id}: ${j.error || j.skipped || res.status}`);
        } else {
          setStatus((s) => ({ ...s, [src.id]: "ok" }));
          merge({
            subdomains: j.data?.subdomains,
            hosts: j.data?.hosts,
            urls: j.data?.urls,
            emails: j.data?.emails,
            paths: j.data?.paths,
            interesting: j.data?.interesting,
            github: j.data?.hits
          });
          log(`${src.id}: ok`);
        }
      } catch (e) {
        setStatus((s) => ({ ...s, [src.id]: "fail" }));
        log(`${src.id}: ${e.message}`);
      }
    }

    const root = domain.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    log("HTTP probe on apex");
    try {
      const res = await fetch("/api/probe", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ domain: root, host: root, authorized: true })
      });
      const j = await res.json();
      merge({ findings: j.findings, internetdb: j.internetdb });
      log(`probe: ${j.findings?.length || 0} findings`);
    } catch (e) {
      log(`probe failed: ${e.message}`);
    }

    const snapshot = JSON.parse(localStorage.getItem("xalgo-ops") || "{}");
    const summary = {
      subdomainCount: (snapshot.assets?.subdomains || []).length,
      urlCount: (snapshot.assets?.urls || []).length,
      interesting: snapshot.assets?.interesting || [],
      github: snapshot.assets?.github || []
    };
    const analyzeRes = await fetch("/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain: root, summary, findings: snapshot.findings || findings })
    });
    const analyzed = await analyzeRes.json();
    setReport(analyzed.report || "");
    setUsedLlm(Boolean(analyzed.usedLlm));
    log(analyzed.usedLlm ? "Report drafted with configured LLM" : "Report drafted locally (no LLM key in env)");
    setRunning(false);
    setTab("findings");
  }

  const counts = useMemo(() => ({
    subs: assets.subdomains.length,
    urls: assets.urls.length,
    findings: findings.length,
    high: findings.filter((f) => f.severity === "high" || f.severity === "critical").length
  }), [assets, findings]);

  return (
    <div className="app">
      <aside className="side">
        <div className="brand">XALGO<span>-OPS</span></div>
        <div className="tiny">Authorized recon workbench</div>
        <div className="nav">
          {["workbench", "assets", "findings", "report", "limits"].map((id) => (
            <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>{id}</button>
          ))}
        </div>
        <p className="tiny" style={{ marginTop: 24 }}>
          LLM baked from env: {health?.llm ? "yes" : "no (heuristic writer)"}<br />
          Paid keys present: {health ? Object.entries(health.keys || {}).filter(([, v]) => v).map(([k]) => k).join(", ") || "none" : "…"}
        </p>
      </aside>

      <main className="main">
        {tab === "workbench" && (
          <>
            <h1>Pipeline</h1>
            <p className="muted">reconFTW / Osmedeus-style phases, cut down to what Vercel can actually run: passive APIs + light HTTP.</p>
            <div className="banner">Only scan targets you are allowed to test. Bug bounty scope, written contract, or your own systems. Active exploitation, nuclei, and nmap are not in this deploy.</div>
            <div className="row">
              <input type="text" placeholder="target.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
              <button className="primary" disabled={running} onClick={run}>{running ? "Running…" : "Run recon"}</button>
              <button className="ghost" onClick={() => { setAssets({ subdomains: [], hosts: [], urls: [], emails: [], paths: [], interesting: [], github: [], internetdb: [] }); setFindings([]); setReport(""); setStatus({}); }}>Clear</button>
            </div>
            <label className="check">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              I am authorized to collect public recon and send light HTTP requests to this domain.
            </label>
            <div className="phase">
              {PHASES.map((p) => <span key={p.id} className="chip on">{p.label}</span>)}
            </div>
            <div className="phase">
              {sources.map((s) => (
                <span key={s.id} className={`chip ${status[s.id] === "ok" ? "on" : status[s.id] === "fail" ? "fail" : ""}`}>
                  {s.label}{s.needsKey ? " · key" : " · free"}
                </span>
              ))}
            </div>
            <div className="grid">
              <div className="stat"><span className="tiny">Subdomains</span><b>{counts.subs}</b></div>
              <div className="stat"><span className="tiny">Archive URLs</span><b>{counts.urls}</b></div>
              <div className="stat"><span className="tiny">Findings</span><b>{counts.findings}</b></div>
              <div className="stat"><span className="tiny">High / critical</span><b>{counts.high}</b></div>
            </div>
          </>
        )}

        {tab === "assets" && (
          <>
            <h1>Assets</h1>
            <h3>Subdomains ({assets.subdomains.length})</h3>
            <pre>{assets.subdomains.join("\n") || "none yet"}</pre>
            <h3>Interesting archive URLs</h3>
            <pre>{(assets.interesting || []).join("\n") || "none yet"}</pre>
            <h3>GitHub hits</h3>
            <pre>{(assets.github || []).map((g) => `${g.repo} ${g.path}`).join("\n") || "none yet"}</pre>
            <h3>InternetDB</h3>
            <pre>{JSON.stringify(assets.internetdb, null, 2)}</pre>
          </>
        )}

        {tab === "findings" && (
          <>
            <h1>Findings board</h1>
            <table className="table">
              <thead><tr><th>Sev</th><th>Title</th><th>Asset</th><th>Evidence</th></tr></thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id}>
                    <td className={`sev ${f.severity}`}>{f.severity}</td>
                    <td>{f.title}</td>
                    <td>{f.asset}</td>
                    <td className="muted">{f.evidence}</td>
                  </tr>
                ))}
                {!findings.length && <tr><td colSpan="4" className="muted">No findings yet. Run recon first. Most real bugs still need authenticated manual work.</td></tr>}
              </tbody>
            </table>
          </>
        )}

        {tab === "report" && (
          <>
            <h1>Report draft {usedLlm ? "· LLM" : "· local"}</h1>
            <pre>{report || "Run recon to generate a draft."}</pre>
          </>
        )}

        {tab === "limits" && (
          <>
            <h1>What this is, and what it is not</h1>
            <p>Xalgorix, reconFTW, Osmedeus and Vigolium are local/VPS engines. They run nmap, nuclei, browsers, YAML workers, and LLM agents for hours. Vercel is a 10–60s serverless function platform. Those two do not fit.</p>
            <p>This app is the slice that <em>does</em> belong on a URL: dashboard, free passive APIs, light HTTP checks, finding board, report draft. Optional keys live in Vercel env so the UI never asks for an AI key.</p>
            <p>For the missing half: run Xalgorix or Vigolium on a VPS, then paste verified findings here. Do not point any of this at systems you do not have permission to test.</p>
          </>
        )}
      </main>

      <aside className="rail">
        <h3>Live log</h3>
        <pre style={{ minHeight: 280 }}>{logs.join("\n") || "idle"}</pre>
        <h3>Notes</h3>
        <p className="tiny">Free sources can rate-limit. HackerTarget especially. Empty results usually mean throttle, not “no assets”.</p>
      </aside>
    </div>
  );
}
