"use client";
import { useEffect, useMemo, useRef, useState } from "react";

const PHASES = [
  { id: "recon", label: "1 Recon" },
  { id: "dns", label: "2 DNS intel" },
  { id: "vuln", label: "3 Vuln scan" },
  { id: "report", label: "4 Report" }
];

const emptyAssets = () => ({ subdomains: [], hosts: [], urls: [], emails: [], paths: [], interesting: [], github: [], internetdb: [], ranked: [], dns: {} });

export default function Page() {
  const [tab, setTab] = useState("workbench");
  const [domain, setDomain] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [pack, setPack] = useState("quick");
  const [hostLimit, setHostLimit] = useState(8);
  const [health, setHealth] = useState(null);
  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState("idle");
  const [logs, setLogs] = useState([]);
  const [status, setStatus] = useState({});
  const [assets, setAssets] = useState(emptyAssets());
  const [findings, setFindings] = useState([]);
  const [report, setReport] = useState("");
  const [usedLlm, setUsedLlm] = useState(false);
  const [filter, setFilter] = useState("all");
  const bag = useRef({ assets: emptyAssets(), findings: [] });

  useEffect(() => {
    fetch("/api/health").then((r) => r.json()).then(setHealth).catch(() => {});
    const saved = localStorage.getItem("xalgo-ops-v11");
    if (saved) {
      try {
        const j = JSON.parse(saved);
        setDomain(j.domain || "");
        setAssets(j.assets || emptyAssets());
        setFindings(j.findings || []);
        setReport(j.report || "");
        bag.current.assets = j.assets || emptyAssets();
        bag.current.findings = j.findings || [];
      } catch {}
    }
  }, []);

  useEffect(() => {
    localStorage.setItem("xalgo-ops-v11", JSON.stringify({ domain, assets, findings, report }));
  }, [domain, assets, findings, report]);

  const sources = health?.sources || [];

  function log(msg) {
    setLogs((l) => [`${new Date().toISOString().slice(11, 19)}  ${msg}`, ...l].slice(0, 120));
  }

  function merge(next) {
    const u = (a, b) => [...new Set([...(a || []), ...(b || [])])];
    const assetsNext = {
      ...bag.current.assets,
      subdomains: u(bag.current.assets.subdomains, next.subdomains).sort(),
      hosts: [...(bag.current.assets.hosts || []), ...(next.hosts || [])].slice(0, 3000),
      urls: u(bag.current.assets.urls, next.urls),
      emails: u(bag.current.assets.emails, next.emails),
      paths: u(bag.current.assets.paths, next.paths),
      interesting: u(bag.current.assets.interesting, next.interesting),
      github: [...(bag.current.assets.github || []), ...(next.github || [])],
      internetdb: [...(bag.current.assets.internetdb || []), ...(next.internetdb || [])],
      ranked: next.ranked || bag.current.assets.ranked || [],
      dns: { ...(bag.current.assets.dns || {}), ...(next.dns || {}) }
    };
    bag.current.assets = assetsNext;
    setAssets(assetsNext);
    if (next.findings?.length) {
      const map = new Map(bag.current.findings.map((f) => [f.id, f]));
      next.findings.forEach((f) => map.set(f.id, f));
      const list = [...map.values()];
      bag.current.findings = list;
      setFindings(list);
    }
  }

  async function post(path, payload) {
    const res = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ ...payload, authorized: true })
    });
    const j = await res.json();
    if (!res.ok) throw new Error(j.error || res.status);
    return j;
  }

  async function runRecon(root) {
    setPhase("recon");
    log(`RECON start ${root}`);
    const batch = [];
    for (const src of sources) {
      batch.push(src);
      if (batch.length === 3) {
        await Promise.all(batch.map((s) => runSrc(s, root)));
        batch.length = 0;
      }
    }
    if (batch.length) await Promise.all(batch.map((s) => runSrc(s, root)));
  }

  async function runSrc(src, root) {
    setStatus((s) => ({ ...s, [src.id]: "on" }));
    try {
      const j = await post("/api/source", { domain: root, source: src.id });
      if (j.skipped) {
        setStatus((s) => ({ ...s, [src.id]: "fail" }));
        log(`${src.id}: skipped`);
        return;
      }
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
      log(`${src.id}: ${(j.data?.subdomains || []).length} subs`);
    } catch (e) {
      setStatus((s) => ({ ...s, [src.id]: "fail" }));
      log(`${src.id}: ${e.message}`);
    }
  }

  function rank(root) {
    const weights = [
      [/(^|\.)(admin|portal|dashboard|console|grafana|kibana|jenkins|gitlab|git)/i, 90],
      [/(^|\.)(dev|stage|staging|test|qa|uat|preprod|sandbox)/i, 80],
      [/(^|\.)(api|graphql|backend|internal|vpn|owa)/i, 75],
      [/(^|\.)(s3|bucket|cdn|static)/i, 55],
      [/(^|\.)(mail|webmail)/i, 50]
    ];
    const set = new Set([root, ...bag.current.assets.subdomains]);
    const ranked = [...set].map((h) => {
      let score = h === root ? 70 : 20;
      for (const [re, w] of weights) if (re.test(h)) score += w;
      return { host: h, score };
    }).sort((a, b) => b.score - a.score).slice(0, Number(hostLimit) || 8);
    merge({ ranked });
    return ranked;
  }

  async function runDns(root, ranked) {
    setPhase("dns");
    log("DNS intel on ranked hosts");
    for (const item of ranked.slice(0, 6)) {
      try {
        const j = await post("/api/dnsintel", { domain: root, host: item.host });
        merge({ dns: { [item.host]: j.records }, findings: j.findings });
        log(`dns ${item.host}: ${(j.findings || []).length} notes`);
      } catch (e) {
        log(`dns ${item.host}: ${e.message}`);
      }
    }
  }

  async function runVuln(root, ranked) {
    setPhase("vuln");
    log(`VULN pack=${pack} hosts=${ranked.length}`);
    for (const item of ranked) {
      try {
        const j = await post("/api/vuln", { domain: root, host: item.host, pack });
        merge({ findings: j.findings });
        log(`scan ${item.host}: ${j.findings.length} hits / ${j.templates} templates`);
      } catch (e) {
        log(`scan ${item.host}: ${e.message}`);
      }
      if (health?.worker) {
        try {
          const n = await post("/api/nuclei", { domain: root, host: item.host });
          merge({ findings: n.findings || [] });
          log(`nuclei ${item.host}: ${(n.findings || []).length} hits`);
        } catch (e) {
          log(`nuclei ${item.host}: ${e.message}`);
        }
      }
    }
  }

  async function runReport(root) {
    setPhase("report");
    const summary = {
      subdomainCount: bag.current.assets.subdomains.length,
      urlCount: bag.current.assets.urls.length,
      hostsScanned: (bag.current.assets.ranked || []).length,
      interesting: bag.current.assets.interesting,
      github: bag.current.assets.github
    };
    const analyzed = await post("/api/analyze", { domain: root, summary, findings: bag.current.findings });
    setReport(analyzed.report || "");
    setUsedLlm(Boolean(analyzed.usedLlm));
    log(analyzed.usedLlm ? "report: LLM" : "report: local writer");
  }

  async function run(mode) {
    if (!authorized) return log("Refused: authorize scope first.");
    const root = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/^www\./, "");
    if (!root) return;
    setRunning(true);
    if (mode === "full" || mode === "recon") {
      bag.current = { assets: emptyAssets(), findings: [] };
      setAssets(emptyAssets());
      setFindings([]);
      setReport("");
      setStatus({});
    }
    try {
      if (mode === "full" || mode === "recon") await runRecon(root);
      const ranked = rank(root);
      if (mode === "full" || mode === "recon") await runDns(root, ranked);
      if (mode === "full" || mode === "vuln") await runVuln(root, ranked.length ? ranked : [{ host: root, score: 70 }]);
      if (mode === "full" || mode === "report") await runReport(root);
      setTab(mode === "recon" ? "assets" : "findings");
    } finally {
      setRunning(false);
      setPhase("idle");
    }
  }

  function setFindingStatus(id, next) {
    const list = bag.current.findings.map((f) => f.id === id ? { ...f, status: next } : f);
    bag.current.findings = list;
    setFindings(list);
  }

  function download(name, text) {
    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
  }

  const shown = findings.filter((f) => filter === "all" || f.severity === filter);
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
        <div className="tiny">recon → vuln → report</div>
        <div className="nav">
          {["workbench", "assets", "findings", "report", "limits"].map((id) => (
            <button key={id} className={tab === id ? "active" : ""} onClick={() => setTab(id)}>{id}</button>
          ))}
        </div>
        <p className="tiny" style={{ marginTop: 24 }}>
          templates: {health?.templates ?? "…"}<br />
          LLM env: {health?.llm ? "yes" : "no"}<br />
          Nuclei worker: {health?.worker ? "configured" : "not attached"}
        </p>
      </aside>
      <main className="main">
        {tab === "workbench" && (
          <>
            <h1>Pipeline</h1>
            <p className="muted">Phase 1 collects assets. Phase 3 scans ranked hosts. Full Nuclei only if a worker is attached.</p>
            <div className="banner">Authorized targets only. Template hits are leads, not finished bounty reports.</div>
            <div className="row">
              <input type="text" placeholder="target.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
              <select value={pack} onChange={(e) => setPack(e.target.value)} style={{ background: "#161b24", color: "#e7edf5", border: "1px solid #232a36", padding: "8px", borderRadius: 8 }}>
                <option value="quick">pack: quick</option>
                <option value="full">pack: full</option>
                <option value="secrets">pack: secrets</option>
                <option value="panels">pack: panels</option>
              </select>
              <input type="text" style={{ minWidth: 90 }} value={hostLimit} onChange={(e) => setHostLimit(e.target.value)} title="max hosts" />
              <button className="primary" disabled={running} onClick={() => run("full")}>{running ? `running ${phase}` : "Run full"}</button>
              <button className="ghost" disabled={running} onClick={() => run("recon")}>Recon only</button>
              <button className="ghost" disabled={running} onClick={() => run("vuln")}>Vuln only</button>
              <button className="ghost" disabled={running} onClick={() => run("report")}>Report only</button>
            </div>
            <label className="check">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              I am authorized to recon and send HTTP checks to this domain and its in-scope hosts.
            </label>
            <div className="phase">{PHASES.map((p) => <span key={p.id} className={`chip ${phase === p.id ? "on" : ""}`}>{p.label}</span>)}</div>
            <div className="phase">
              {sources.map((s) => (
                <span key={s.id} className={`chip ${status[s.id] === "ok" ? "on" : status[s.id] === "fail" ? "fail" : ""}`}>{s.label}{s.needsKey ? " · key" : ""}</span>
              ))}
            </div>
            <div className="grid">
              <div className="stat"><span className="tiny">Subdomains</span><b>{counts.subs}</b></div>
              <div className="stat"><span className="tiny">Archive URLs</span><b>{counts.urls}</b></div>
              <div className="stat"><span className="tiny">Findings</span><b>{counts.findings}</b></div>
              <div className="stat"><span className="tiny">High / critical</span><b>{counts.high}</b></div>
            </div>
            <h3>Ranked scan queue</h3>
            <pre>{(assets.ranked || []).map((r) => `${r.score}\t${r.host}`).join("\n") || "run recon first"}</pre>
          </>
        )}
        {tab === "assets" && (
          <>
            <h1>Assets</h1>
            <div className="row">
              <button className="ghost" onClick={() => download(`${domain || "target"}-subs.txt`, assets.subdomains.join("\n"))}>Export subs</button>
              <button className="ghost" onClick={() => download(`${domain || "target"}-urls.txt`, assets.urls.join("\n"))}>Export URLs</button>
            </div>
            <h3>Subdomains ({assets.subdomains.length})</h3>
            <pre>{assets.subdomains.join("\n") || "none"}</pre>
            <h3>Interesting URLs</h3>
            <pre>{(assets.interesting || []).join("\n") || "none"}</pre>
          </>
        )}
        {tab === "findings" && (
          <>
            <h1>Findings</h1>
            <div className="row">
              {["all", "critical", "high", "medium", "low", "info"].map((s) => (
                <button key={s} className={filter === s ? "primary" : "ghost"} onClick={() => setFilter(s)}>{s}</button>
              ))}
              <button className="ghost" onClick={() => download(`${domain || "target"}-findings.json`, JSON.stringify(findings, null, 2))}>Export JSON</button>
            </div>
            <table className="table">
              <thead><tr><th>Sev</th><th>Title</th><th>Asset</th><th>Evidence</th><th>Triage</th></tr></thead>
              <tbody>
                {shown.map((f) => (
                  <tr key={f.id}>
                    <td className={`sev ${f.severity}`}>{f.severity}</td>
                    <td>{f.title}</td>
                    <td>{f.asset}</td>
                    <td className="muted">{f.evidence}</td>
                    <td>
                      <select value={f.status || "new"} onChange={(e) => setFindingStatus(f.id, e.target.value)} style={{ background: "#161b24", color: "#e7edf5", border: "1px solid #232a36" }}>
                        <option value="new">new</option>
                        <option value="confirmed">confirmed</option>
                        <option value="false-positive">fp</option>
                      </select>
                    </td>
                  </tr>
                ))}
                {!shown.length && <tr><td colSpan="5" className="muted">No findings in this filter.</td></tr>}
              </tbody>
            </table>
          </>
        )}
        {tab === "report" && (
          <>
            <h1>Report {usedLlm ? "· LLM" : "· local"}</h1>
            <button className="ghost" onClick={() => download(`${domain || "target"}-report.md`, report || "")}>Download .md</button>
            <pre>{report || "Run the pipeline to draft a report."}</pre>
          </>
        )}
        {tab === "limits" && (
          <>
            <h1>Coverage</h1>
            <p>Vercel: recon APIs + HTTP templates. Nuclei public pack: worker on a VPS.</p>
            <p>File only what you reproduced.</p>
          </>
        )}
      </main>
      <aside className="rail">
        <h3>Live log</h3>
        <pre style={{ minHeight: 320 }}>{logs.join("\n") || "idle"}</pre>
      </aside>
    </div>
  );
}
