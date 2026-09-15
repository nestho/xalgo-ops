# xalgo-ops

Authorized bug-bounty command center.

Pipeline is fixed: **recon → DNS intel → vuln scan → report**.

## What runs on Vercel

- Passive recon: crt.sh, Cert Spotter, HackerTarget, Anubis, ThreatMiner, OTX, Wayback, urlscan, RDAP, DoH
- Host ranking (admin/dev/api first)
- DNS intel: SPF/DMARC/CNAME takeover hints
- HTTP template scanner (Nuclei-style checks for exposed git/env/actuators/swagger/graphql/panels/backups)
- Findings board with triage + JSON/MD export
- Report writer (local heuristic, or Grok/OpenAI/Groq from env — no UI API prompt)

Live: https://xalgo-ops.vercel.app

## What does *not* run on Vercel

ProjectDiscovery Nuclei with the public template pack, nmap, massdns, sqlmap. Those need a binary host. That is `worker/`.

```bash
cd worker
# nuclei must be on PATH
WORKER_TOKEN=change-me node server.js
```

Set `WORKER_URL` and `WORKER_TOKEN` on the Vercel project if you want the dashboard to know a worker exists.

## Use

1. Open the app
2. Enter an in-scope domain
3. Tick authorization
4. `Run full` or `Recon only` then `Vuln only`
5. Triage findings, download the markdown report

Do not file unverified template hits.
