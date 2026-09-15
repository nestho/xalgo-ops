# xalgo-ops

Authorized bug-bounty command center. Dashboard + passive recon + light HTTP checks, deployable on Vercel.

This is **not** a hosted copy of [Xalgorix](https://github.com/xalgorix/xalgorix), reconFTW, Osmedeus, or Vigolium. Those tools need a long-running privileged host (Kali/Docker, nmap, nuclei, browsers, YAML workers). Vercel cannot run that stack.

What this repo *does* take from them:

- Phase layout similar to reconFTW / Osmedeus (OSINT → subdomains → DNS → archives → HTTP → report)
- Finding board and evidence-first report tone closer to Xalgorix / Vigolium
- Free/public APIs wired in so a scan works without pasting keys in the UI

## Run locally

```bash
npm install
npm run dev
```

Open http://localhost:3000

## Deploy on Vercel

Import `nestho/xalgo-ops`. Optional env vars (never prompted in the UI):

- `XAI_API_KEY` / `XAI_MODEL` — Grok report drafting
- `OPENAI_API_KEY` or `GROQ_API_KEY` — fallback LLM
- `SECURITYTRAILS_API_KEY`, `VIRUSTOTAL_API_KEY`, `GITHUB_TOKEN`, `URLSCAN_API_KEY`

If no LLM key is set, reports are written by a local heuristic.

## Rules

Only use this on programs you are allowed to test. The API rejects scans unless `authorized: true` is sent. Light HTTP probes hit a short allowlist of paths on the named host. No exploit payloads ship in this app.

## What you still need a VPS for

Xalgorix agent, reconFTW `-a`, Osmedeus flows, Vigolium native/agent scan, massdns/puredns brute, nuclei templates, authenticated DAST. Point those at the same in-scope targets, then bring verified findings back into this board.
