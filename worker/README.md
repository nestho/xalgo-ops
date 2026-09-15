# xalgo-ops worker

Runs on a VPS or laptop, not on Vercel. Exposes Nuclei behind a tiny HTTP API.

```bash
# install nuclei first: https://docs.projectdiscovery.io/tools/nuclei/install
export WORKER_TOKEN=change-me
node server.js
```

Docker:

```bash
docker build -t xalgo-ops-worker .
docker run --rm -p 8787:8787 -e WORKER_TOKEN=change-me xalgo-ops-worker
```

Then set on the Vercel project:

- WORKER_URL=https://your-vps:8787
- WORKER_TOKEN=change-me

Only point Nuclei at in-scope hosts. Update templates with `nuclei -update-templates` on that machine.
