export async function fetchJson(url, opts = {}, timeoutMs = 8000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      headers: {
        "user-agent": "xalgo-ops/1.1 authorized-recon",
        accept: "application/json,text/plain,*/*",
        ...(opts.headers || {})
      }
    });
    const text = (await res.text()).slice(0, 750000);
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { ok: res.ok, status: res.status, text, json, headers: {} };
  } catch (err) {
    return { ok: false, status: 0, text: String(err && err.message ? err.message : err), json: null, headers: {} };
  } finally {
    clearTimeout(t);
  }
}
