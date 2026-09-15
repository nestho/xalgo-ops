export async function fetchJson(url, opts = {}, timeoutMs = 9000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      ...opts,
      signal: ctrl.signal,
      headers: {
        "user-agent": "xalgo-ops/1.0 authorized-recon",
        accept: "application/json,text/plain,*/*",
        ...(opts.headers || {})
      }
    });
    const text = await res.text();
    let json = null;
    try { json = JSON.parse(text); } catch {}
    return { ok: res.ok, status: res.status, text, json, headers: Object.fromEntries(res.headers.entries()) };
  } catch (err) {
    return { ok: false, status: 0, text: String(err.message || err), json: null, headers: {} };
  } finally {
    clearTimeout(t);
  }
}

export async function fetchText(url, opts = {}, timeoutMs = 9000) {
  const r = await fetchJson(url, opts, timeoutMs);
  return r;
}
