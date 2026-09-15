const BLOCKED = new Set([
  "localhost", "127.0.0.1", "0.0.0.0", "::1",
  "internal", "intranet", "corp", "local"
]);

export function normalizeDomain(input) {
  if (!input) return "";
  let s = String(input).trim().toLowerCase();
  s = s.replace(/^https?:\/\//, "").replace(/\/.*$/, "").replace(/:\d+$/, "");
  s = s.replace(/^\*\./, "").replace(/^www\./, "");
  return s;
}

export function isValidDomain(domain) {
  if (!domain || domain.length > 253) return false;
  if (BLOCKED.has(domain)) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) return false;
  return /^(?=.{1,253}$)(?!-)[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(domain);
}

export function inScope(host, root) {
  const h = normalizeDomain(host);
  const r = normalizeDomain(root);
  return h === r || h.endsWith("." + r);
}
