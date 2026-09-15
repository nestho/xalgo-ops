const WEIGHTS = [
  [/(^|\.)(admin|administrator|portal|dashboard|console|grafana|kibana|jenkins|gitlab|git|gitea|argocd|vault|keycloak)/i, 90],
  [/(^|\.)(dev|devel|development|stage|staging|stg|test|testing|qa|uat|preprod|sandbox)/i, 80],
  [/(^|\.)(api|graphql|backend|internal|intranet|corp|vpn|citrix|owa|remote|ssh)/i, 75],
  [/(^|\.)(s3|bucket|storage|cdn|static|assets|media|img)/i, 55],
  [/(^|\.)(mail|webmail|smtp|imap|autodiscover)/i, 50],
  [/(^|\.)(www|app|shop|store|pay|billing|account)/i, 40]
];

export function scoreHost(host, root) {
  let score = host === root ? 70 : 20;
  for (const [re, w] of WEIGHTS) if (re.test(host)) score += w;
  if (host.split(".").length > root.split(".").length + 2) score -= 10;
  return score;
}

export function rankHosts(subdomains, root, limit = 12) {
  const set = new Set([root, ...(subdomains || [])]);
  return [...set]
    .map((h) => ({ host: h, score: scoreHost(h, root) }))
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}
