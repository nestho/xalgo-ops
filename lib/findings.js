const TAKEOVER_FINGERPRINTS = [
  { re: /no such bucket/i, vendor: "AWS S3" },
  { re: /there isn't a github pages site here/i, vendor: "GitHub Pages" },
  { re: /repository not found/i, vendor: "GitHub" },
  { re: /no settings were found for this company/i, vendor: "Help Scout" },
  { re: /is not a registered instapage/i, vendor: "Instapage" },
  { re: /the specified bucket does not exist/i, vendor: "AWS S3" },
  { re: /project not found/i, vendor: "Readme.io / Surge" },
  { re: /whatever you were looking for doesn't currently exist/i, vendor: "Tumblr" },
  { re: /do you want to register/i, vendor: "Wordpress" }
];

export function findingsFromProbe(probe) {
  const out = [];
  if (!probe) return out;
  const url = probe.url || "";
  const headers = probe.headers || {};
  const body = probe.bodySnippet || "";
  const h = Object.fromEntries(Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]));

  if (probe.path === "/.git/HEAD" && /^(ref:|\w{40})/.test(body)) {
    out.push(finding("critical", "Exposed Git repository", url, "/.git/HEAD is readable. Source and history may leak.", "CWE-538"));
  }
  if (probe.path === "/.env" && /=/.test(body) && !/html/i.test(body.slice(0, 80))) {
    out.push(finding("critical", "Exposed environment file", url, ".env returned key=value content.", "CWE-200"));
  }
  if (probe.path && /swagger|openapi/i.test(probe.path) && /"swagger"|"openapi"/i.test(body)) {
    out.push(finding("medium", "OpenAPI / Swagger exposed", url, "API schema is public. Map auth and object IDs next.", "CWE-200"));
  }
  if (!h["content-security-policy"]) {
    out.push(finding("low", "Missing Content-Security-Policy", url, "No CSP header on this response.", "CWE-693"));
  }
  if (!h["x-frame-options"] && !(h["content-security-policy"] || "").includes("frame-ancestors")) {
    out.push(finding("low", "Clickjacking surface", url, "No X-Frame-Options or CSP frame-ancestors.", "CWE-1021"));
  }
  if ((h["access-control-allow-origin"] || "") === "*" && h["access-control-allow-credentials"] === "true") {
    out.push(finding("high", "Permissive CORS with credentials", url, "ACA-Origin * combined with credentials is invalid but worth verifying on APIs.", "CWE-942"));
  } else if ((h["access-control-allow-origin"] || "") === "*") {
    out.push(finding("info", "Wildcard CORS", url, "Access-Control-Allow-Origin is *. Check authenticated APIs separately.", "CWE-942"));
  }
  if ((h["server"] || "").match(/IIS\/6|Apache\/2\.2|PHP\/5|OpenSSL\/0\./i)) {
    out.push(finding("medium", "Aging server banner", url, `Server: ${h["server"]}`, "CWE-1104"));
  }
  if (h["x-powered-by"]) {
    out.push(finding("info", "Technology disclosure", url, `X-Powered-By: ${h["x-powered-by"]}`, "CWE-200"));
  }
  for (const fp of TAKEOVER_FINGERPRINTS) {
    if (fp.re.test(body)) {
      out.push(finding("high", `Possible subdomain takeover (${fp.vendor})`, url, "Response matches a common dangling-service fingerprint. Confirm DNS and claimability before reporting.", "CWE-284"));
    }
  }
  return out;
}

export function findingsFromAssets(domain, assets) {
  const out = [];
  const subs = assets.subdomains || [];
  const interesting = subs.filter((s) => /dev|stage|staging|test|uat|qa|admin|internal|vpn|git|jenkins|grafana|kibana|s3|bucket|vpn|citrix|owa|mail/i.test(s));
  if (interesting.length) {
    out.push(finding("info", "High-value hostnames", domain, interesting.slice(0, 25).join(", "), "CWE-200"));
  }
  const emails = assets.emails || [];
  if (emails.length) {
    out.push(finding("info", "Public emails in passive sources", domain, emails.slice(0, 15).join(", "), "CWE-200"));
  }
  return out;
}

function finding(severity, title, asset, evidence, cwe) {
  return {
    id: `${severity}-${title}-${asset}`.slice(0, 80),
    severity,
    title,
    asset,
    evidence,
    cwe,
    status: "new",
    verified: false
  };
}
