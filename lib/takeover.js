export const CANON = [
  { vendor: "GitHub Pages", cname: /github\.io$/i, body: /there isn't a github pages site here/i },
  { vendor: "Heroku", cname: /herokudns\.com$|herokuapp\.com$/i, body: /no such app/i },
  { vendor: "AWS S3", cname: /s3[.-][a-z0-9-]+\.amazonaws\.com$|s3\.amazonaws\.com$/i, body: /no such bucket|the specified bucket does not exist/i },
  { vendor: "Cloudfront", cname: /cloudfront\.net$/i, body: /the request could not be satisfied|bad request/i },
  { vendor: "Azure", cname: /azurewebsites\.net$|cloudapp\.net$|trafficmanager\.net$/i, body: /404 web site not found/i },
  { vendor: "Shopify", cname: /myshopify\.com$/i, body: /sorry, this shop is currently unavailable/i },
  { vendor: "Tumblr", cname: /tumblr\.com$/i, body: /whatever you were looking for doesn't currently exist/i },
  { vendor: "Fastly", cname: /fastly\.net$/i, body: /fastly error: unknown domain/i },
  { vendor: "Pantheon", cname: /pantheonsite\.io$/i, body: /404 error unknown site/i },
  { vendor: "Surge", cname: /surge\.sh$/i, body: /project not found/i },
  { vendor: "Bitbucket", cname: /bitbucket\.io$/i, body: /repository not found/i },
  { vendor: "Zendesk", cname: /zendesk\.com$/i, body: /help center closed/i },
  { vendor: "Readme", cname: /readme\.io$/i, body: /project doesnt exist|not found/i },
  { vendor: "Netlify", cname: /netlify\.app$|netlifyglobalcdn\.com$/i, body: /not found — request id/i },
  { vendor: "Vercel", cname: /vercel-dns\.com$|vercel\.app$/i, body: /deployment not found|the deployment could not be found/i },
  { vendor: "Cargo", cname: /cargocollective\.com$/i, body: /404 not found/i },
  { vendor: "Ghost", cname: /ghost\.io$/i, body: /doesn.t exist/i },
  { vendor: "WordPress.com", cname: /wordpress\.com$/i, body: /doesn.t exist/i }
];

export function vendorFromCname(cname) {
  if (!cname) return null;
  const hit = CANON.find((c) => c.cname.test(String(cname).replace(/\.$/, "")));
  return hit ? hit.vendor : null;
}
