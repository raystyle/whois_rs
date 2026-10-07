// RDAP 443 备选道:本站 TCP 43 被拦时走 RDAP(fetch,HTTPS 443)。IANA bootstrap 发现注册局。
const BOOTSTRAP = "https://data.iana.org/rdap/dns.json";
const cache = { tlds: null, at: 0 };

async function bootstrap() {
  if (cache.tlds && Date.now() - cache.at < 86400_000) return cache.tlds;
  const r = await fetch(BOOTSTRAP);
  const j = await r.json();
  const map = {};
  for (const svc of j.services) {
    const tlds = svc[0];
    const urls = svc[1];
    for (const t of tlds) map[t.toLowerCase()] = urls[0];
  }
  cache.tlds = map;
  cache.at = Date.now();
  return map;
}

export async function rdapLookup(domain) {
  const tld = domain.split(".").pop().toLowerCase();
  const map = await bootstrap();
  const base = map[tld];
  if (!base) throw new Error(`no RDAP for .${tld}(该 TLD 无 RDAP 服务,如 .cn;用 whois 直查道)`);
  const r = await fetch(`${base.replace(/\/$/, "")}/domain/${domain}`, { headers: { Accept: "application/rdap+json" } });
  if (r.status === 404) throw new Error(`not found: ${domain}`);
  if (!r.ok) throw new Error(`rdap http ${r.status}`);
  return await r.json();
}

// 结构化提取(与 nsm intel 的 vt.ts 面对齐)
export function rdapSummary(j) {
  const pick = (type) => (j.events ?? []).filter((e) => e.eventAction === type).map((e) => e.eventDate)[0];
  return {
    domain: j.ldhName,
    registrar: (j.entities ?? []).find((e) => (e.roles ?? []).includes("registrar"))?.vcardArray?.[1]?.find((x) => x[0] === "fn")?.[3] ?? null,
    createdAt: pick("registration"),
    expiresAt: pick("expiration"),
    updatedAt: pick("last changed"),
    status: j.status ?? [],
    nameservers: (j.nameservers ?? []).map((n) => n.ldhName).filter(Boolean),
  };
}
