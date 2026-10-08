// RDAP 443 备选道:本站 TCP 43 被拦时走 RDAP(fetch,HTTPS 443)。IANA bootstrap 发现注册局。
// 双对象道:域名走 dns.json(TLD 键),IPv4/IPv6 走 ipv4.json/ipv6.json(CIDR 最长前缀匹配;
// 2026-10-08 补,此前 IP 查询误用末段当 TLD 报「无 RDAP」)。
const BOOTSTRAP_DNS = "https://data.iana.org/rdap/dns.json";
const BOOTSTRAP_V4 = "https://data.iana.org/rdap/ipv4.json";
const BOOTSTRAP_V6 = "https://data.iana.org/rdap/ipv6.json";
const DAY_MS = 86400_000;
const cache = { tlds: null, v4: null, v6: null, at: { tlds: 0, v4: 0, v6: 0 } };

async function fetchBootstrap(kind, url) {
  const at = cache.at[kind] ?? 0;
  if (cache[kind] && Date.now() - at < DAY_MS) return cache[kind];
  const r = await fetch(url);
  const j = await r.json();
  cache[kind] = j.services ?? [];
  cache.at[kind] = Date.now();
  return cache[kind];
}

/** 域名道:dns.json 展开成 TLD -> 首个服务 URL。 */
async function tldMap() {
  const services = await fetchBootstrap("tlds", BOOTSTRAP_DNS);
  const map = {};
  for (const svc of services) for (const t of svc[0]) map[t.toLowerCase()] = svc[1][0];
  return map;
}

function ipToInt(ip) {
  // v4 直转 uint32;v6 走 BigInt(128 位)
  if (ip.includes(":")) {
    const groups = ip.split("::");
    const head = groups[0] ? groups[0].split(":").filter(Boolean) : [];
    const tail = groups[1] !== undefined && groups[1] !== "" ? groups[1].split(":").filter(Boolean) : [];
    const fill = 8 - head.length - tail.length;
    const parts = [...head, ...Array(Math.max(fill, 0)).fill("0"), ...tail];
    return parts.reduce((acc, p) => (acc << 16n) + BigInt(parseInt(p || "0", 16)), 0n);
  }
  return ip.split(".").reduce((acc, o) => (acc << 8n) + BigInt(Number(o) || 0), 0n);
}

function prefixLenOf(cidr) {
  return Number(cidr.split("/")[1] ?? (cidr.includes(":") ? 128 : 32));
}

/** IP 道:bootstrap 的 CIDR 清单按最长前缀匹配取服务 URL。 */
async function ipService(ip) {
  const isV6 = ip.includes(":");
  const services = await fetchBootstrap(isV6 ? "v6" : "v4", isV6 ? BOOTSTRAP_V6 : BOOTSTRAP_V4);
  const bits = isV6 ? 128n : 32n;
  const val = ipToInt(ip);
  let best = null;
  let bestLen = -1;
  for (const svc of services) {
    for (const cidr of svc[0]) {
      const pl = prefixLenOf(cidr);
      if (pl <= bestLen) continue;
      const mask = pl === 0 ? 0n : ((1n << BigInt(pl)) - 1n) << (bits - BigInt(pl));
      const net = cidr.split("/")[0];
      if ((val & mask) === (ipToInt(net) & mask)) {
        best = svc[1][0];
        bestLen = pl;
      }
    }
  }
  return best;
}

const IPV4_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;
const IPV6_RE = /^[0-9a-fA-F:]+$/;

function isIp(q) {
  return IPV4_RE.test(q) || (q.includes(":") && IPV6_RE.test(q));
}

export async function rdapLookup(query) {
  const accept = { headers: { Accept: "application/rdap+json" } };
  if (isIp(query)) {
    const base = await ipService(query);
    if (!base) throw new Error(`no RDAP service covers ${query}`);
    const r = await fetch(`${base.replace(/\/$/, "")}/ip/${query}`, accept);
    if (r.status === 404) throw new Error(`not found: ${query}`);
    if (!r.ok) throw new Error(`rdap http ${r.status}`);
    return await r.json();
  }
  const tld = query.split(".").pop().toLowerCase();
  const map = await tldMap();
  const base = map[tld];
  if (!base) throw new Error(`no RDAP for .${tld}(该 TLD 无 RDAP 服务,如 .cn;用 whois 直查道)`);
  const r = await fetch(`${base.replace(/\/$/, "")}/domain/${query}`, accept);
  if (r.status === 404) throw new Error(`not found: ${query}`);
  if (!r.ok) throw new Error(`rdap http ${r.status}`);
  return await r.json();
}

// 结构化提取(与 nsm intel 的 vt.ts 面对齐;IP 对象无 registrar/nameservers,取网络面)
export function rdapSummary(j) {
  const pick = (type) => (j.events ?? []).filter((e) => e.eventAction === type).map((e) => e.eventDate)[0];
  const isIpObj = Array.isArray(j?.handle) === false && (j?.objectClassName ?? "") === "ip network";
  if (isIpObj) {
    return {
      network: j.name ?? null,
      type: j.type ?? null,
      country: j.country ?? null,
      range: j.startAddress && j.endAddress ? `${j.startAddress} - ${j.endAddress}` : null,
      remarks: (j.remarks ?? []).map((r) => (r.description ?? []).join(" ")).filter(Boolean),
    };
  }
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
