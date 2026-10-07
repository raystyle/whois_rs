# whois_rs — WHOIS 绑定(napi-rs)

WHOIS over TCP 43 的原生 Node 模块:Rust 内核(whois-rust 3.1.0),TypeScript 只见
`lookup(query: string): Promise<string>`。

## 架构

- **AsyncTask 而非 async fn**:同步 lookup 是阻塞 TCP,工作丢 libuv 线程池
  (不用 napi async fn 套 tokio,双运行时打架;用户蓝图裁定)
- **servers.json 编进二进制**:`include_str!`,安装后无需找文件(node-whois 上游列表)
- **Lazy 全局 WhoIs 实例**:`once_cell::sync::Lazy`,首次调用初始化

## 用法

```ts
import { lookup } from "@d3fend/whois-binding";
const raw = await lookup("d3fend.cn"); // 原始 whois 文本
```

调用方注意:
- **并发限制**:libuv 默认线程池 4,批量 WHOIS 会占满池;JS 侧信号量(≤8)自制
- **缓存自制**:返回值是原始文本;结构化解析留在 TS 侧
- **网络前提**:TCP 43 出站可达(wrt tproxy 会拦 43 口,经 pi-server/云侧道可达)
- **Edge/浏览器不适用**:无 TCP 43,走 RDAP fetch

## 构建

```bash
napi build --platform --release   # 本机
napi build --target x86_64-unknown-linux-musl --release  # 交叉目标
napi artifacts   # 收 .node
napi prepublish -t npm  # 发平台包(optionalDependencies 形态)
```

MSRV: rustc 1.89+(whois-rust 3.1.0 的 MSRV;CI 固定 1.89.0)。

napi CLI 3.x 产物名坑(2026-10-08 CI 实证):`napi build --target X` 产物恒为裸
`whois-binding.node`(加载器与 `napi artifacts` 只认平台限定名)——CI 每腿 build 后
按 abi 改名;`napi artifacts` 要求 artifacts/ 下全目标限定名在场,download-artifact
禁 merge-multiple(裸名六腿相撞);aarch64-gnu 交叉需显式
`CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc`。

## 实测(2026-10-07)

- pi-server(SG):d3fend.cn 381B(Registration data)、IP 1.1.1.1 3017B(arin)、example.com 233B(iana)✓
- 本站(wrt tproxy 后):TCP 43 被拦(os error 11 EAGAIN)→ 经 mesh 云侧道跑

## 分发形态

`package.json` napi.targets 六平台;每个平台一个 `.node` 经 optionalDependencies 分发,
根包只带 index.js/d.ts/servers.json。

## RDAP 443 备选道(rdap.mjs)

TCP 43 被拦的网络(本站 wrt tproxy)走 RDAP(HTTPS 443,fetch 原生):

```ts
import { rdapLookup, rdapSummary } from "./rdap.mjs";
const j = await rdapLookup("example.com");  // 原始 RDAP JSON
const s = rdapSummary(j);                    // 结构化:registrar/createdAt/expiresAt/status/nameservers
```

- IANA bootstrap 发现注册局(data.iana.org/rdap/dns.json,缓存 24h)
- **覆盖缺口**:.cn 等部分 TLD 无 RDAP 服务(报错明示,应转 whois 直查道)
- 实测:example.com 全字段绿(本站 443 道畅通)
