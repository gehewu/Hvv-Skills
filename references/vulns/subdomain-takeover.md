# 子域接管（指纹 / 验证 / 利用）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---



## Subdomain Takeover — Detection & Exploitation Playbook


## 1. CORE CONCEPT

Subdomain takeover occurs when:

1. `sub.target.com` has a DNS record (CNAME, NS, A) pointing to an external service
2. The external resource is **no longer provisioned** (deleted S3 bucket, removed Heroku app, etc.)
3. The attacker can **register/claim** that exact resource name on the provider
4. The attacker now controls content served under `sub.target.com`

**Impact**: cookie theft (parent domain cookies), OAuth token interception, phishing under trusted domain, CSP bypass via whitelisted subdomain.  
（历史文案里的 CORS bypass：仅作危害链理解；**护网不单独挖/写 CORS**。）

---

## 2. DETECTION METHODOLOGY

### 2.1 CNAME Enumeration

```
1. Collect subdomains (amass, subfinder, assetfinder, crt.sh, SecurityTrails)
2. Resolve DNS for each:
   dig CNAME sub.target.com +short
3. For each CNAME → check if the CNAME target returns NXDOMAIN or a provider error
4. Match error response against fingerprint table (Section 3)
```

### 2.2 Key Signals

| Signal | Meaning |
|---|---|
| CNAME → `xxx.s3.amazonaws.com` + HTTP 404 "NoSuchBucket" | S3 bucket deleted, claimable |
| CNAME → `xxx.herokuapp.com` + "No such app" | Heroku app deleted |
| CNAME → `xxx.github.io` + 404 "There isn't a GitHub Pages site here" | GitHub Pages unclaimed |
| NXDOMAIN on the CNAME target domain itself | Target domain expired or never existed |
| CNAME → provider but HTTP 200 with default parking page | May or may not be claimable — verify |

### 2.3 Automated Tools

| Tool | Purpose |
|---|---|
| `subjack` | Automated CNAME takeover checking |
| `nuclei -t takeovers/` | Nuclei takeover detection templates |
| `can-i-take-over-xyz` (GitHub) | Reference for which services are vulnerable |
| `dnsreaper` | Multi-provider takeover scanner |
| `subzy` | Fast subdomain takeover verification |

---

## 3. SERVICE PROVIDER FINGERPRINT TABLE

| Provider | CNAME Pattern | Fingerprint (HTTP Response) | Claimable? |
|---|---|---|---|
| **AWS S3** | `*.s3.amazonaws.com` / `*.s3-website-*.amazonaws.com` | `NoSuchBucket` (404) | Yes — create bucket with matching name |
| **GitHub Pages** | `*.github.io` | `There isn't a GitHub Pages site here` (404) | Yes — create repo + enable Pages |
| **Heroku** | `*.herokuapp.com` / `*.herokudns.com` | `No such app` | Yes — create app with matching name |
| **Azure** | `*.azurewebsites.net` / `*.cloudapp.azure.com` / `*.trafficmanager.net` | Various default pages, NXDOMAIN | Yes — register matching resource |
| **Shopify** | `*.myshopify.com` | `Sorry, this shop is currently unavailable` | Yes — create shop, add custom domain |
| **Fastly** | CNAME to Fastly edge | `Fastly error: unknown domain` | Yes — add domain to Fastly service |
| **Pantheon** | `*.pantheonsite.io` | `404 Site Not Found` with Pantheon branding | Yes |
| **Tumblr** | `*.tumblr.com` (custom domain CNAME) | `There's nothing here` / `Whatever you were looking for doesn't exist` | Yes |
| **WordPress.com** | CNAME to `*.wordpress.com` | `Do you want to register` | Yes — claim domain in WP.com |
| **Zendesk** | `*.zendesk.com` | `Help Center Closed` / Zendesk branding on error | Yes — create matching subdomain |
| **Unbounce** | `*.unbouncepages.com` | `The requested URL was not found` | Yes |
| **Ghost** | `*.ghost.io` | `404 Not Found` Ghost error | Yes |
| **Surge.sh** | `*.surge.sh` | `project not found` | Yes |
| **Fly.io** | CNAME to `*.fly.dev` | Fly.io default 404 | Yes |

---

## 4. TAKEOVER PROCEDURE — COMMON PROVIDERS

### 4.1 AWS S3

```
1. Confirm: curl -s http://sub.target.com → "NoSuchBucket"
2. Extract bucket name from CNAME (e.g., sub.target.com.s3.amazonaws.com → bucket = "sub.target.com")
3. aws s3 mb s3://sub.target.com --region <region>
4. Upload index.html proving control
5. Enable static website hosting
```

### 4.2 GitHub Pages

```
1. Confirm: curl -s https://sub.target.com → "There isn't a GitHub Pages site here"
2. Create GitHub repo (any name)
3. Add CNAME file containing "sub.target.com"
4. Enable GitHub Pages in repo settings
5. Wait for DNS propagation (GitHub verifies CNAME match)
```

### 4.3 Heroku

```
1. Confirm: curl -s http://sub.target.com → "No such app"
2. heroku create <app-name-from-cname>
3. heroku domains:add sub.target.com
4. Deploy proof-of-concept page
```

---

## 5. NS TAKEOVER — HIGH SEVERITY

NS takeover is **far more dangerous** than CNAME takeover: you control **all DNS resolution** for the zone.

### How It Happens

```
target.com NS → ns1.expireddomain.com
                 ↓
attacker registers expireddomain.com
                 ↓
attacker now controls ALL DNS for target.com
(A records, MX records, TXT records — everything)
```

### Detection

```
1. Enumerate NS records: dig NS target.com +short
2. Check each NS domain: whois ns1.example.com → is the domain expired or available?
3. Also check: dig A ns1.example.com → NXDOMAIN/SERVFAIL?
4. Subdelegated zones: check NS for sub.target.com specifically
```

### Impact

- Full domain takeover (serve any content, intercept email, issue TLS certs via DNS-01)
- Issue DV certificates from any CA using DNS challenge
- Modify SPF/DKIM/DMARC → send authenticated email as target

---

## 6. MX TAKEOVER — EMAIL INTERCEPTION

When MX records point to deprovisioned mail services:

```
target.com MX → mail.deadservice.com (service discontinued)
```

If attacker can claim `mail.deadservice.com` or the mail tenant:
- Receive password reset emails
- Intercept sensitive communications
- Potentially reset accounts that use email-based auth

### Common Scenario

Expired Google Workspace / Microsoft 365 tenant → MX still points to Google/Microsoft → attacker creates new tenant and claims the domain.

---

## 7. WILDCARD DNS RISKS

If `*.target.com` has a wildcard CNAME to a claimable service:
- **Every** undefined subdomain is vulnerable
- `anything.target.com` can be taken over
- Massively increases attack surface

Detection: `dig A random1234567.target.com` — if it resolves, wildcard exists.

---

## 8. DETECTION & EXPLOITATION DECISION TREE

```
Subdomain discovered (sub.target.com)?
├── Resolve DNS records
│   ├── Has CNAME → external service?
│   │   ├── HTTP response matches known fingerprint? (Section 3)
│   │   │   ├── YES → Attempt claim on provider (Section 4)
│   │   │   │   ├── Claim successful → TAKEOVER CONFIRMED
│   │   │   │   └── Claim blocked (name reserved, region locked) → document, try variations
│   │   │   └── NO → Service active, no takeover
│   │   └── CNAME target NXDOMAIN?
│   │       ├── Target is a registrable domain? → Register it → full control
│   │       └── Target is a subdomain of active provider → check provider claim process
│   │
│   ├── Has NS records → external nameserver?
│   │   ├── NS domain expired/available? → Register → FULL ZONE TAKEOVER
│   │   └── NS domain active → no takeover
│   │
│   ├── Has MX → external mail service?
│   │   ├── Mail service deprovisioned/claimable? → Claim tenant → EMAIL INTERCEPTION
│   │   └── Active mail service → no takeover
│   │
│   └── Has A record → IP address?
│       ├── IP belongs to elastic cloud (AWS EIP, Azure, GCP)?
│       │   ├── IP unassigned? → Claim IP → serve content
│       │   └── IP assigned to another customer → no takeover
│       └── IP belongs to dedicated server → no takeover
│
└── Post-takeover impact assessment
    ├── Shared cookies with parent domain? → Session hijacking
    ├── （勿单独报 CORS）子域 XSS / 接管后的敏感读/写 → 写主业务洞
    ├── CSP whitelists *.target.com? → XSS via taken-over subdomain
    ├── OAuth redirect_uri allows sub.target.com? → Token theft
    └── Can issue TLS cert for sub.target.com? → Full MITM
```

---

## 9. DEFENSE & REMEDIATION

| Action | Priority |
|---|---|
| Remove DNS records when deprovisioning cloud resources | Critical |
| Monitor CNAME targets for NXDOMAIN responses | High |
| Use DNS monitoring tools (SecurityTrails, DNSHistory) | High |
| Claim/reserve resource names before deleting DNS records | High |
| Audit NS delegations — ensure NS domains are owned and renewed | Critical |
| Avoid wildcard CNAMEs to third-party services | Medium |
| Implement Certificate Transparency monitoring | Medium |

---

## 10. TRICK NOTES — WHAT AI MODELS MISS

1. **CNAME ≠ takeover**: A CNAME to S3 that returns 403 (bucket exists, private) is NOT vulnerable. Only `NoSuchBucket` (404) is.
2. **Region matters for S3**: Bucket names are global, but website endpoints are regional. Try matching the region from the CNAME.
3. **GitHub Pages verification**: GitHub added domain verification — org-verified domains cannot be claimed by others. Check if target uses this.
4. **Edge cases**: Some providers (e.g., Cloudfront) require specific distribution configuration, not just domain claiming.
5. **Second-order takeover**: `sub.target.com CNAME → other.target.com CNAME → dead-service.com` — the chain must be followed fully.
6. **SPF subdomain takeover**: If SPF includes `include:sub.target.com` and you take over `sub.target.com`, you can modify its SPF TXT record to authorize your mail server → send spoofed email as `target.com`.


---

## 补充与进阶

## 子域名枚举实战参考
- 子域名 Web 指纹识别 → `../recon/info-fingerprint.md`
- 目录/文件爆破 → `../recon/info-dir-brute.md`

> 分类: 证书透明 → DNS → 字典爆破 → 搜索引擎 → 工具链

> **last_updated**: 2026-06-04 | **tested_against**: Amass 4.x, Subfinder 2.x, crt.sh, DNSRecon
---

---

## 1. 工具链速查

---

### 1.1 常用工具对比

| 工具 | 速度 | 发现量 | 特点 |
|------|------|--------|------|
| **subfinder** | 快 | 中 | 被动收集 (证书+API), 不主动爆破 |
| **amass** | 慢 | 多 | 全面, 被动+主动, OWASP维护 |
| **assetfinder** | 快 | 中 | 轻量, 被动收集 |
| **findomain** | 快 | 中 | 证书透明+API |
| **shuffledns** | 中 | 多 | 纯DNS解析, 配合massdns |
| **dnsx** | 快 | — | DNS工具集, 配合其他用 |
| **chaos** | — | 多 | ProjectDiscovery的公共数据集 |

---

### 1.2 组合命令 (推荐)

```bash

---

# === 第一步: 被动收集 (不产生大流量, 快速) ===
subfinder -d target.com -o subs_passive.txt
assetfinder --subs-only target.com >> subs_passive.txt
findomain -t target.com -q >> subs_passive.txt

---

# 去重
sort -u subs_passive.txt -o subs_unique.txt

---

# === 第二步: DNS 解析 (确认存活) ===
dnsx -l subs_unique.txt -resp-only -o subs_alive.txt

---

# === 第三步: 主动爆破 (可选, 动静大) ===

---

# 需要好的字典
shuffledns -d target.com -w subdomains-top1million-5000.txt -r resolvers.txt -o subs_brute.txt

---

# === 第四步: 合并 + 解析 + HTTP探测 ===
cat subs_alive.txt subs_brute.txt | sort -u | dnsx -resp-only | httpx -o subs_http.txt
```

---

---

## 2. 证书透明 (Certificate Transparency)

---

### 2.1 crt.sh

```bash

---

# 在线查看: https://crt.sh/?q=%25.target.com

---

# API 方式获取:
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

---

# 或一行:
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | tr '\n' '\n' | sed 's/^\*\.//' | sort -u > crtsh_subs.txt
```

---

### 2.2 其他证书源

```bash

---

# Google Transparency Report

---

# https://transparencyreport.google.com/https/certificates

---

# Facebook Certificate Transparency
curl -s "https://developers.facebook.com/tools/ct/search/?query=target.com" | grep -oP '[a-zA-Z0-9.-]+\.target\.com' | sort -u

---

# CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u
```

---

---

## 3. DNS 爆破

---

### 3.1 字典

```bash

---

# 推荐字典:

---

# 1. SecLists: https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS

---

# 2. Assetnote: https://wordlists-cdn.assetnote.io/data/automated.json

---

# 3. jhaddix all.txt: 聚合字典

---

# 首先用小字典 (top 5000)
shuffledns -d target.com -w subdomains-top1million-5000.txt -r resolvers.txt

---

# 然后针对大企业用大字典 (top 100k+)
shuffledns -d target.com -w all.txt -r resolvers.txt -o subs_dns_brute.txt
```

---

### 3.2 置换扫描 (Permutation)

```bash

---

# 对已知子域名做置换 (dev/staging/test/etc.)

---

# 已知: www.target.com, api.target.com

---

# 生成: dev.www.target.com, staging.api.target.com, www-dev.target.com...

---

# 工具: gotator / altdns
gotator -sub subs_alive.txt -perm permutations.txt -depth 1 -numbers 10 -o perm_subs.txt

---

# 然后解析:
dnsx -l perm_subs.txt -resp-only -o perm_alive.txt
```

---

---

## 4. DNS 区域传送 (Zone Transfer)

```bash

---

# === 尝试 AXFR ===
dig axfr @ns1.target.com target.com
dig axfr @dns.target.com target.com

---

# === 遍历所有 NS ===
for ns in $(dig +short NS target.com); do
  echo "=== $ns ==="
  dig axfr @$ns target.com
done
```

---

---

## 5. 搜索引擎 + 第三方

```bash

---

# === Google Hacking ===
site:*.target.com
site:target.com -www

---

# === Shodan ===
hostname:target.com
ssl:target.com
ssl.cert.subject.cn:target.com

---

# === FOFA ===
domain="target.com" && cert="target.com"

---

# === VirusTotal ===
https://www.virustotal.com/gui/domain/target.com/relations

---

# → subdomains 选项卡

---

# === SecurityTrails ===
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: your-key" | jq -r '.subdomains[]' | sed "s/$/.target.com/"

---

# === AlienVault OTX ===
curl -s "https://otx.alienvault.com/api/v1/indicators/domain/target.com/passive_dns" | jq -r '.passive_dns[].hostname' | sort -u

---

# === Chaos (ProjectDiscovery) ===
chaos -d target.com -o chaos_subs.txt
```

---

---

## 6. 子域名信息扩展

---

### 6.1 HTTP 探测

```bash

---

# 识别 Web 服务
cat subs_alive.txt | httpx -title -status-code -tech-detect -o http_info.txt

---

# 截图 (看长什么样的网站)
cat http_info.txt | aquatone -out aquatone_output

---

# 按状态码分类:
grep "200" http_info.txt > web_200.txt
grep "403" http_info.txt > web_403.txt   # 403可能是敏感后台
grep "401" http_info.txt > web_401.txt
```

---

### 6.2 端口扫描 (子域名)

```bash

---

# 对解析出的 IP 扫端口
cat subs_alive.txt | dnsx -a -resp-only | sort -u > ips.txt
nmap -sS -sV -p 21,22,80,443,8080,8443,9090 -iL ips.txt -T4 -oA nmap_subs
```

---

### 6.3 目录爆破 (Top 子域名)

```bash

---

# 优先爆破 200 OK + 有趣标题的子域名
cat web_200.txt | head -20 | while read url; do
  ffuf -u "$url/FUZZ" -w common.txt -o ffuf_$(echo $url | md5sum | cut -c1-8).json
done
```

---

---

## 7. 快速参考

```bash

---

# === 30秒快速收集 ===
subfinder -d target.com -silent
assetfinder --subs-only target.com

---

# === 5分钟标准收集 ===
subfinder -d target.com | anew subs.txt
assetfinder --subs-only target.com | anew subs.txt
findomain -t target.com -q | anew subs.txt
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | anew subs.txt
dnsx -l subs.txt -resp-only -o subs_alive.txt
httpx -l subs_alive.txt -o subs_http.txt

---

# 看结果:
wc -l subs*.txt
cat subs_http.txt
```

---

---

## 8. 子域名接管 (Subdomain Takeover)

> 原理: CNAME 指向已释放的第三方服务（GitHub Pages/Heroku/S3/OSS 等）→ 攻击者注册同名资源即可接管该子域名。
> 价值: 钓鱼/窃取主域 Cookie（作用域为父域时）/ 绕过 CSP — 接管成功且有实际影响按 🟡中危 起步报告。

```bash

---

# === 检测流程 ===

---

# 1. 收集所有子域名的 CNAME 记录
dnsx -l subs.txt -cname -resp -o cnames.txt

---

# 2. 匹配悬空指纹 — 自动化工具
subzy run --targets subs_alive.txt          # 快速
nuclei -l subs_alive.txt -tags takeover     # 模板化

---

# 3. 人工确认（必须）: 访问子域名看服务商的错误页特征

---

# GitHub Pages → "There isn't a GitHub Pages site here"

---

# S3/OSS      → NoSuchBucket

---

# Heroku      → "No such app"

---

# Azure       → "404 Web Site not found"
```

> ⚠️ 工具告警必须人工访问确认；仅在能注册接管（或明确展示服务商已释放）时报告，"可能可接管"不报。

---

---

## 相关参考
- 子域名 Web 指纹识别 → `../recon/info-fingerprint.md`
- 目录/文件爆破 → `../recon/info-dir-brute.md`

*参考: Subfinder + Amass + Assetfinder + 实战*