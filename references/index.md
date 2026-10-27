# 知识库总索引

> 先读 `../SKILL.md`，再按场景取文件。不要一次通读全部。

---

## 0. 规则（必读）

| 文件 | 一句话 |
|------|--------|
| `hw-rules/authorization-scope.md` | 授权、范围、越界处置、靶标队列 |
| `hw-rules/rules-of-engagement.md` | ROE、禁止项、扫描节奏、内网约束、清理 |
| `hw-rules/evidence-and-trace.md` | 留痕、证据链、凭证管理、脱敏 |
| `hw-rules/collaboration.md` | 多小组、线程交接、报备、同步 |
| `hw-rules/report-format.md` | 护网报告、日报、成果表、定级 |
| `hw-rules/workflow.md` | 靶标闭环、进站矩阵、同闸、肥瘦、升链 |

---

## 1. 资产测绘（recon）

| 文件 | 内容 |
|------|------|
| `recon/asset-mapping.md` | **总方法论（先读）**：Phase 0～6、红蓝用法 |
| `recon/decisions.md` | 404 分类、存活分级、403/404 扫描决策、硬封锁 |
| `recon/expansion.md` | 前端反推、二级目录、影子/边缘、废弃系统、反代、供应链、子系统、C/B 端、运维视角 |
| `recon/correlation.md` | 关联维度、攻击路径推演 |
| `recon/recon-tools.md` | crt.sh、Fofa、Hunter、Shodan、被动 DNS、CLI、Luvv-MCP |
| `recon/info-port-scan.md` | 端口扫描与服务识别 |
| `recon/info-subdomain.md` | 子域名枚举与接管检测 |
| `recon/info-dir-brute.md` | 目录/文件爆破 |
| `recon/info-fingerprint.md` | Web 指纹 |
| `recon/info-osint.md` | OSINT |

---

## 2. 漏洞技能（vulns）

> 漏洞知识统一在 `vulns/`；一个漏洞一个文件。完整索引见 `vulns/README.md`；进站先读 `vulns/手法索引.md`。

### 核心
| 文件 | 内容 |
|------|------|
| `vulns/injection.md` | 注入族（SQL/NoSQL/LDAP/XPath/EL/命令/SSTI） |
| `vulns/rce.md` | RCE / 命令执行 / 反弹 / 应用 RCE |
| `vulns/xss.md` | XSS（反射/存储/DOM/CSP/XSS→RCE） |
| `vulns/ssrf.md` | SSRF（内网/云元数据/Gopher/盲打） |
| `vulns/xxe.md` | XXE（文件读取/Blind OOB/XInclude/Office/SAML） |
| `vulns/auth-idor.md` | 越权/认证接管 |
| `vulns/file-upload.md` | 文件上传 |
| `vulns/path-traversal-lfi.md` | 路径穿越/LFI |
| `vulns/403-bypass.md` | 401/403 绕过 |
| `vulns/waf-bypass.md` | WAF 绕过 |
| `vulns/logic-race.md` | 业务逻辑/竞态 |
| `vulns/csrf.md` | CSRF |
| `vulns/http-protocol.md` | CRLF/Host/走私/缓存 |
| `vulns/graphql.md` | GraphQL |
| `vulns/jwt-oauth.md` | JWT/OAuth |
| `vulns/deserialization.md` | 反序列化 |
| `vulns/subdomain-takeover.md` | 子域接管 |
| `vulns/info-leak.md` | 信息泄露 |
| `vulns/cors.md` | CORS（默认不挖） |

### 专项
`vulns/api-gateway.md`、`websocket.md`、`prototype-pollution.md`、`type-juggling.md`、`jndi-injection.md`、`cloud-ide.md`、`agent-tool-exec.md`、`insecure-scm.md`、`dependency-confusion.md`、`ghost-bits.md`、`csv-formula.md`、`dangling-markup.md`、`email-header.md`、`clickjacking.md`、`open-redirect.md`、`http2.md`、`hpp.md`、`xslt-injection.md`、`llm-security.md`、`js-reverse-guide.md`、`low-value.md`

### 护网补充
`vulns/手法索引.md`、`vulns/boundary-devices.md`、`vulns/honeypot-recognition.md`

---

## 3. 内网 / 后渗透（post）

| 文件 | 内容 |
|------|------|
| `post/linux-privesc.md` | Linux 提权 |
| `post/windows-privesc.md` | Windows 提权 |
| `post/credential-access.md` | 凭据窃取 / 横向 |
| `post/domain-pentest.md` | 域渗透 |
| `post/evasion.md` | 免杀 / 低特征 |
| `post/host-brute.md` | 密码爆破 |

---

## 4. 工具（tools）

`tools/tools-nmap.md`、`tools-sqlmap.md`、`tools-msf.md`、`tools-impacket.md`、`tools-hydra.md`、`tools-fuzz.md`

---

## 5. 蓝队（defense）

| 文件 | 内容 |
|------|------|
| `defense/self-assessment.md` | 资产自查、暴露面收敛、整改复测 |
| `defense/alert-triage.md` | 告警研判 |
| `defense/incident-response.md` | 应急响应、溯源、反制边界 |
