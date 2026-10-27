# vulns/ — 漏洞技能统一目录

> 一个漏洞一个文件，按场景取用；不要一次通读整个目录。
> 授权、ROE、留痕、报告见 `../hw-rules/`；进站先读 `手法索引.md`。

---

## 1. 核心漏洞

| 文件 | 内容 |
|---|---|
| `injection.md` | SQL / NoSQL / LDAP / XPath / EL / 命令 / SSTI |
| `rce.md` | 命令执行 / 无回显 / 反弹 / 应用 RCE / 绕过 |
| `xss.md` | 反射 / 存储 / DOM / CSP / XSS→RCE |
| `ssrf.md` | 内网 / 云元数据 / Gopher / 盲打 |
| `xxe.md` | 文件读取 / Blind OOB / XInclude / Office / SAML |
| `auth-idor.md` | IDOR / 垂直水平越权 / 任意登录 / 会话 |
| `file-upload.md` | 后缀 / 内容 / 解析 / 竞态 / 对象存储 |
| `path-traversal-lfi.md` | 穿越 / LFI / 伪协议 / 日志投毒 |
| `403-bypass.md` | 401/403 分层绕过 |
| `waf-bypass.md` | 编码 / 协议 / 语义 / HPP |
| `logic-race.md` | 支付 / 券 / 库存 / 并发 |
| `csrf.md` | Token / SameSite / JSON / CSWSH |
| `http-protocol.md` | CRLF / Host / 走私 / 缓存投毒 |
| `graphql.md` | 内省 / 越权 / 注入 / 批量 |
| `jwt-oauth.md` | 算法 / 弱钥 / 流程 / 接管 |
| `deserialization.md` | PHP / Java / Python / .NET / Node |
| `subdomain-takeover.md` | 指纹 / 验证 / 利用 |
| `info-leak.md` | 配置 / 源码 / 密钥 / 内部数据 |
| `cors.md` | CORS（护网默认不挖，仅参考） |

## 2. 专项

| 文件 | 内容 |
|---|---|
| `api-gateway.md` | API 网关 / 微服务 |
| `websocket.md` | WebSocket |
| `prototype-pollution.md` | 原型链污染 |
| `type-juggling.md` | 类型杂耍 |
| `jndi-injection.md` | JNDI 注入 |
| `cloud-ide.md` | 云 IDE / Codex RPC 链 |
| `agent-tool-exec.md` | 对话口工具真执行 |
| `insecure-scm.md` | 不安全 SCM |
| `dependency-confusion.md` | 依赖混淆 |
| `ghost-bits.md` | Ghost Bits |
| `csv-formula.md` | CSV 公式注入 |
| `dangling-markup.md` | Dangling markup |
| `email-header.md` | 邮件头注入 |
| `clickjacking.md` | 点击劫持 |
| `open-redirect.md` | 开放重定向 |
| `http2.md` | HTTP/2 攻击 |
| `hpp.md` | HTTP 参数污染（不单交） |
| `xslt-injection.md` | XSLT 注入（占位） |
| `llm-security.md` | LLM 安全（非护网目标，仅存档） |
| `js-reverse-guide.md` | JS 逆向 |
| `low-value.md` | 低价值类报告门槛 |

## 3. 护网补充

| 文件 | 内容 |
|---|---|
| `手法索引.md` | 手法索引，进站先看 |
| `boundary-devices.md` | VPN / OA / 邮件 / 网关 / 域控 / 中间件 |
| `honeypot-recognition.md` | 蜜罐识别（红队）与运用（蓝队） |

---

## 4. 使用

1. 进站先读 `手法索引.md`，对得上再开对应文件。
2. 每个文件按“检测 → 利用/绕过 → 工具 → 假点/停止 → 护网注意”组织。
3. 护网红线（授权/ROE/留痕/报告）始终走 `../hw-rules/`。
4. 占位文件（如 `hpp.md`、`http2.md`、`clickjacking.md`）只写“默认不交/并回父主题”，需要细节时看对应主文件。