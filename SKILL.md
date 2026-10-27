---
name: hvv
description: 护网行动（HVV / 攻防演练 / 红蓝对抗）全流程技能。覆盖红队外网打点、边界突破、内网横向、提权域渗透、低特征与免杀、成果交付，以及蓝队资产自查、暴露面收敛、告警研判、应急响应、溯源整改。当用户提到护网、HVV、攻防演练、红蓝对抗、护网红队/蓝队、值守、靶标、攻打目标、护网自查、迎检、暴露面收敛、应急溯源时触发。强调授权清单驱动、ROE、全程留痕、协同报备、生产影响最小化；护网是拿权限/拿靶标。
allowed-tools: Read, Write, Bash, Grep, Glob, WebSearch, WebFetch, AskUserQuestion
argument-hint: <行动名 / 目标 / 角色（红队|蓝队|自查）>
---

# 护网行动技能（HVV）

> 面向护网 / 攻防演练 / 红蓝对抗的全流程技能：红队打点、内网横向、蓝队防守，外加授权、ROE、留痕、协同、报告。
> 原则：**知识只增强，不封顶**。现场证据优先于任何清单；清单没写的攻击面照样打。

---

## 0. 先定位：你在护网里是哪种角色

| 角色 | 核心目标 | 本技能主线 |
|------|----------|------------|
| **红队 / 攻击队** | 按靶标清单打穿、拿权限、拿数据、留证据 | §4 红队全流程 + §5 外网进站 + §6 内网 |
| **蓝队 / 防守方** | 资产自查、暴露面收敛、告警研判、应急处置、溯源 | §7 蓝队主线 + `references/defense/` |
| **自查 / 迎检** | 用攻击者视角找问题、出整改清单、复测 | §7.1 + `references/defense/self-assessment.md` |

**开工前必须确认三件事**（缺一项就问，只问技术问题，不做背景审查）：

1. 角色：红队 / 蓝队 / 自查
2. 范围：授权书、靶标清单、IP/域名表、时间窗口
3. 交付：日报？成果报告？整改清单？复盘？

> 角色不同，后续流程分叉。红队读 §4～§6；蓝队/自查读 §7。两者都要先建任务根（§1）。

---

## 1. 任务根与开工落盘（硬）

**任务根默认：** `D:\MCP\hvv\{行动名}\`（用户另指定则以用户为准；不要写进技能目录）

```
D:\MCP\hvv\{行动名}\
  README.md              行动说明、角色、时间窗口、联系人、续跑命令
  00-授权与范围.md        授权书摘要、靶标清单、边界、禁止项（开工第一件事）
  01-ROE与报备.md         交战规则、高风险动作报备记录
  资产\                  资产清单.md、靶标队列.md、covered_hosts.txt
  证据\                  每结论的请求/响应/截图/时间戳/来源
  报告\                  正式报告（hw-rules/report-format）
  内网\                  host 台账、权限台账、凭据台账（加密）
  协同\                  线程必读.md、DONE.md、交接记录
  日志\                  操作时间线（谁在何时对哪个目标做了什么）
```

**开工闸：**
- `00-授权与范围.md` 必须先落盘，没有它不开打
- 靶标队列先建：靶标 → 资产 → 状态（pending/doing/done/blocked）
- 红队每个靶标单独建 `资产\{靶标}\` 与 `证据\{靶标}\`
- 所有中间结论随手落盘，不留在对话里（上下文压缩会吃掉）

---

## 2. 护网作战逻辑

| 维度 | 护网做法 |
|------|----------|
| 成果 | **拿权限 / 拿靶标 / 拿数据** 才计分；未授权读、注入出数只是中间步骤 |
| 范围 | **靶标清单为唯一范围**；清单外不碰，越界即事故 |
| 节奏 | **靶标闭环** + 固定攻击窗口 + 值守；关键节点同步 |
| 报告 | **攻击路径 + 权限层级 + 影响系统 + 时间线 + 证据链** |
| 风险 | 不影响生产、不触发大面积告警、后门必须报备 |
| 停止 | 靶标达成 / 窗口结束 / 指挥部叫停 |

**三条作战原则：**
1. **目标导向**：每个动作都要能回答“离靶标更近了吗”。不能只堆扫描/未授权读。
2. **权限优先**：发现入口后继续跟到 shell/会话/管理员/域控/核心数据，不停在“能访问”。
3. **证据闭环**：每个结论有请求/响应/截图/时间；没有证据的“打穿了”等于没打。

---

## 3. 硬规则（不可违反）

| # | 规则 | 要点 |
|---|------|------|
| 1 | **授权清单唯一** | 只打清单内目标；越界/存疑立即停手上报。清单外目标哪怕再肥也不碰 |
| 2 | **ROE 优先** | 禁止 DoS/压测、拖库、删改生产数据、未报备后门、规则禁止的社工、攻击供应链/第三方、真实资损 |
| 3 | **全程留痕** | 每个动作记录：时间、目标、工具、payload、结果、操作人；证据落 `证据\` |
| 4 | **凭证管理** | 凭据加密存储、单独台账；**实时会话 token 不落盘明文**；报告脱敏 |
| 5 | **协同报备** | 提权、横向、留后门、触碰核心系统**先报备**；靶标达成/被封/范围存疑**立即同步** |
| 6 | **生产影响最小** | 写操作先评估；不并发压测；上传/改密/改绑过了立刻改回；不真资损 |
| 7 | **报告口径** | 护网报告只认 `references/hw-rules/report-format.md` |
| 8 | **清理与后门** | 行动结束按指挥部要求清理；任何持久化必须报备并登记，禁止私留 |

> 详细展开：`references/hw-rules/authorization-scope.md`、`rules-of-engagement.md`、`evidence-and-trace.md`、`collaboration.md`、`report-format.md`。

---

## 4. 红队全流程（Phase 0～6）

### Phase 0 — 接令与建账
- 读授权书 / 靶标清单 / ROE / 时间窗口 / 报备通道
- 建任务根、`00-授权与范围.md`、`01-ROE与报备.md`
- 靶标队列落盘：靶标名、类型（Web/边界/内网/供应链）、优先级、状态、负责人
- **闸门：** 授权与范围未落盘 → 不开打

### Phase 1 — 资产测绘与暴露面
- 对每个靶标做资产展开：子域 / 端口 / 目录 / 证书 / 被动 DNS / 影子资产 / 边缘设备
- 降噪：404 分类、存活分级、指纹去重、扫描模型判断（先随机路径探针）
- 红队：找最容易进的那一面；蓝队：同一套方法反向做自查
- 产出：`资产\资产清单.md`、`攻击面地图.md`、`靶标队列.md`
- 详细方法：`references/recon/asset-mapping.md` + `references/recon/`

### Phase 2 — 外网打点
- 按靶标优先级进站，**靶标闭环**：一个靶标的面挖完再换下一个
- 开场：`references/vulns/手法索引.md` 几枪 → 对得上开对应模块
- 进站：§5 的固定动作（说清这摊 → 抽 JS 钥匙 → 接口清单 → 矩阵）
- 优先：未登录出他主体 → 认证接管 → 换 id → 四件套（注入/SSRF/XSS/RCE）→ 凭证/敏感路径
- 高价值苗头（稳定注入/RCE/跨租户/可用凭证/任意登录进号）先打穿再换目标
- 产出：`报告\` 逐条落盘（确认即写，不攒）+ `证据\`

### Phase 3 — 边界突破与权限获取
- 拿到第一个 shell / 会话 / 可用凭证 → **立即固化**（截图、回显、时间戳、来源）
- 凭证认钥：假值对照 → 生产认了 → 认钥枪带出身份或列表 → 才登记为“可用”
- 边界设备打法：VPN / OA / 邮件 / 网关 / 域控（见 `references/vulns/boundary-devices.md`）
- 产出：`内网\权限台账.md`、`内网\凭据台账.md`（加密）

### Phase 4 — 内网横向
- 信息收集：主机、网段、域、共享、凭据、会话
- 提权：Linux / Windows（`references/post/linux-privesc.md`、`windows-privesc.md`）
- 横向：PTH/PTT/WMI/WinRM/PSExec（`references/post/credential-access.md`）
- 域渗透：Kerberoasting / AS-REP / DCSync / Golden Ticket（`references/post/domain-pentest.md`）
- 低特征：免杀与流量特征（`references/post/evasion.md`，仅授权、仅必要）
- **禁止：** 拖库、删改、未报备后门、批量破坏、真资损
- 产出：`内网\` 台账 + `证据\` + 路径图

### Phase 5 — 成果固化与交付
- 靶标达成表：靶标、状态、权限层级、关键证据、时间线
- 正式报告：`references/hw-rules/report-format.md`
- 日报：当日新增、阻塞、下一步、需协调
- 清理：按 ROE 清理账号/文件/后门；清理记录入 `协同\`
- 产出：`报告\`、`协同\`、`日志\`

### Phase 6 — 复盘与迭代
- 哪些打法可复用 → 写进 `references/vulns/手法索引.md`
- 哪些告警/封禁踩坑 → 写进 `references/hw-rules/rules-of-engagement.md` 的教训区
- 蓝队：整改建议、复测结果、暴露面收敛报告

---

## 5. 外网进站打法（红队核心）

### 5.1 靶标闭环

```
取一个靶标 T
  → 展开资产（去重/去废/去非存活）
  → 剩下的活面全部进站（§5.2 固定动作）
  → 每个站过“本轮完成”闸（§5.5）
  → 靶标 T 达成 / 确认不可达 / 窗口结束 → 标 done
  → 才取下一个靶标
```

- **禁止**把清单里所有靶标一次扫完再回头挖
- **禁止**靶标还剩活面就去扩新靶标（扩面假进度）
- 靶标内可多线程：深挖为主，禁止全员 FOFA/探活
- **节点同步**（靶标达成、被封、范围存疑）必须上报，不能闷头挖

### 5.2 进站固定动作

1. **说清这摊（3～5 行）**：谁在用、核心对象、钱/权/状态字段、未登录能碰哪层
2. **抽 JS 钥匙**：`/api/` 路径、签名盐、硬编码钥、密文 id、hidden 路由、演示号、测试租户、执行类 Sink
3. **建接口清单**：抓包补全；回包里的 id/url/token 立刻入队
4. **全类型矩阵**：未授权、越权/IDOR、注入、SSRF、XSS、RCE、上传、穿越、认证接管、逻辑、凭证、敏感路径（**CORS 不挖**）
5. **四件套打在“有差分面”的业务参上**：注入只打能看出条数/内容变化的参；SSRF 打 URL 类参；XSS 打回显/写入点；RCE 跟命令/模板/反序列化 Sink
6. **有会话**：对象图 → 换 id（不限字段名）→ 加字段/跳步/并发
7. **同闸停**：业务口全是同一登录码且未登录例外已点过 → 四件套收口，sibling 一眼差分
8. **肥瘦分层**：肥面（JS 多/后台/业务 JSON）深挖；瘦壳（403/同闸/同皮）一眼证伪

### 5.3 力气顺序

| 先打 | 说明 |
|------|------|
| 未登录出他人/他主体 | 不登录出名单/详情/附件；通了再换 id |
| 认证接管 | 发会话 / 重置 / 改绑 / 换票 / 2FA；进号或改密才算 |
| 换 id | 没号：未授权通了再换；有号：带着会话换 |
| 四件套 | 注入 / SSRF / XSS / RCE，打在有差分面上 |
| 凭证 / 敏感路径 | 配置、AKSK、swagger、actuator、heapdump、内网地址 |
| 逻辑 / 提权 | 加 role/金额/状态、跳步、券/库存并发 |

### 5.4 升链与停止

- 中危同一对象先升链（读 → 写 → 跨用户 → 接管 → 执行），不换站
- 高价值苗头先打穿再换目标
- **停：** 无入口 N/A + 原因；同闸已证；空列表/报错/超时无稳定差分
- **不停：** 打开是登录页 → 先找业务面；不是换靶标理由
- **必须换线：** 站不可达、硬封锁无旁路、纯废壳；记过换下一个，不提问停工

### 5.5 单站“本轮完成”闸（可换站下限）

1. 这摊已说清（或确认抽不出业务对象）
2. 接口清单已建（含 JS 钥匙表，无则写“无”）
3. 类型矩阵探针勾完（有入口打，无入口 N/A + 原因）
4. 有差分面的注入/SSRF/XSS/RCE 真发过 payload 或证伪
5. 有会话：对象图/换 id/加字段打过
6. 认证口（发会话/重置/改绑/换票/2FA）勾完或 N/A
7. 确认漏洞已按 `hw-rules/report-format.md` 落盘
8. 未耗在同皮镜像/已 covered 面

---

## 6. 边界突破与内网（要点）

- **首次权限先固化**：shell、会话、凭证、路径、时间戳，先存证再深入
- **凭证三问**：假值对照过吗？生产认了吗？认钥枪带出身份/列表了吗？三问有一否 → 不算可用
- **内网先画图**：网段、主机、域、信任关系、可达路径；不要盲目扫
- **横向最小必要**：只走靶标路径；不碰无关系统；不批量
- **域渗透高风险**：DCSync/黄金票据等先报备；不破坏 AD；不改域策略
- **后门/持久化**：能不留就不留；必须留 → 报备 + 登记 + 行动后清理
- **低特征**：免杀、流量伪装仅在授权且必要时使用；不针对蓝队个人
- 参考：`references/post/`、`references/vulns/boundary-devices.md`、`references/vulns/honeypot-recognition.md`

---

## 7. 蓝队主线（防守 / 自查）

### 7.1 资产自查与暴露面收敛
- 用 `references/recon/asset-mapping.md` 反向做：影子资产、废弃系统、边缘端口、测试环境、第三方组件
- 输出：资产台账、暴露面清单、整改优先级（按“可被利用 + 业务重要性”）
- 先收敛：关停/下线/加认证/加白名单；再补漏洞

### 7.2 告警研判
- 常见告警：Webshell、横向、扫描、C2、异常登录、DNS 隧道、数据外带
- 研判流程：告警 → 上下文 → 资产归属 → 是否误报 → 定级 → 处置/升级
- 详细：`references/defense/alert-triage.md`

### 7.3 应急响应
- 发现 → 隔离 → 取证 → 清除 → 恢复 → 复盘
- 取证优先：内存、进程、网络连接、日志、账号、计划任务/服务
- 详细：`references/defense/incident-response.md`

### 7.4 溯源与反制
- 攻击者画像：IP、域名、样本、TTP、基础设施
- 蜜罐/沙箱/诱饵；反制仅在授权与规则允许范围内
- 输出：溯源报告、IOC 清单、封禁建议

### 7.5 整改验证
- 修复 → 复测 → 回归 → 关闭
- 复测用攻击者视角，不只跑扫描器
- 无法立即修复 → 补偿措施（WAF/白名单/下线/监控）

---

## 8. 报告与交付

- **正式报告：** `references/hw-rules/report-format.md`（攻击路径 / 权限层级 / 影响系统 / 时间线 / 证据 / 整改）
- **日报：** 当日新增靶标、突破、阻塞、需协调、风险
- **靶标达成表：** 靶标、状态、权限层级、证据编号、时间
- **蓝队：** 事件报告、溯源报告、整改清单
- **脱敏：** 报告里的凭据、个人信息、内网地址按规则脱敏；原始证据单独加密存放

---

## 9. 知识库导航

### 规则（先读）
| 文件 | 用途 |
|------|------|
| `references/hw-rules/authorization-scope.md` | 授权、范围、越界处置、时间窗口 |
| `references/hw-rules/rules-of-engagement.md` | ROE、禁止项、扫描节奏、内网约束、清理 |
| `references/hw-rules/evidence-and-trace.md` | 留痕、证据链、凭证管理、脱敏 |
| `references/hw-rules/collaboration.md` | 多小组、线程交接、报备、同步 |
| `references/hw-rules/report-format.md` | 护网报告、日报、成果表 |
| `references/hw-rules/workflow.md` | 靶标闭环、进站矩阵、同闸、肥瘦、升链 |

### 资产测绘
`references/recon/asset-mapping.md`（总方法论）→ `decisions.md`（404/403/存活分级）→ `expansion.md`（深度展开）→ `correlation.md`（关联编排）→ `recon-tools.md`（查询语法）；补充：`info-port-scan.md`、`info-subdomain.md`、`info-dir-brute.md`、`info-fingerprint.md`、`info-osint.md`

### 漏洞技能（统一目录：references/vulns/）
> 进站先读 `references/vulns/手法索引.md`；完整索引见 `references/vulns/README.md`。

| 场景 | 文件 |
|------|------|
| 注入族（SQL/NoSQL/LDAP/XPath/EL/命令/SSTI） | `references/vulns/injection.md` |
| RCE / 命令执行（无回显/反弹/应用 RCE） | `references/vulns/rce.md` |
| XSS（反射/存储/DOM/CSP/XSS→RCE） | `references/vulns/xss.md` |
| SSRF（内网/云元数据/Gopher/盲打） | `references/vulns/ssrf.md` |
| XXE（文件读取/Blind OOB/XInclude/Office/SAML） | `references/vulns/xxe.md` |
| 越权/认证接管（IDOR/任意登录/会话） | `references/vulns/auth-idor.md` |
| 文件上传（后缀/内容/解析/竞态/对象存储） | `references/vulns/file-upload.md` |
| 路径穿越/LFI（读文件/伪协议/日志投毒） | `references/vulns/path-traversal-lfi.md` |
| 401/403 绕过 | `references/vulns/403-bypass.md` |
| WAF 绕过 | `references/vulns/waf-bypass.md` |
| 业务逻辑/竞态 | `references/vulns/logic-race.md` |
| CSRF | `references/vulns/csrf.md` |
| HTTP 协议族（CRLF/Host/走私/缓存） | `references/vulns/http-protocol.md` |
| GraphQL | `references/vulns/graphql.md` |
| JWT/OAuth | `references/vulns/jwt-oauth.md` |
| 反序列化 | `references/vulns/deserialization.md` |
| 子域接管 | `references/vulns/subdomain-takeover.md` |
| 信息泄露 | `references/vulns/info-leak.md` |
| API 网关 / WebSocket / 原型链 / 类型杂耍 / JNDI | `references/vulns/api-gateway.md`、`websocket.md`、`prototype-pollution.md`、`type-juggling.md`、`jndi-injection.md` |
| 云 IDE / Agent 工具 / 供应链 | `references/vulns/cloud-ide.md`、`agent-tool-exec.md`、`insecure-scm.md`、`dependency-confusion.md` |
| 边界设备 / 蜜罐 | `references/vulns/boundary-devices.md`、`honeypot-recognition.md` |

### 内网 / 后渗透
| 场景 | 文件 |
|------|------|
| Linux 提权 | `references/post/linux-privesc.md` |
| Windows 提权 | `references/post/windows-privesc.md` |
| 凭据窃取 / 横向 | `references/post/credential-access.md` |
| 域渗透 | `references/post/domain-pentest.md` |
| 免杀 / 低特征 | `references/post/evasion.md` |
| 密码爆破 | `references/post/host-brute.md` |

### 工具速查
`references/tools/`：nmap、sqlmap、msf、impacket、hydra、fuzz

### 蓝队
`references/defense/self-assessment.md`、`alert-triage.md`、`incident-response.md`

---

## 10. 每轮自检（收尾前过一遍）

- [ ] 目标在授权清单内？时间在窗口内？
- [ ] 动作留痕了吗（时间/目标/工具/payload/结果）？证据落盘了吗？
- [ ] 凭据/会话 token 是否明文落盘？
- [ ] 高风险动作报备了吗？节点同步了吗？
- [ ] 是否把“未授权读/注入出数”当成终点，没有继续跟权限？
- [ ] 有差分面的四件套真打了吗？还是每个 path 喷了 `'`？
- [ ] 有会话时对象图/换 id/加字段打了吗？
- [ ] 中危同一对象升链了吗？
- [ ] 是否在同皮/同闸上磨超过时间盒？
- [ ] 报告按 `hw-rules/report-format.md` 写了吗？脱敏了吗？
- [ ] 有没有越界、破坏、未报备后门、真资损？

---

## 11. 一句话

**清单内、留痕、报备、不伤生产；靶标闭环、先拿权限、再谈报告。**
红队：资产测绘 → 外网打点 → 边界突破 → 内网横向 → 成果固化 → 复盘。
蓝队：资产自查 → 暴露面收敛 → 告警研判 → 应急溯源 → 整改复测。
**拿权限才算成果，靶标清单就是边界。**
