# 工具与平台速查（tools）

Phase 1 种子收集与 Phase 4 横向搜索的工具/查询语法速查。均为公开可访问平台与通用 CLI，按实际可用性选用；未授权访问仅限已获授权的测试目标。

> **MCP 工具优先**：环境里接入 Luvv-MCP 时，前端/指纹/泄露类工作优先用 MCP 工具调用（见 §6），CLI 组合作为降级方案。

## 1. 子域名与种子收集

| 工具/平台 | 用途 | 要点 |
|---|---|---|
| crt.sh | 证书 CT 日志查询 | 网页查询 `%target.com`；SAN 字段列内部域名；API：`https://crt.sh/?q=%25.target.com&output=json` |
| 被动 DNS | 历史解析记录 | 现在指向 CDN 的域名半年前可能直连内网 IP |
| subfinder / amass | 子域名枚举 | 多源聚合 |
| Fofa / Hunter / Shodan | 资产测绘搜索引擎 | 见下方语法 |
| Wayback Machine | 历史页面/文件 | 找被删的配置文件、旧接口、后台入口 |

## 2. 搜索引擎语法速查

### Fofa（常用字段）
- `domain="target.com"` — 主域名下所有资产
- `host="target.com"` — 指定主机
- `cert="target.com"` — 证书含该域名（SAN 内资产全出）
- `icon_hash="xxx"` — favicon hash 反查（hash 算法见下）
- `ip="1.2.3.0/24"` — IP 段
- `title="xxx"` / `header="xxx"` / `body="xxx"` — 标题/响应头/响应体特征
- `server="nginx"` — 服务器特征
- 组合：`domain="target.com" && status_code="404"`、`cert="target.com" && icon_hash="xxx"`
- 供应链指纹反查：用自研前端框架的特定 JS 文件名 / CSS class / meta 标签作为 body 特征搜索

### Hunter（鹰图）
- `domain="target.com"` — 域名资产
- `web.title="xxx"` / `web.body="xxx"` / `header="xxx"` — 特征搜索
- `cert="target.com"` — 证书关联
- `ip="1.2.3.0/24"` — 网段
- 供应链反查：`web.body="特定JS文件名或class"`

### Shodan
- `ssl.cert.subject.cn:target.com` — 证书 CN 关联
- `ssl.cert.subjectAltName:target.com` — SAN 关联
- `hostname:target.com` — 主机名
- `http.favicon.hash:xxx` — favicon hash（Shodan 自身 hash 算法，与 mmh3 不同，需单独算）
- `net:1.2.3.0/24` — 网段
- `http.title:"xxx"` — 标题特征

### Google/Bing dork
- `site:target.com -www` / `site:target.com filetype:pdf` / `site:target.com inurl:admin`
- `intitle:"test" site:target.com` — 测试环境
- `"target.com" "internal"` — 内部资产线索

## 3. 主动探测 CLI 组合（通用）

| 阶段 | 命令思路 |
|---|---|
| 子域名收集后解析 | `subfinder -d target.com` 后批量解析 IP |
| 存活探测 | `httpx`（httpx-toolkit）：`-status-code -title -tech-detect -favicon`，输出含指纹 |
| 端口扫描 | `nmap -p- -T4`（全端口）；重点补 8000-65535 高位 + UDP 常用口 |
| 指纹识别 | `whatweb`、`wappalyzer`、`httpx -tech-detect`；**有 Luvv-MCP 时用 `luvv_site_sniff`（7,183 规则）+ `luvv_fingerprint_scan`（favicon hash 维度）替代** |
| favicon hash | 对 favicon 内容 base64 后算 mmh3（Fofa icon_hash 标准；Shodan 用自身 hash，需另算） |
| 目录扫描 | `ffuf`/`dirsearch`（**先做随机路径探针判断扫描模型**再决定，见 `decisions.md` §3） |
| 提取 JS 中的 API | 首选 `luvv_collect_assets`（外链 JS + 内联脚本 + 跨域资源一次采集）；降级：grep/正则提取 axios/fetch 的 url 参数；大型 JS 用反混淆器处理后提取 |
| Source Map 检查 | 首选 `luvv_collect_assets`（自动发现并解析还原 .map 源码）；降级：请求 JS 末尾 `//# sourceMappingURL=` 指向的 `.map` 文件 |
| JS 源码泄露扫描 | `luvv_leak_scan`（60+ 规则：云 AK/SK、平台 Token、Webhook、数据库连接串、PEM 私钥、JWT、PII、硬编码密码） |
| 前端漏洞面审计 | `luvv_vuln_audit`（暴露的管理 API 端点、敏感路由、硬编码凭证、SourceMap/debug 残留） |

## 4. 常用默认路径/端口探测清单

- 框架默认：`/actuator` `/actuator/env` `/swagger-ui.html` `/v2/api-docs` `/v3/api-docs` `/phpinfo.php` `/druid/` `/api-docs`
- 管理后台：`/admin/` `/manage/` `/console/` `/login`
- 管控台端口：Nacos 8848、Apollo 8070、SkyWalking 8080/11800、Sentinel 8080、XXL-Job 8080、Kong admin 8001、APISIX admin 9180、JMX 1099、pprof 6060、ES 9200、Jenkins agent 50000
- 配置/注册中心：Nacos、Eureka、Consul、Apollo（未授权即读服务列表/配置）

## 5. 指纹→横向搜索工作流

1. 识别自研指纹：JS 文件名、CSS class、meta 标签、自定义响应头（X-Gateway-Version、特殊 X-Trace-Id）、favicon hash、报错栈包名。
2. 将指纹转成 Fofa/Hunter body/header 查询。
3. 搜索结果与已知资产比对，新资产即同源资产族成员。
4. 同一资产族：优先打鉴权最弱的、维护最旧的、入口最隐蔽的。

## 6. Luvv-MCP 工具对照表（有 MCP 环境时优先）

Luvv-MCP 是前端安全分析引擎（5 个工具），覆盖本 skill 的 Phase 2 指纹、Phase 4 §1 前端反推、§2 二级目录。**单 URL 工具，无批量模式**——资产清单逐个调用，量大时先按 Phase 2 分级挑代表。

| Luvv-MCP 工具 | 对应本 skill 章节 | 何时用 |
|---|---|---|
| `luvv_site_sniff` | tools.md §3 指纹识别 | 拿到任一存活 Web 资产后第一步：技术栈/CMS/框架/CDN/安全头 |
| `luvv_fingerprint_scan` | §5 指纹→横向搜索 | 服务器/中间件/OA/网络设备指纹（EHole 体系），产出可转 Fofa/Hunter 反查的特征 |
| `luvv_collect_assets` | expansion.md §1 前端反推、§2 二级目录 | SPA 资产的核心动作：外链 JS + 内联脚本 + SourceMap 自动还原；产出喂给下面两个工具 |
| `luvv_leak_scan` | expansion.md §1.1 多环境地址/第三方依赖 | 扫 JS 源码里的 AK/SK、Token、Webhook、连接串、内网 IP、PII（支持直接传 `source`） |
| `luvv_vuln_audit` | expansion.md §1.1 鉴权逻辑、错误码 | 暴露的管理 API、敏感路由、硬编码凭证、SourceMap/debug 残留 |

**推荐调用链**（对应 expansion.md §1 流程）：

```
luvv_site_sniff(url)                 → 技术栈定性，决定走"读前端"还是"字典爆破"
  └─ luvv_collect_assets(url)        → JS + SourceMap 源码
       ├─ luvv_leak_scan(source=…)   → 残留密钥/内网地址/测试环境
       └─ luvv_vuln_audit(source=…)  → 免鉴权端点/管理 API/敏感路由
```

**注意**：
- `fingerprint_scan` 实际加载 100 条规则（EHole 体系），与 README 宣传的 11,596 不一致，按 100 预期
- 工具产出是**证据**（规则命中+响应证据），可直接作为资产清单的"指纹/来源"字段，不走 `[引用:]` 体系
- `collect_assets` 依赖 Playwright（需配 `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` 指向本机浏览器），失败时降级为 curl 抓 HTML + 手工提取 JS 链接

## 7. 产物路径约定（默认，用户另指定则以用户为准）

任务根统一落 **`D:\MCP\hvv\{行动名}\资产\`**（资产测绘产物直接作为打点输入）。

```
D:\MCP\hvv\{行动名}\资产\
  README.md          任务说明、进度表、续跑命令
  资产\              资产清单.md、种子队列.md、covered_hosts.txt
  证据\              响应特征、指纹、favicon hash、来源 URL、扫描器原始导出（httpx/nmap/FOFA）
  {短名}_dig\        中间状态、临时脚本、pass2/3 增量
  报告\              攻击面地图.md、推荐攻击路径.md
```

| 子目录 | 放什么 | 不放什么 |
|--------|--------|----------|
| `资产/` | 公网可挖 URL/域名清单、资产清单、种子队列、covered_hosts | **禁止** JS 文件、扫描原始导出、报告 |
| `证据/` | 结论的可复现证据：响应特征、指纹、hash、来源 URL、扫描器原始输出 | 结论性报告 |
| `{名}_dig/` | 中间状态、临时脚本、半截探测缓存（增量轮次仍在此） | 定稿交付物 |
| `报告/` | 攻击面地图、推荐攻击路径、未决项 | 脚本、原始导出、JS |

**落盘纪律：**
- Phase 1~5 每次推进（新种子/新资产/新指纹/新关联）**随手写回文件**，不攒到最后——对话压缩会吃掉未落盘的中间结论
- **提取的 JS 不落 `资产/`**（若需存放前端 JS，先落 `{名}_dig/`，定稿移入任务根 `js/`，与打点阶段口径一致）
- 同一目标已有任务根 → **续用**，不另建

**与工具分工**：`luvv_collect_assets` 等 MCP 工具的产出（规则命中+响应证据）写进 `证据/`，资产条目写进 `资产/资产清单.md`。
