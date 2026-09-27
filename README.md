# 可撤回数据用途许可与派生阻断 API

基于 **Python + FastAPI + PostgreSQL** 的数据用途合规服务：

- 许可（grant）与撤销（revocation）以**追加事件**登记，事件带不可变录入序号 `seq`；
- 许可包含 `grant_id`、数据类别、处理目的、接收方与**半开有效区间** `[valid_from, valid_to)`；
- 撤销引用 `grant_id` 并注明**业务生效时间**（可以早于录入时间，即追溯撤销）；
- 任意决策按 **`use_at`（使用时点）与 `as_of`（录入可见时点）** 双时点确定性重放，
  **默认拒绝**，并返回命中的许可或撤销依据；
- 处理任务用**幂等键**登记决策回执、派生产物与**无环血缘（DAG）**，
  一个产物可以声明**多组替代依据**；
- 补录的追溯撤销使受影响的既有决策当前重放失效，并沿血缘传播：
  **仅当所有替代依据组都失效时才阻断产物**；解释按**失效事件数最少、再按事件 ID 排序**；
- 决策登记与同一主体的撤销通过 PostgreSQL 咨询锁**串行化**，且**先取锁、再建立
  事务快照**：同一主体的写入严格按锁获取顺序读取彼此已提交的状态；
- 所有持久化操作只有 `INSERT`，**历史回放不会改写旧记录**（状态随时由事件重放派生）；
- **撤销处置台账**：追溯撤销在**同一事务**内比较撤销前后回执状态，为每条由有效
  转为失效的 allow 回执开立处置项（归属接收方、关联沿血缘本次阻断的产物）；接收方
  凭令牌提交停止使用声明与清除证据，管理员按版本复核；证据与决定同样只追加。
- **删除请求与删除计划**：客户端凭幂等键提交 `subject_id`、`product_ids`
  （空 = 主体全部产物）与请求时间，服务在主体咨询锁保护的 REPEATABLE READ 快照中
  登记不可变请求；目标范围仍有**活动许可**或**未结处置**时返回**可定位**的阻断
  原因，否则按依赖**反向拓扑**生成**下游先删、同层稳定排序**的删除批次并记录
  `basis_seq`；查询时**复用登记回执的范围、下游闭包与处置派生逻辑**按当前状态
  重新评估并与历史结论比较——**结论变化**（许可 / 撤销重放改变阻断，或处置
  提交获批 / 取消结案解除阻断）即标记**过期**并要求用**新幂等键**重新评估；
  仅追加事件但结论不变（如与范围无关的许可 / 撤销）不误报过期。
  历史计划、批次与阻断原因从不改写，也从不真实执行删除。
- **合规证明（attestation）**：客户端凭幂等键提交 `subject_id`、产品范围、
  `use_at` 与 `as_of_seq`，服务在主体咨询锁保护的**同一 REPEATABLE READ
  快照**中重放许可、撤销、回执血缘、处置状态与删除结论，生成**只含稳定
  标识与依据**的规范化 JSON 声明（固定字段、规范序列化），保存
  **SHA-256 摘要**与本地密钥 **HMAC-SHA256 签名**，返回可**独立验签**
  的字节。同键同内容重放原证明，同键异内容冲突；**后续事件永不改写既有
  证明**，`POST /attestations/verify` 验签只依赖声明、摘要、签名与配置
  密钥，**不读取任何可变业务状态**。产品范围为空、含未知产品或越界
  `as_of_seq` 一律拒绝。
- **合规状态双时点差异报告**：客户端提交 `subject_id`、非空
  `product_ids`、`use_at` 与两条全局事件序号上界
  `from_seq < to_seq`，服务在**一个 REPEATABLE READ 只读快照**中分别
  按两条上界重放许可、撤销、决策回执、血缘产品、处置项与删除结论，
  返回每个产品及其传递回执的 **added / removed / changed / unchanged**
  分类、两侧稳定依据与状态翻转原因（可定位到撤销 / 许可 / 处置项序号）；
  from 侧尚未登记的产品标为 **absent**，未知产品或未来序号拒绝；
  结果按产品、回执与事件序号稳定排序；**不写入任何业务表**，
  **后续事件不改变同一 (from_seq, to_seq) 的报告**。

## 1. 一键启动

前置：Docker 与 Docker Compose v2。

```bash
docker compose up --build
```

启动后：

| 入口 | 地址 |
| --- | --- |
| API 健康检查 | http://localhost:8000/health |
| Swagger UI（交互文档） | http://localhost:8000/docs |
| ReDoc | http://localhost:8000/redoc |
| OpenAPI Schema | http://localhost:8000/openapi.json |
| PostgreSQL | localhost:5432（用户/库/密码均为 `consent`） |

数据库表在 API 启动时自动幂等创建（`sql/schema.sql`）。
停止并清库：`docker compose down -v`。

compose 为**撤销处置台账**预置了本地开发令牌（可通过环境变量覆盖，见 §4.5）：

- 管理员：`Authorization: Bearer dev-admin-token`（执行复核）；
- 接收方：`Authorization: Bearer dev-token-a`（partner-a）、
  `Bearer dev-token-b`（partner-b），只能查询 / 提交自己的处置项。

## 2. 核心概念与时间语义

每个事件有两个时间维度（bitemporal）：

- **录入时间 `recorded_at`**：系统何时知道该事件，对应重放参数 **`as_of`**
  （也可用事件序号 `as_of_seq`）；
- **业务时间**：许可区间 `[valid_from, valid_to)` 与撤销的 `business_effective_at`，
  对应重放参数 **`use_at`**。

因此「2026-09 才补录一条业务生效时间为 2026-01 的撤销」不会修改 5 月已经写下的决策回执，
但在当前（9 月）重放 5 月的使用时会命中撤销，回执进入失效状态并沿血缘传播；
而指定 `as_of_seq` 回到撤销之前，仍可重放出当时的 `allow`。

确定性规则：

1. 类别/目的/接收方匹配，且 `use_at ∈ [valid_from, valid_to)` 的许可中，
   取**录入序号最大**者；
2. 若该许可存在 `business_effective_at <= use_at` 的撤销，取**序号最小**的生效撤销为命中依据；
3. 其余情况一律 **deny / no_grant**（默认拒绝）。

## 3. API 一览

| 方法 | 路径 | 说明 |
| --- | --- | --- |
| POST | `/grants` | 追加许可事件 |
| POST | `/revocations` | 追加撤销事件（引用 grant_id + 业务生效时间） |
| GET  | `/subjects/{subject_id}/events[?as_of_seq=]` | 查看追加事件登记处 |
| POST | `/decisions/evaluate[?as_of_seq=]` | 按 use_at/as_of 确定性重放（不落库） |
| POST | `/tasks` | **幂等**登记决策回执 + 产物 + 血缘（需 `Idempotency-Key` 头） |
| GET  | `/receipts/{key}` | 回执详情与当前重放有效性 |
| GET  | `/subjects/{subject_id}/products/{product_id}[?as_of=&as_of_seq=]` | 产物阻断状态与解释 |
| GET  | `/subjects/{subject_id}/remediation[?recipient=]` | 处置台账：未结项、证据、复核历史与结案状态（需令牌） |
| POST | `/remediation/items/{item_id}/submissions` | 接收方提交停止使用声明 + 清除证据（需令牌 + `Idempotency-Key`） |
| POST | `/remediation/items/{item_id}/reviews` | 管理员按版本批准 / 驳回（需管理员令牌） |
| POST | `/deletion-requests` | **幂等**登记删除请求并生成删除计划（需 `Idempotency-Key`；不真实执行删除） |
| GET  | `/deletion-requests/{request_id}` | 查询删除计划；按当前许可/撤销重放与处置结案状态重新评估，结论变化时标记过期 |
| POST | `/attestations` | **幂等**生成合规证明：同一快照重放全部依据，规范化声明 + SHA-256 摘要 + HMAC 签名（需 `Idempotency-Key`） |
| GET  | `/attestations/{id}` | 取回既有证明的声明字节、摘要与签名（不按当前状态重放） |
| POST | `/attestations/verify` | 独立验签：只依赖声明、摘要、签名与配置密钥，不读取业务状态 |
| POST | `/compliance-diffs` | 合规状态双时点差异报告：同一快照按 from_seq/to_seq 重放并分类 added/removed/changed/unchanged（只读，不落库） |

错误统一返回 `{"error": {"code", "message"}}`，状态码：
`401 unauthorized`（缺少 / 无效令牌）、`403 forbidden`（令牌角色或接收方不匹配）、
`404 not_found` / `409 conflict`（幂等键冲突、grant_id/product_id 重复、
处置项版本过期 / 已结案）/
`422 unprocessable_entity`（血缘有环、引用未知、半开区间非法、证据未覆盖关联产物、
证明产品范围为空 / 含未知产品 / 越界 as_of_seq、验签输入格式非法、
差异报告产品范围为空 / 含未知产品 / from_seq ≥ to_seq / 未来序号等）。

## 4. 示例调用

### 4.1 追加许可（半开区间）

```bash
curl -sS -X POST localhost:8000/grants \
  -H 'Content-Type: application/json' -d '{
    "subject_id": "u1",
    "grant_id": "g1",
    "category": "email",
    "purpose": "marketing",
    "recipient": "partner-a",
    "valid_from": "2026-01-01T00:00:00Z"
  }'
# -> {"seq":1,"event_type":"grant","grant_id":"g1", ...}
```

`valid_to` 省略表示开放结束；`use_at == valid_to` 不包含在区间内（半开）。

### 4.2 确定性重放决策（默认拒绝）

```bash
curl -sS -X POST localhost:8000/decisions/evaluate \
  -H 'Content-Type: application/json' -d '{
    "subject_id":"u1","category":"email","purpose":"marketing",
    "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z"}'
```

命中许可：

```json
{"decision":"allow","hit":"grant",
 "basis":{"kind":"grant","seq":1,"grant_id":"g1","reason":"grant"}}
```

无匹配许可时：`{"decision":"deny","hit":"none","basis":{"kind":"none","reason":"no_grant"}}`。

### 4.3 幂等登记任务、回执、产物与血缘

```bash
curl -sS -X POST localhost:8000/tasks \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: task-1' -d '{
    "subject_id":"u1",
    "category":"email","purpose":"marketing","recipient":"partner-a",
    "use_at":"2026-05-01T00:00:00Z",
    "products":[{
      "product_id":"report-1",
      "description":"营销报表",
      "groups":[[{"kind":"receipt","ref":"task-1"}]]
    }]}'
```

- `groups` 是“替代依据组”列表：**任一组**全部输入有效则产物 active；全部组失效才 blocked。
- 组内输入 `kind` 为 `receipt`（引用幂等键）或 `product`（引用同主体上游产物）；
  支持同批声明的新产物互相引用，服务端做 DAG 无环校验。
- 同 `Idempotency-Key` 重放返回首次结果（HTTP 200，`idempotent_replay:true`）；
  负载不同返回 `409`。

### 4.4 追溯撤销与血缘传播

```bash
# 业务生效时间回溯到 1 月：5 月的使用在“当前”重放中失效
curl -sS -X POST localhost:8000/revocations \
  -H 'Content-Type: application/json' -d '{
    "subject_id":"u1","grant_id":"g1",
    "business_effective_at":"2026-01-15T00:00:00Z"}'
```

响应会列出本次撤销新波及的回执与产物；阻断解释示例：

```json
{
  "product_id":"report-2","status":"blocked",
  "invalidating_events":[3],
  "explanation":[{"group_index":0,"active":false,
                  "invalidating_events":[3],
                  "failed_inputs":[{"input_kind":"receipt",
                    "input_ref":"task-1","invalidating_events":[3], ...}]}]
}
```

多组都失效时，`explanation` 选择**失效事件数最少**的组，事件数相同则按
事件 ID（seq）字典序。

### 4.5 撤销处置台账（令牌、版本、结案）

追溯撤销提交时，服务在**同一事务**内比较撤销前后的重放状态：

- 每条由**有效转为失效**的 allow 回执开立一个**处置项**（`item_id`），
  归属该回执的接收方，并关联**沿该回执血缘在本次转为阻断**的产物
  （沿 DAG 传递依赖；撤销响应的 `remediation_items` 立即返回）；
- 撤销事务回滚（如引用了不存在的 grant_id）则处置记录同样不存在；
- 回执未恢复有效即再次被撤销，**不重复开立**；
- 后续许可使回执**恢复有效**时，其**未结**处置项在许可事务内追加取消记录
  （许可响应的 `cancelled_remediation_items` 返回）；此后再次失效**另开新项**。

处置项状态全部由追加记录派生（无 UPDATE）：

```
open（待提交）→ submitted（待复核）→ rejected（已驳回，可补证）
             ↘ approved（获批结案）
任何未结状态 + 回执恢复有效 → cancelled（取消）
```

**令牌（本地配置，环境变量）**：

| 环境变量 | 作用 | compose 默认值 |
| --- | --- | --- |
| `REMEDIATION_ADMIN_TOKEN` | 管理员令牌：执行复核、按 `?recipient=` 查询 | `dev-admin-token` |
| `REMEDIATION_RECIPIENT_TOKENS` | 接收方令牌映射，格式 `接收方=令牌,接收方2=令牌2` | `partner-a=dev-token-a,partner-b=dev-token-b` |
| `ATTESTATION_HMAC_KEY` | 合规证明声明的 HMAC-SHA256 签名密钥（**仅服务端持有**；验签只依赖它，不读业务状态） | `dev-attestation-hmac-key` |

令牌经 `Authorization: Bearer <令牌>` 头携带：接收方令牌**只能查询和提交自己的
处置项**（冒充他人返回 403），管理员令牌**只能复核**。生产部署务必覆盖默认值。

接收方提交（逐项；停止使用声明 + 对**全部关联产物逐项**给出清除证据摘要）：

```bash
curl -sS -X POST localhost:8000/remediation/items/1/submissions \
  -H 'Authorization: Bearer dev-token-a' \
  -H 'Idempotency-Key: rem-1-v1' \
  -H 'Content-Type: application/json' -d '{
    "version": 1,
    "cease_declaration": "已停止对相关数据的一切使用",
    "evidence": [{"product_id": "report-1",
                  "summary": "已删除报表及备份，见工单 OPS-1"}]}'
```

- 首个提交 `version=1`；管理员驳回后只能补证 `version=2`，依此类推；
- **同键重复提交**返回首次结果（200，`idempotent_replay:true`）；同键不同内容
  `409`；版本号与服务端期望不符（过期）`409`；证据未覆盖全部关联产物或含无关
  产物 `422`；已结案 / 已取消的处置项拒绝再提交。

管理员按**最新提交版本**批准或驳回（驳回后可补证，驳回的版本不得再复核）：

```bash
curl -sS -X POST localhost:8000/remediation/items/1/reviews \
  -H 'Authorization: Bearer dev-admin-token' \
  -H 'Content-Type: application/json' \
  -d '{"version": 1, "action": "reject", "comment": "证据不足"}'
```

接收方查询自己的台账（管理员加 `?recipient=partner-a`）：

```bash
curl -sS localhost:8000/subjects/u1/remediation \
  -H 'Authorization: Bearer dev-token-a'
```

返回未结项 `open_item_ids`、每项的提交证据（全部历史版本）与复核历史，以及该
（主体, 接收方）维度的 `status`：**全部处置项均获批（或取消）才显示 `closed`**；
后续新增失效另开新项后自动重新显示 `pending`。证据与复核决定只追加保存；**结案
不改变原回执、产物阻断状态与 `as_of_seq` 历史回放**。

### 4.6 历史时点回放（旧记录保持原样）

```bash
# 按录入序号回到撤销之前
curl -sS "localhost:8000/subjects/u1/products/report-1?as_of_seq=2"
# 或按时间 as_of=2026-01-31T23:59:59Z
```

### 4.7 删除请求与删除计划（不真实执行删除）

客户端凭幂等键提交删除请求：`product_ids` 为空表示该主体**全部产物**，
`requested_at` 为客户端请求时间。服务在主体咨询锁保护的 REPEATABLE READ
快照中：

1. **登记不可变请求**：请求范围归一化（排序去重，顺序 / 重复不影响幂等
   指纹）；实际删除范围 = 请求范围 ∪ 全部**传递下游**产物——删除一个产物
   必须连带删除由它派生的一切；
2. **评估阻断原因（可定位）**：
   - `active_grant`：范围上游血缘中仍有当前有效的回执，给出当前命中许可的
     `grant_id` / `grant_seq`、回执键与受影响产物；
   - `open_remediation`：范围血缘内回执的处置项未了结，给出 `item_id`、
     接收方、当前状态与受影响产物；
3. **无阻断时生成删除批次**：按依赖反向拓扑**下游先删**（被依赖的产物排在
   更晚批次），同批内按 `product_id` 字典序稳定排序，并记录登记时点的主体
   事件序号 `basis_seq`。

```bash
curl -sS -X POST localhost:8000/deletion-requests \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: del-1' -d '{
    "subject_id":"u1","product_ids":[],
    "requested_at":"2026-09-26T08:00:00Z"}'
```

放行（`planned`）响应示例：

```json
{"request_id":1,"status":"planned","basis_seq":7,"current_seq":7,"stale":false,
 "scope":["report-1","report-2","report-3"],
 "batches":[{"batch_no":1,"product_ids":["report-2","report-3"]},
            {"batch_no":2,"product_ids":["report-1"]}],
 "blockers":[]}
```

阻断（`blocked`）响应示例（同样 201 登记，原因可定位）：

```json
{"request_id":2,"status":"blocked","batches":[],
 "blockers":[{"kind":"active_grant","grant_id":"g2","grant_seq":2,
              "category":"email","purpose":"marketing",
              "recipient":"partner-a","receipt_key":"task-1",
              "products":["report-1"]}]}
```

- 同键同内容重放返回原计划（HTTP 200，`idempotent_replay:true`）；
  同键异内容 `409`；缺 `Idempotency-Key` `422`；未知 `product_id` `422`；
- 查询计划：`GET /deletion-requests/{request_id}`。查询复用登记时保存的
  归一化范围（下游闭包回执），以**当前**事件重放与处置台账追加记录重新派生
  结论，并与历史状态 / 阻断原因身份比较：结论一致则 `stale:false`（即使
  `current_seq != basis_seq`，例如追加了与范围无关的事件，或同一未结处置项
  仅在 open/submitted/rejected 间流转）；**结论变化**——处置获批 / 取消结案
  解除 `open_remediation` 阻断、新许可 / 撤销使回执重放为有效 / 失效、或
  阻断原因身份切换——则响应 `stale:true` 并在 `detail` 中提示**用新的幂等键
  重新提交**以重新评估。处置提交与复核不产生事件序号，故是否过期由结论比较
  决定而非 `current_seq` 与 `basis_seq` 的简单不等比较；
- 请求、批次与阻断原因全部只追加保存：查询过期只改变即时计算的 `stale` /
  `detail`，**历史 `status`、批次、阻断原因与原回执从不改写，端点也从不真实
  执行任何删除**（产物、回执与 `as_of_seq` 历史回放均不受影响）。

### 4.8 合规证明：规范化声明、摘要 / 签名与独立验签

客户端凭幂等键提交主体、**非空**产品范围、`use_at` 与 `as_of_seq`：

```bash
curl -sS -X POST localhost:8000/attestations \
  -H 'Content-Type: application/json' -H 'Idempotency-Key: att-1' -d '{
    "subject_id":"u3",
    "product_ids":["report-1","report-2"],
    "use_at":"2026-05-01T00:00:00Z",
    "as_of_seq":3}'
```

服务在主体咨询锁保护的**同一 REPEATABLE READ 快照**（锁先于快照，见 §5）
中一次性重放：

1. **许可 / 撤销**：截至 `as_of_seq` 的事件对范围内血缘回执按各回执
   `use_at` 双时点重放，给出 `currently_valid` 与 `invalidating_events`；
2. **回执血缘**：沿快照时点（`recorded_seq <= as_of_seq`）已登记产物的
   DAG 传播，给出每个产品 `active/blocked`、失效事件与全部传递依赖回执；
3. **处置状态**：快照时点已开立（撤销序号 `<= as_of_seq`）的处置项，
   其**当前**追加派生状态（open/submitted/rejected/approved/cancelled）
   作为依据进入声明；
4. **删除结论**：快照血缘做下游闭包，复用删除请求的阻断派生
   （`active_grant` / `open_remediation`，均可定位）；无阻断时给
   下游先删批次。

声明（claim）**只含稳定标识与依据**，不含服务端生成时间、自由文本等可变
内容；字段集合固定为：

```
version, subject_id, use_at, as_of_seq, basis_seq,
product_ids, products{product_id -> {status, invalidating_events,
  receipts[{receipt_key, currently_valid, invalidating_events}],
  remediation_items[{item_id, receipt_key, recipient, status, revocation_seq}]}},
deletion{scope, status, blockers[...], batches[{batch_no, product_ids}]}
```

`basis_seq` 是生成时该主体可见的最大事件序号（`<= as_of_seq`；序号全局
单调，主体在该时点可能尚无自身事件）。

**固定字段序列化**：`json.dumps(claim, sort_keys=True, ensure_ascii=False,
separators=(",", ":"))` 取 UTF-8 字节（`app/attestation.py`）。服务保存该
**原始字节**（`BYTEA`，绝不经 JSONB 重序列化），并计算：

- `digest` = `SHA-256(claim_bytes)`（小写十六进制）；
- `signature` = `HMAC-SHA256(ATTESTATION_HMAC_KEY, claim_bytes)`。

响应同时返回 `claim`（解析对象）、`claim_canonical`（规范字节字符串）、
`digest`、`signature`、算法标识与 `attestation_id`：

```json
{"attestation_id":1,"idempotency_key":"att-1","as_of_seq":3,"basis_seq":3,
 "claim":{"version":"1.0", "...":"..."},
 "claim_canonical":"{\"as_of_seq\":3,\"basis_seq\":3,...}",
 "digest":"3b5247…","signature":"206881…",
 "digest_alg":"SHA-256","signature_alg":"HMAC-SHA256",
 "idempotent_replay":false,"created_at":"2026-09-26T…"}
```

**取回**：`GET /attestations/{id}` 返回登记时保存的字节 / 摘要 / 签名，
**不按当前事件重放**——后续许可 / 撤销 / 处置追加永不改写既有证明。

**独立验签**：`POST /attestations/verify` **不打开事务、不读取数据库或
任何业务状态**，只用提交的字节、摘要、签名与配置密钥计算：

```bash
# 提交 claim_canonical（原样字节）
curl -sS -X POST localhost:8000/attestations/verify \
  -H 'Content-Type: application/json' -d '{
    "claim_canonical":"{\"as_of_seq\":3, …}",
    "digest":"3b5247…","signature":"206881…"}'
# 或提交 claim 对象（服务端按固定字段重新规范化）
```

```json
{"valid":true,"digest_ok":true,"signature_ok":true,
 "digest_alg":"SHA-256","signature_alg":"HMAC-SHA256",
 "digest":"3b5247…"}
```

篡改任一字节：`valid/digest_ok/signature_ok` 均为 `false`；只换错摘要：
`digest_ok=false`（`signature_ok` 仍可能为 true，用于定位篡改层）；密钥
不符：仅 `signature_ok=false`。非十六进制摘要 / 签名、未提供声明或未知
`alg` 返回 `422`。验签同样可以**完全离线**完成（Python 标准库）：

```python
import hashlib, hmac
key = b"dev-attestation-hmac-key"          # 即 ATTESTATION_HMAC_KEY
cb  = claim_canonical.encode("utf-8")
digest_ok  = hashlib.sha256(cb).hexdigest() == digest
signature_ok = hmac.compare_digest(
    hmac.new(key, cb, hashlib.sha256).hexdigest(), signature)
```

**幂等与不可变**：同键同内容（范围排序去重、时间归一化）重放原证明
（HTTP 200，`idempotent_replay:true`，摘要 / 签名字节不变）；同键异内容
`409`；新键同快照内容生成不同 ID 但**摘要与签名相同**（声明只由快照派生）。

**校验**：缺 `Idempotency-Key` `422`；产品范围为空 `422`；含主体未知产品
`422`；`as_of_seq` 超过当前全局最大事件序号（越界）`422`；产品在
`as_of_seq` 之后才登记（快照中尚不存在）`422`；未知证明 `404`。

**密钥配置**：通过环境变量 `ATTESTATION_HMAC_KEY` 配置（compose 预置
本地默认值，**生产部署务必覆盖**）。密钥是本地对称密钥：服务重启不变
（声明仍可验签）；轮换密钥后旧签名只能用旧密钥验证。

### 4.9 合规状态双时点差异报告（只读，不落库）

客户端提交主体、**非空**产品范围、`use_at` 与两条全局事件序号上界
（`from_seq < to_seq`）：

```bash
curl -sS -X POST localhost:8000/compliance-diffs \
  -H 'Content-Type: application/json' -d '{
    "subject_id":"u3",
    "product_ids":["report-1","report-2"],
    "use_at":"2026-05-01T00:00:00Z",
    "from_seq":2,"to_seq":3}'
```

服务在**一个 REPEATABLE READ 只读快照**中分别按两条上界重放：许可 /
撤销（`seq <= 上界`）、决策回执与血缘产品（`recorded_seq <= 上界`）、
处置项（开立 `revocation_seq <= 上界`、取消 `grant_seq <= 上界`）与
删除结论（范围闭包 + 阻断派生，同 §4.7 / §4.8 口径），然后逐产品、
逐回执比较两侧状态：

- **分类**：仅 to 侧存在 -> `added`（from 侧尚未登记的产品 / 回执 /
  处置项，from 侧标 `{"presence":"absent"}`）；仅 from 侧存在 ->
  `removed`（本系统只追加，实际不出现，分类保持完备）；两侧均存在且
  状态比较键不同 -> `changed`，否则 `unchanged`；
- **两侧稳定依据**：产品给出 `recorded_seq` / `task_key` 与两侧
  `status` / `invalidating_events`；回执给出登记时的不可变决策
  （`decision`、`basis`、`use_at`、`recorded_seq`）与两侧
  `currently_valid` / `invalidating_events` / 当前命中许可
  （`hit_grant`）；处置项给出 `revocation_seq`、关联产物与两侧状态；
  删除结论给出两侧 `scope` / `status` / `blockers` / `batches`；
- **状态翻转原因**（可定位）：回执 `revoked`（新增失效撤销的序号、
  grant_id、业务生效时间）与 `hit_grant_changed`（命中许可切换——
  新许可恢复有效或更新许可取代旧命中）；产品 `status_flip`（含
  `causing_receipts`）；处置项 `opened`（revocation_seq）/
  `cancelled`（grant_seq）；删除结论 `blocker_added` /
  `blocker_removed`（阻断原因身份）/ `scope_changed` 等。

响应骨架（撤销落入区间时）：

```json
{"subject_id":"u3","use_at":"2026-05-01T00:00:00+00:00",
 "from_seq":2,"to_seq":3,"from_basis_seq":2,"to_basis_seq":3,
 "summary":{"products":{"added":0,"removed":0,"changed":2,"unchanged":0},
            "receipts":{"added":0,"removed":0,"changed":1,"unchanged":0},
            "remediation_items":{"added":1,"removed":0,"changed":0,"unchanged":0},
            "deletion":"changed"},
 "products":[{"product_id":"report-1","classification":"changed",
   "recorded_seq":2,"task_key":"u3-task-1",
   "from":{"presence":"present","status":"active","invalidating_events":[]},
   "to":{"presence":"present","status":"blocked","invalidating_events":[3]},
   "flip_reasons":[{"kind":"status_flip","from_status":"active",
     "to_status":"blocked","invalidating_events":[3],
     "causing_receipts":["u3-task-1"]}],
   "receipts":[{"receipt_key":"u3-task-1","classification":"changed",
     "decision":"allow","basis":{"grant_id":"g1","seq":1,"reason":"grant"},
     "use_at":"2026-05-01T00:00:00+00:00","recorded_seq":2,
     "from":{"presence":"present","currently_valid":true,
             "invalidating_events":[],"hit_grant":{"grant_id":"g1","grant_seq":1}},
     "to":{"presence":"present","currently_valid":false,
           "invalidating_events":[3],"hit_grant":{"grant_id":"g1","grant_seq":1}},
     "flip_reasons":[{"kind":"revoked","revocation_seq":3,"grant_id":"g1",
                      "business_effective_at":"2026-01-15T00:00:00+00:00"}]}]}],
 "remediation_items":[{"item_id":1,"receipt_key":"u3-task-1",
   "recipient":"partner-a","revocation_seq":3,"products":["report-1","report-2"],
   "classification":"added","from":{"presence":"absent"},
   "to":{"presence":"present","status":"open"},
   "flip_reasons":[{"kind":"opened","revocation_seq":3}]}],
 "deletion":{"classification":"changed",
   "from":{"scope":["report-1","report-2"],"status":"blocked",
           "blockers":[{"kind":"active_grant","grant_id":"g1","grant_seq":1,
                        "receipt_key":"u3-task-1","products":["report-1","report-2"],
                        "category":"email","purpose":"marketing",
                        "recipient":"partner-a"}],"batches":[]},
   "to":{"scope":["report-1","report-2"],"status":"blocked",
         "blockers":[{"kind":"open_remediation","item_id":1,
                      "receipt_key":"u3-task-1","recipient":"partner-a",
                      "status":"open","products":["report-1","report-2"]}],
         "batches":[]},
   "flip_reasons":[{"kind":"blocker_removed","blocker":{"kind":"active_grant",...}},
                   {"kind":"blocker_added","blocker":{"kind":"open_remediation",...}}]}}
```

语义与保证：

- **后续事件不改变报告**：两侧口径完全由事件序号界定（事件、回执 /
  产物的 `recorded_seq`、处置项开立 `revocation_seq` 与取消
  `grant_seq` 均按上界过滤），同一 `(from_seq, to_seq)` 重复签发
  逐字节一致，与独立只读 `?as_of_seq=` 回放口径相同；并发追加事件
  （含其他主体）不影响报告——跨主体事件从不纳入；
- **处置证据提交 / 复核不携带事件序号**（不是许可 / 撤销事件）：报告
  按请求时点快照原样反映其派生状态（与 §4.7 删除计划查询的口径一致），
  而全部**事件驱动**状态严格按上界过滤；
- `use_at` 是报告锚定的使用时点（随响应回显）；各回执仍按其自身登记
  的 `use_at` 重放（与产品状态、删除计划、合规证明口径一致）；
- **只读**：不写入任何业务表（无需幂等键），结果按产品 ID、回执键与
  事件序号稳定排序；
- **校验**：产品范围为空 `422`；`from_seq >= to_seq` `422`；`to_seq`
  超过当前全局最大事件序号（未来序号）`422`；含主体未知产品 `422`；
  产品在 `to_seq` 之后才登记（两侧快照均不存在）`422`。

### 一键跑完整演示

```bash
./scripts/demo.sh                 # 默认 http://localhost:8000
BASE_URL=http://localhost:8000 ./scripts/demo.sh
```

脚本串起：默认拒绝 → 许可 → 任务/产物登记 → 两组替代依据 →
追溯撤销传播 → 幂等重放 → 历史时点回放 →
撤销处置台账开立 → 接收方提交/驳回/补证/批准 → 案件结案 →
处置结案使登记时 blocked 的删除请求变 stale → 新幂等键重新评估放行 →
删除请求放行（下游先删批次）→ 新许可使计划过期 → 重新评估被活动许可阻断 →
合规证明生成 / 同键重放 / 取回 / 在线与离线独立验签 / 篡改检测 / 校验拒绝 →
合规状态双时点差异报告（撤销 / 恢复 / 新增产品落入区间的分类与翻转原因、
后续事件不改变报告、校验拒绝）。

## 5. 并发与不可变性

- 写事务（许可/撤销/任务登记）隔离级别为 `REPEATABLE READ`，同一主体经
  `pg_advisory_lock(hashtext(subject_id))` 串行化：不同主体并行，同一主体严格串行，
  杜绝“撤销传播扫描”与“新决策登记”竞态。
- **锁先于快照**：REPEATABLE READ 的快照在事务内第一条语句执行时即建立，
  若在事务内用 `SELECT pg_advisory_xact_lock(...)` 取锁，快照会在真正拿到锁
  **之前**就固定——排队期间其他事务提交的撤销 / 回执对该事务不可见
  （撤销的 `affected_receipts` 会漏数、任务登记会沿用旧许可）。因此写路径在
  **事务开始之前**先获取**会话级**咨询锁（`app/db.py` 的
  `transaction(lock_subject=...)`，锁在独立的短隐式事务中获取、由会话持有），
  随后才开启 REPEATABLE READ 事务，事务提交 / 回滚后、连接归还连接池前释放锁。
  由此保证同主体写入按锁获取顺序读取已提交状态：
    - **撤销先获锁提交**：之后才获锁的任务登记即 `deny/revoked`（依据为本次
      撤销），即使其请求在撤销提交前就已到达并排队；
    - **任务先获锁登记**：撤销响应的 `affected_receipts` **恰好**列出其获得
      主体锁之前已登记且被本次撤销失效的回执，不多不少；产物的阻断状态与
      `as_of_seq` 历史回放保持一致。
- 只读端点（决策重放、事件列表、回执 / 产物查询）使用
  `REPEATABLE READ ... READ ONLY` 事务，看到一致快照且 PostgreSQL 拒绝任何写操作。
- 事务属性通过 psycopg3 的**连接属性**设置：在事务开始前设置
  `conn.isolation_level` / `conn.read_only`，由 `conn.transaction()` 发出
  `BEGIN ISOLATION LEVEL REPEATABLE READ [READ ONLY|READ WRITE]`。
  注意 `Connection.transaction()` **不接受** `isolation_level` / `read_only`
  参数（这是 psycopg2 写法，psycopg3 下会直接抛 `TypeError` 导致接口 500）；
  `app/db.py` 的 `transaction()` 统一封装该写法，并在连接归还连接池前恢复
  属性、释放会话级咨询锁，保证连接池复用不被只读 / 隔离级别 / 咨询锁污染。
  正常退出提交、异常回滚、连接获取 / 归还连接池的语义保持不变。
- 同一 `Idempotency-Key` 的并发登记：幂等键是全局主键，而主体锁按主体分区——
  **不同主体**并发使用同一幂等键时互不可见，可能同时未查到既有回执而撞上
  回执主键。服务端识别 `receipts_pkey` 唯一冲突后回滚并用新事务**自动重试**，
  重试时走正常幂等重放（同负载返回首次结果 200，负载不同返回 409），不会返回
  5xx。同主体的同键并发由主体锁串行化，在锁内即可看到先提交的回执。
- 表结构中没有任何更新路径：事件、回执、产物、血缘、处置项、处置证据 / 复核决定
  均只追加。
  回执保存登记当时的不可变决策；`currently_valid`、产物 `status`、处置项状态
  等当前状态全部由重放 / 追加记录即时计算，因此历史回放永远还原历史，结案也不
  改写任何既有记录。
- 处置证据提交与管理员复核同样在 `transaction(lock_subject=...)` 内执行
  （先用只读事务按 `item_id` 定位主体，再取主体锁开写事务）：版本判定与同主体的
  撤销 / 许可追加串行，不会出现并发提交产生同版本两条证据的情况。证据幂等键是
  全局唯一约束，跨主体同键并发冲突时回滚重试，行为与任务登记一致。
- 删除请求登记同样走 `transaction(lock_subject=...)`：与同一主体的许可 /
  撤销 / 任务登记串行，评估读取的是持锁后建立的 REPEATABLE READ 快照；
  幂等键全局唯一（`deletion_requests_idem_uidx`），跨主体同键并发冲突时回滚
  重试，行为与任务登记一致。删除计划查询为只读事务，过期判定在查询时即时
  计算：复用登记时保存的归一化范围（下游闭包回执），以当前事件重放与处置
  台账追加记录重新派生阻断结论，与历史状态 / 阻断原因身份比较——结论变化
  （含处置提交获批 / 取消结案，这类操作不产生主体事件）才标记 stale；
  不改写已登记的计划、批次与阻断原因。
- **合规证明登记**同样走 `transaction(lock_subject=...)`：并发追加事件时，
  证明事务要么完整包含、要么完全不包含某次并发提交（快照在拿到主体锁后才
  建立），同 `as_of_seq` 的并发证明逐字节一致，且与独立只读
  `?as_of_seq=` 回放口径相同；不会读到半提交状态或沿用持锁前旧快照。
  证明事务只读业务表 + INSERT 一行证明；幂等键全局唯一
  （`attestations_idem_uidx`），跨主体同键并发冲突时回滚重试。
  `GET /attestations/{id}` 与 `POST /attestations/verify` 均为只读：
  前者只取登记时保存的字节 / 摘要 / 签名（不重放），后者**完全不访问
  数据库**——验签仅凭提交字节与配置密钥，因此证明的可验证性不受后续业务
  状态变化、运维改库（篡改字节只会使验签失败）或服务重启影响。
- **合规差异报告**（`POST /compliance-diffs`）使用
  `REPEATABLE READ ... READ ONLY` 单快照：两侧（from_seq / to_seq）在
  **同一事务快照**内分别按序号上界重放，不取主体咨询锁、不写任何业务表。
  由于 `seq <= to_seq` 的事件、回执、产物与处置记录全部不可变，并发
  追加的许可 / 撤销（序号必大于 to_seq）对报告不可见——同一
  `(from_seq, to_seq)` 的报告在任意时刻重发逐字节一致；跨主体事件经
  `subject_id` 过滤从不纳入。处置证据提交 / 复核不携带事件序号，其
  派生状态按请求时点快照计入（与删除计划查询的口径一致）。

## 6. 测试

纯领域逻辑（确定性重放、半开区间、替代依据组、血缘传播、解释排序、无环检测、
血缘传递依赖、处置项 / 案件状态机、删除范围下游闭包、删除批次分层、
历史 / 当前结论比较（过期判定）、合规证明规范序列化 / 摘要 / HMAC 验签、
双时点差异分类 added/removed/changed/unchanged）
不依赖第三方库，可直接运行：

```bash
python3 -m unittest discover -s tests -v
```

完整 API 集成测试需要 FastAPI 环境与 PostgreSQL（compose 已就绪）。测试直连
ASGI 应用（httpx in-process），无需启动 uvicorn；可直接连 compose 暴露的
`localhost:5432`：

```bash
pip install -r requirements.txt -r requirements-dev.txt

# 先 docker compose up 起库（暴露 localhost:5432），再运行
DATABASE_URL=postgresql://consent:consent@localhost:5432/consent \
  python3 -m unittest tests.test_api
```

`tests/test_api.py` 覆盖 PostgreSQL 端到端与并发回归：

- 五个核心接口 `/decisions/evaluate`、`/grants`、`/revocations`、`/tasks`
  与只读回执 / 产物查询：**无事件默认查询返回 200 的 deny/no_grant**（核心
  500 回归）、写入提交与回滚、追溯撤销沿血缘传播、`as_of_seq` 历史回放；
- 无许可时登记任务落库 deny 回执并阻断下游；
- 真实连接上校验 `REPEATABLE READ` / `READ ONLY` 生效，以及连接池复用后
  属性不泄漏、写冲突回滚后连接仍可复用；
- 同主体并发追加许可（零丢失）、同幂等键并发登记（恰好一次落库 + 重放）、
  撤销与任务交错并发（咨询锁串行、最终状态自洽）、写入时并发只读重放
  （始终 200）、不同主体并行互不阻塞；
- **撤销处置台账**端到端：撤销同事务开立处置项并关联本次阻断产物、令牌鉴权
  （401/403）、逐版本提交（证据覆盖校验、同键重放 200 / 内容冲突 409 /
  过期版本 409）、驳回后补证、批准后案件结案、许可恢复有效取消未结项、
  再失效另开新项且案件重新 pending、未恢复重复撤销不重复开立、多接收方案件
  独立、结案不改变回执 / 阻断 / 历史回放；
- **删除请求**端到端：活动许可 / 未结处置的可定位阻断、处置结案后放行并生成
  下游先删批次、范围归一化与下游闭包展开、同键重放 200 / 异内容 409 /
  同键并发恰好登记一次、结论变化使计划过期（stale）——**处置提交获批 /
  取消结案（无新事件）同样使历史 blocked 查询变 stale 并要求新幂等键重评**，
  新事件使计划过期、仅事件序号变化但结论不变不误报、历史计划与回执不改写、
  未知产物 / 缺幂等键 / 未知请求 422/404；
- **可控交错回归**（协调连接持有主体会话级咨询锁 + `pg_locks` 轮询排队次序，
  确定性编排锁获取顺序）：撤销先获锁提交时，早已排队的任务登记即
  `deny/revoked` 而非沿用旧快照的 `allow`；任务先获锁登记时，撤销响应的
  `affected_receipts` 恰好等于其获锁前已登记的失效回执；混合队列下产物
  阻断与 `as_of_seq` 历史回放口径一致。
- **合规证明**端到端：同一快照内重放许可 / 撤销 / 血缘 / 处置 / 删除结论，
  撤销后证明 `blocked` + `open_remediation`、撤销前历史证明 `active` +
  `active_grant`、处置结案后新证明 `planned`（下游先删批次）且旧证明字节
  不变；同键重放 200 / 异内容 409 / 新键同内容摘要相同；空范围、未知产品、
  越界 / 早于产品登记的 `as_of_seq`、缺幂等键、未知 ID 的 422/404 拒绝；
  `claim_canonical` 与 `claim` 对象两种验签输入、篡改字节 / 篡改摘要 /
  错密钥分别定位、非十六进制与缺声明 422；**并发追加事件下快照一致性**
  （多证明与撤销并发：同 `as_of_seq` 证明逐字节一致且与独立只读回放口径
  相同，撤销后证明不同而历史证明不改写）；**篡改持久层字节**后验签如实
  失败且验签不读库（未篡改字节 + 原签名仍通过）。
- **合规差异报告**端到端：撤销 / 恢复许可 / 新产品落入区间时的
  added / changed / unchanged 分类与翻转原因定位（撤销序号、命中许可
  切换、处置开立 / 取消、删除阻断身份变化）、from 侧 absent、汇总计数；
  空范围 / from_seq ≥ to_seq / 未来序号 / 未知产品 / 产品晚于 to_seq
  登记的 422 拒绝；跨主体事件与无关事件不误纳入（全部 unchanged、
  basis_seq 只计本主体事件）；处置提交 / 复核按请求快照反映而事件
  严格有界；只读性（任何业务表行数不变）与可重复性（逐字节一致）；
  **并发追加事件（含跨主体）下同一 (from_seq, to_seq) 报告与基线逐字节
  一致**，且两侧与独立只读 `?as_of_seq=` 回放口径相同。

## 7. 目录结构

```
app/
  config.py       运行配置（环境变量；含处置台账管理员 / 接收方令牌与证明 HMAC 密钥）
  db.py           psycopg3 连接池、事务上下文（隔离级别/只读/主体咨询锁）与启动建表
  domain.py       纯领域逻辑：双时点重放 + 血缘阻断 + 处置项状态机 + 删除批次/结论比较 + 双时点差异分类（可单测）
  attestation.py  合规证明：规范 JSON 序列化、SHA-256 摘要、HMAC-SHA256 签名与独立验签（可单测）
  repository.py   只追加 SQL 访问层（事件 / 回执 / 产物 / 处置台账 / 删除请求 / 合规证明）
  service.py      事件追加 / 确定性重放 / 幂等登记 / 撤销传播 / 处置台账 / 删除计划 / 证明编排 / 双时点差异报告
  schemas.py      Pydantic 请求模型
  main.py         FastAPI 路由与 Bearer 令牌鉴权
sql/schema.sql    追加式表结构（含处置项、证据、复核决定、取消记录、删除请求与计划、合规证明）
scripts/demo.sh   端到端示例脚本（含处置台账提交 / 复核 / 结案、删除计划过期、合规证明验签与差异报告）
tests/            领域单元测试 + 证明加密单元测试 + API 集成测试（端到端、处置台账、删除请求、证明、差异报告与并发回归）
```
