#!/usr/bin/env bash
# 端到端演示：许可 -> 决策登记/产物血缘 -> 追溯撤销传播 -> 幂等重放 -> 历史时点回放
# -> 撤销处置台账 -> 删除请求（下游先删批次）-> 计划过期与重新评估。
# 依赖：curl、python3；目标：http://localhost:8000（docker compose up 后）。
set -euo pipefail
BASE="${BASE_URL:-http://localhost:8000}"
PP='python3 -m json.tool'

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$1"; }
post() { curl -sS -X POST "$BASE$1" -H 'Content-Type: application/json' "${@:2}"; }
get()  { curl -sS "$BASE$1"; }

# 处置台账令牌（与 docker-compose.yml 本地默认配置一致）。
ADMIN_AUTH=(-H 'Authorization: Bearer dev-admin-token')
PARTNER_A_AUTH=(-H 'Authorization: Bearer dev-token-a')

say "0. 健康检查"
get /health | $PP

say "1. 默认拒绝（没有任何许可）"
post /decisions/evaluate -d '{
  "subject_id":"u1","category":"email","purpose":"marketing",
  "recipient":"partner-x","use_at":"2026-05-01T00:00:00Z"}' | $PP

say "2. 登记两个重叠许可 g1、g2（半开区间 2026-01-01 起，开放结束）"
post /grants -d '{
  "subject_id":"u1","grant_id":"g1","category":"email","purpose":"marketing",
  "recipient":"partner-a","valid_from":"2026-01-01T00:00:00Z"}' | $PP
post /grants -d '{
  "subject_id":"u1","grant_id":"g2","category":"email","purpose":"marketing",
  "recipient":"partner-a","valid_from":"2026-01-01T00:00:00Z"}' | $PP

say "3. 登记任务 task-1（命中最新许可 g2，allow）+ 产物 report-1"
post /tasks -H 'Idempotency-Key: task-1' -d '{
  "subject_id":"u1","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z",
  "products":[{"product_id":"report-1","description":"营销报表",
               "groups":[[{"kind":"receipt","ref":"task-1"}]]}]}' | $PP

say "4. 登记任务 task-2（allow）+ 产物 report-2，两组替代依据：[task-1] 或 [task-2]"
post /tasks -H 'Idempotency-Key: task-2' -d '{
  "subject_id":"u1","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z",
  "products":[{"product_id":"report-2",
               "groups":[[{"kind":"receipt","ref":"task-1"}],
                         [{"kind":"receipt","ref":"task-2"}]]}]}' | $PP

say "5. 追溯撤销 g1（业务生效 2026-01-15，早于 5 月的使用）"
REV1=$(post /revocations -d '{
  "subject_id":"u1","grant_id":"g1",
  "business_effective_at":"2026-01-15T00:00:00Z"}')
echo "$REV1" | $PP
REV1_SEQ=$(echo "$REV1" | python3 -c 'import sys,json;print(json.load(sys.stdin)["event"]["seq"])')

say "6. task-1/task-2 命中的是 g2，故 report-1/report-2 仍存活"
get /subjects/u1/products/report-2 | $PP

say "7. 追溯撤销 g2（被命中的最新许可）-> 两个回执失效"
post /revocations -d '{
  "subject_id":"u1","grant_id":"g2",
  "business_effective_at":"2026-01-15T00:00:00Z"}' | $PP

say "8. report-1 阻断；report-2 两组均失效才阻断，解释取事件数最少、事件 ID 最小"
get /subjects/u1/products/report-1 | $PP
get /subjects/u1/products/report-2 | $PP

say "9. 幂等重放：同 key 同负载返回首次结果（回执内容未改写，当前状态显示已失效）"
post /tasks -H 'Idempotency-Key: task-1' -d '{
  "subject_id":"u1","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z",
  "products":[{"product_id":"report-1","description":"营销报表",
               "groups":[[{"kind":"receipt","ref":"task-1"}]]}]}' | $PP

say "10. 历史回放：as_of_seq 取 g2 撤销之前，旧记录未被改写，决策 allow / 产物 active"
post "/decisions/evaluate?as_of_seq=$((REV1_SEQ-1))" -d '{
  "subject_id":"u1","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z"}' | $PP
get "/subjects/u1/products/report-1?as_of_seq=$((REV1_SEQ-1))" | $PP

say "11. 撤销处置台账：第 7 步撤销 g2 时已在同事务为失效回执开立处置项"
CASE=$(get /subjects/u1/remediation "${PARTNER_A_AUTH[@]}")
echo "$CASE" | $PP
echo "（接收方凭令牌只能查看自己的处置项；该接收方全部处置项获批前案件保持 pending）"

say "12. 接收方逐项提交：版本 1 被驳回，补证版本 2 后管理员批准"
python3 - "$BASE" <<'PY'
import json, subprocess, sys
base = sys.argv[1]
RA = ["-H", "Authorization: Bearer dev-token-a"]
AD = ["-H", "Authorization: Bearer dev-admin-token"]
case = json.loads(subprocess.check_output(
    ["curl", "-sS", f"{base}/subjects/u1/remediation", *RA]))
for item in case["items"]:
    iid = item["item_id"]
    products = item["products"]
    def submit(version, key, decl, summary):
        body = json.dumps({
            "version": version, "cease_declaration": decl,
            "evidence": [{"product_id": p, "summary": f"{summary}:{p}"}
                         for p in products]})
        out = subprocess.check_output(
            ["curl", "-sS", "-X", "POST",
             f"{base}/remediation/items/{iid}/submissions",
             "-H", "Content-Type: application/json",
             "-H", f"Idempotency-Key: {key}", *RA, "-d", body])
        print(json.dumps(json.loads(out), ensure_ascii=False, indent=2))
    def review(version, action, comment):
        body = json.dumps({"version": version, "action": action,
                           "comment": comment})
        out = subprocess.check_output(
            ["curl", "-sS", "-X", "POST",
             f"{base}/remediation/items/{iid}/reviews",
             "-H", "Content-Type: application/json", *AD, "-d", body])
        print(json.dumps(json.loads(out), ensure_ascii=False, indent=2))
    submit(1, f"rem-{iid}-v1", "已停止使用", "初版证据")
    review(1, "reject", "证据不足")
    submit(2, f"rem-{iid}-v2", "已停止使用并清除全部派生产物", "清除+审计")
    review(2, "approve", "证据齐备，准予结案")
PY

say "13. 全部处置项获批 -> 案件结案（closed）；后续新增失效将重新显示 pending"
get /subjects/u1/remediation "${PARTNER_A_AUTH[@]}" | $PP

say "13b. 处置结案前登记的 blocked 删除请求：结案后无新事件，查询仍应 stale=true"
# 先构造一个带未结处置项的主体 u2：许可 -> 任务/产物 -> 追溯撤销开立处置项。
post /grants -d '{
  "subject_id":"u2","grant_id":"g1","category":"email","purpose":"marketing",
  "recipient":"partner-a","valid_from":"2026-01-01T00:00:00Z"}' >/dev/null
post /tasks -H 'Idempotency-Key: u2-task-1' -d '{
  "subject_id":"u2","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z",
  "products":[{"product_id":"report-1",
               "groups":[[{"kind":"receipt","ref":"u2-task-1"}]]}]}' >/dev/null
post /revocations -d '{
  "subject_id":"u2","grant_id":"g1",
  "business_effective_at":"2026-01-15T00:00:00Z"}' >/dev/null
DELB=$(post /deletion-requests -H 'Idempotency-Key: u2-del-blocked' -d '{
  "subject_id":"u2","product_ids":[],
  "requested_at":"2026-09-26T08:00:00Z"}')
echo "$DELB" | $PP
U2_ITEM=$(echo "$DELB" | python3 -c 'import sys,json;print(json.load(sys.stdin)["blockers"][0]["item_id"])')
# 提交 + 批准：处置结案，不新增任何许可 / 撤销。
curl -sS -X POST "$BASE/remediation/items/$U2_ITEM/submissions" \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer dev-token-a' \
  -H 'Idempotency-Key: u2-rem-v1' -d '{
    "version":1,"cease_declaration":"已停止使用",
    "evidence":[{"product_id":"report-1","summary":"已删除，见 OPS-2"}]}' | $PP
curl -sS -X POST "$BASE/remediation/items/$U2_ITEM/reviews" \
  -H 'Content-Type: application/json' -H 'Authorization: Bearer dev-admin-token' \
  -d '{"version":1,"action":"approve","comment":"准予结案"}' | $PP
echo '-> 同一 blocked 请求现在应为 stale:true（历史 status 仍为 blocked）：'
get "/deletion-requests/$(echo "$DELB" | python3 -c 'import sys,json;print(json.load(sys.stdin)["request_id"])')" | $PP
echo '-> 用新幂等键重新评估：处置已结案 -> planned。'
post /deletion-requests -H 'Idempotency-Key: u2-del-planned' -d '{
  "subject_id":"u2","product_ids":[],
  "requested_at":"2026-09-26T09:00:00Z"}' | $PP

say "14. 撤销后登记 task-3（回执为 deny）+ 产物 report-3（依赖 report-1，构成链）"
post /tasks -H 'Idempotency-Key: task-3' -d '{
  "subject_id":"u1","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z",
  "products":[{"product_id":"report-3",
               "groups":[[{"kind":"product","ref":"report-1"}]]}]}' | $PP

say "15. 提交删除请求（空 product_ids = 全部产物）：处置已结案 -> 生成下游先删的批次"
DEL=$(post /deletion-requests -H 'Idempotency-Key: del-1' -d '{
  "subject_id":"u1","product_ids":[],
  "requested_at":"2026-09-26T08:00:00Z"}')
echo "$DEL" | $PP
DEL_ID=$(echo "$DEL" | python3 -c 'import sys,json;print(json.load(sys.stdin)["request_id"])')

say "16. 幂等重放：同键同内容返回原计划（200，idempotent_replay:true）"
post /deletion-requests -H 'Idempotency-Key: del-1' -d '{
  "subject_id":"u1","product_ids":[],
  "requested_at":"2026-09-26T08:00:00Z"}' | $PP

say "17. 追加新许可 g3 -> 查询计划标记过期（stale:true），历史批次不改写"
post /grants -d '{
  "subject_id":"u1","grant_id":"g3","category":"email","purpose":"marketing",
  "recipient":"partner-a","valid_from":"2026-01-01T00:00:00Z"}' | $PP
get "/deletion-requests/$DEL_ID" | $PP

say "18. 用新幂等键重新评估：许可恢复有效 -> 被 active_grant 阻断（原因可定位）"
post /deletion-requests -H 'Idempotency-Key: del-2' -d '{
  "subject_id":"u1","product_ids":[],
  "requested_at":"2026-09-26T09:00:00Z"}' | $PP

# ---------------------------------------------------------------- 合规证明
say "19. 合规证明：独立主体 u3 —— 许可 -> 任务/产物 -> 追溯撤销 -> 开立处置"
post /grants -d '{
  "subject_id":"u3","grant_id":"g1","category":"email","purpose":"marketing",
  "recipient":"partner-a","valid_from":"2026-01-01T00:00:00Z"}' >/dev/null
post /tasks -H 'Idempotency-Key: u3-task-1' -d '{
  "subject_id":"u3","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z",
  "products":[{"product_id":"report-1",
               "groups":[[{"kind":"receipt","ref":"u3-task-1"}]]},
              {"product_id":"report-2",
               "groups":[[{"kind":"product","ref":"report-1"}]]}]}' >/dev/null
U3_REV=$(post /revocations -d '{
  "subject_id":"u3","grant_id":"g1",
  "business_effective_at":"2026-01-15T00:00:00Z"}')
U3_SEQ=$(echo "$U3_REV" | python3 -c 'import sys,json;print(json.load(sys.stdin)["event"]["seq"])')

say "19a. 幂等提交合规证明（同一 REPEATABLE READ 快照内重放全部依据）"
ATT=$(post /attestations -H 'Idempotency-Key: u3-att-1' -d "{
  \"subject_id\":\"u3\",\"product_ids\":[\"report-1\",\"report-2\"],
  \"use_at\":\"2026-05-01T00:00:00Z\",\"as_of_seq\":$U3_SEQ}")
echo "$ATT" | $PP
ATT_ID=$(echo "$ATT" | python3 -c 'import sys,json;print(json.load(sys.stdin)["attestation_id"])')

say "19b. 同键同内容重放 -> 200 原证明（摘要/签名字节不变）"
post /attestations -H 'Idempotency-Key: u3-att-1' -d "{
  \"subject_id\":\"u3\",\"product_ids\":[\"report-2\",\"report-1\",\"report-1\"],
  \"use_at\":\"2026-05-01T00:00:00Z\",\"as_of_seq\":$U3_SEQ}" | $PP

say "19c. GET 取回保存的原始字节/摘要/签名（后续事件不改写既有证明）"
get "/attestations/$ATT_ID" | $PP

say "19d. 独立验签：仅依赖声明字节 + 摘要 + 签名 + 配置密钥（不读业务状态）"
ATT_JSON="$ATT" python3 - "$BASE" <<'PY'
import json, os, subprocess, sys
att = json.loads(os.environ["ATT_JSON"])
base = sys.argv[1]
def verify(body):
    out = subprocess.run(
        ["curl","-sS","-X","POST",f"{base}/attestations/verify",
         "-H","Content-Type: application/json","-d",json.dumps(body)],
        capture_output=True, text=True).stdout
    return json.loads(out)
# 1) 原字节 -> valid:true
ok = verify({"claim_canonical": att["claim_canonical"],
             "digest": att["digest"], "signature": att["signature"]})
print("原字节验签:", json.dumps(ok, ensure_ascii=False))
assert ok["valid"]
# 2) 用 claim 对象（固定字段重规范化）-> valid:true
ok2 = verify({"claim": att["claim"], "digest": att["digest"],
              "signature": att["signature"]})
print("claim 对象验签:", json.dumps(ok2, ensure_ascii=False))
assert ok2["valid"]
# 3) 篡改一个字节（claim_canonical 中改产品 ID）-> digest/signature 均 false
tampered = att["claim_canonical"].replace("report-2", "report-X", 1)
bad = verify({"claim_canonical": tampered, "digest": att["digest"],
              "signature": att["signature"]})
print("篡改字节验签:", json.dumps(bad, ensure_ascii=False))
assert not bad["valid"] and not bad["digest_ok"] and not bad["signature_ok"]
PY

say "19e. 完全离线验签（标准库，不访问服务 / 数据库）"
ATT_JSON="$ATT" python3 - <<'PY'
import hashlib, hmac, json, os
att = json.loads(os.environ["ATT_JSON"])
key = "dev-attestation-hmac-key"   # 对应 ATTESTATION_HMAC_KEY
cb = att["claim_canonical"].encode("utf-8")
digest_ok = hashlib.sha256(cb).hexdigest() == att["digest"]
sig_ok = hmac.compare_digest(
    hmac.new(key.encode(), cb, hashlib.sha256).hexdigest(), att["signature"])
print(f"digest_ok={digest_ok} signature_ok={sig_ok} valid={digest_ok and sig_ok}")
assert digest_ok and sig_ok
PY

say "19f. 校验：空范围 / 未知产品 / 越界 as_of_seq 均 422；同键异内容 409"
post /attestations -H 'Idempotency-Key: u3-bad1' -d "{
  \"subject_id\":\"u3\",\"product_ids\":[],
  \"use_at\":\"2026-05-01T00:00:00Z\",\"as_of_seq\":$U3_SEQ}"
post /attestations -H 'Idempotency-Key: u3-bad2' -d "{
  \"subject_id\":\"u3\",\"product_ids\":[\"ghost\"],
  \"use_at\":\"2026-05-01T00:00:00Z\",\"as_of_seq\":$U3_SEQ}"
post /attestations -H 'Idempotency-Key: u3-bad3' -d '{
  "subject_id":"u3","product_ids":["report-1"],
  "use_at":"2026-05-01T00:00:00Z","as_of_seq":999999999}'
post /attestations -H 'Idempotency-Key: u3-att-1' -d "{
  \"subject_id\":\"u3\",\"product_ids\":[\"report-1\"],
  \"use_at\":\"2026-05-01T00:00:00Z\",\"as_of_seq\":$U3_SEQ}"

say "20. 合规状态双时点差异报告（只读、不落库）：独立主体 u4"
# 许可 g1 -> 任务/产物链 p1<-p2 -> 追溯撤销（开立处置项）-> 新许可恢复。
post /grants -d '{
  "subject_id":"u4","grant_id":"g1","category":"email","purpose":"marketing",
  "recipient":"partner-a","valid_from":"2026-01-01T00:00:00Z"}' >/dev/null
U4_G=$(get /subjects/u4/events | python3 -c 'import sys,json;print(json.load(sys.stdin)["events"][0]["seq"])')
post /tasks -H 'Idempotency-Key: u4-task-1' -d '{
  "subject_id":"u4","category":"email","purpose":"marketing",
  "recipient":"partner-a","use_at":"2026-05-01T00:00:00Z",
  "products":[{"product_id":"report-1",
               "groups":[[{"kind":"receipt","ref":"u4-task-1"}]]},
              {"product_id":"report-2",
               "groups":[[{"kind":"product","ref":"report-1"}]]}]}' >/dev/null
U4_REV=$(post /revocations -d '{
  "subject_id":"u4","grant_id":"g1",
  "business_effective_at":"2026-01-15T00:00:00Z"}')
U4_REV_SEQ=$(echo "$U4_REV" | python3 -c 'import sys,json;print(json.load(sys.stdin)["event"]["seq"])')
post /grants -d '{
  "subject_id":"u4","grant_id":"g2","category":"email","purpose":"marketing",
  "recipient":"partner-a","valid_from":"2026-01-01T00:00:00Z"}' >/dev/null
U4_END=$(get /subjects/u4/events | python3 -c 'import sys,json;print(json.load(sys.stdin)["events"][-1]["seq"])')

say "20a. from=许可上界 -> to=撤销上界：产品/回执 changed，处置项 added（可定位撤销序号）"
post /compliance-diffs -d "{
  \"subject_id\":\"u4\",\"product_ids\":[\"report-1\",\"report-2\"],
  \"use_at\":\"2026-05-01T00:00:00Z\",
  \"from_seq\":$U4_G,\"to_seq\":$U4_REV_SEQ}" | $PP

say "20b. from=撤销上界 -> to=恢复许可上界：回执恢复（grant_restored）、处置项取消（item_cancelled）"
post /compliance-diffs -d "{
  \"subject_id\":\"u4\",\"product_ids\":[\"report-1\",\"report-2\"],
  \"use_at\":\"2026-05-01T00:00:00Z\",
  \"from_seq\":$U4_REV_SEQ,\"to_seq\":$U4_END}" | $PP

say "20c. 校验：from_seq>=to_seq / 未来序号 / 未知产品 / 空范围 均 422"
post /compliance-diffs -d "{
  \"subject_id\":\"u4\",\"product_ids\":[\"report-1\"],
  \"use_at\":\"2026-05-01T00:00:00Z\",
  \"from_seq\":$U4_END,\"to_seq\":$U4_END}"; echo
post /compliance-diffs -d '{
  "subject_id":"u4","product_ids":["report-1"],
  "use_at":"2026-05-01T00:00:00Z","from_seq":1,"to_seq":999999999}'; echo

say "完成。事件登记处（append-only，只增不改）："
get /subjects/u1/events | $PP
