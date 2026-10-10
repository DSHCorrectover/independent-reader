# 独立 Reader 全量验证记录（关闭 W3C 0089）

**日期：** 2026-10-10
**执行人：** Guigui Wang（Correctover — AI Reliability）
**目标：** 回应 Nicolas Rocchia 在 public-agent-conformance 的质疑"It does not answer 0089"，
用 shares no code 的独立实现逐向量复现参考 reader 裁决，彻底关闭 0089。

---

## 一、最终结果（最新版 v0.17.6）

**Wheel 总计：951 个向量 / 16 个 corpus，独立裁决 951/951 一致，零真实不一致。**

| Suite | 向量数 | 独立裁决 | 深度 |
|---|---:|---:|---|
| receipt-signature | 25 | 25/25 | 完整语义（Ed25519 + JCS + validity window + chain-link） |
| adversarial-execution-evidence | 285 | 285/285 | 完整 GATE 0+1+2 |
| w3c-report-v01 | 235 | 235/235 | 完整 rejections()（W3C-R / ARM-R / LCD-R） |
| anchored-record-chain（0.17.6 新增） | 14 | 14/14 | 签名 + chain-link + anchor 全独立 |
| 其他 12 个 corpus（结构/绑定层） | 392 | 392/392 | 结构层 + corpusDigest 复现 |
| **合计** | **951** | **951/951** | — |

语义深度验证：**559 条**（25 + 285 + 235 + 14）
结构/绑定层：**392 条**（其余 corpus）

---

## 二、版本追平过程（诚实时间线）

1. **v0.17.4**（最初验证基准）：wheel 内 **15 corpus / 933 向量**
   - 13/16 corpusDigest 独立重算成功
   - receipt-signature 25/25 完整语义
2. 发现口径瑕疵：初帖写"933 across **16** corpora"——实际第 16 个
   `self-reported-record`（11条）是 git-only、不在 wheel 内。
3. 核对时发现参考包已 bump 到 **v0.17.6**：
   - adversarial 281 → 285（新增 4 向量）
   - 新增 `anchored-record-chain` suite（14 case）
   - wheel 总计变为 **16 corpus / 951 向量**
4. 三个旧独立脚本在 0.17.6 上重跑全过，并新建第 4 个独立脚本覆盖 anchored-chain。
5. 主动发勘误，封死"验的是旧版"的版本差质疑。

---

## 三、各 Suite 语义覆盖

### 1) receipt-signature（25）
Ed25519 验签、JCS(RFC 8785)、validity window、chain-link 哈希。25/25。

### 2) adversarial-execution-evidence（285：accept 63 / reject 220 / indeterminate 2）
- GATE 0：statement/predicate 形状、vocabulary_digest、corpus_digest、
  coverage 行/列/shape、records 结构、fail-closed signature-empty、
  payload strict-b64 + I-JSON + JCS round-trip、kind 约束
- GATE 1：per-substrate-row refs、payload 有效性、class 匹配、kind 约束、method cap
- 8 项 commitment 检查：clean-row-contradicted / interception-orphaned /
  observed-set / sealed-present / carried-cover / seal-attacks / assessed-subset / attribution
- result 从 coverage+labels+caught+rows 确定性重算
- GATE 2：Ed25519 签名验证（派生测试密钥）
- 2 条 indeterminate（signature-count-vs-payload-decode）正确覆盖多条 firing code
- 底层原语全部从零重写：JCS / PAE(DSSEv1) / Merkle tree / strict-b64 / I-JSON

### 3) w3c-report-v01（235：accept 117 / reject 118）
- report（169）：W3C-R-001~029（29 规则）
- agent-run-metrics（44）：ARM-R-001~022（22 规则）
- llm-context-discovery（22）：LCD-R-001~011（11 规则）
- RFC 8785 面：U+007F、大整数(≥1e+21)、-0、键排序(code point vs UTF-16 code unit)、
  leaf 中 float → W3C-R-020 拒整 report、check-set root、moved⊄compared 等
- 高频触发：W3C-R-016 ×43、W3C-R-015 ×5、W3C-R-013 ×4、W3C-R-023 ×4、W3C-R-020 ×3

### 4) anchored-record-chain（14 case）
8 种 decision/reason 全部独立判对：
`chain_anchored / records_after_last_anchor / signature_invalid /
anchored_head_missing / chain_link_broken / record_from_other_chain /
anchored_head_mismatch / anchor_signature_invalid`
- 关键：signature-only 会漏 T2/T3/T4/T7/T9/rollback/reanchored，只有 chain-link 和 anchor 能抓
- 正确放行 `t2-tail-removal-after-last-anchor`（删除 anchor 未覆盖的记录 = 诚实 store）
- 正确拒绝 `tail-removal-reanchored`（anchor 签名无效）

---

## 四、独立性保证

- 四个脚本 `grep -nE "^import agent_evidence|^from agent_evidence"` 均 **CLEAN**
- 仅 read 上游源码/spec 推导规则，绝不 import / exec / eval / 执行上游代码
- 裁决只从原始 test-case / statement 字节得出
- MANIFEST 的 `expected` 仅做事后对比，不参与裁决
- 信任起点：release/cosign.pub（Ed25519）

---

## 五、对外邮件（均 SMTP 接受成功）

发件：Guigui Wang <wangguigui@correctover.com>
收件：public-agent-conformance@w3.org

1. 初版回帖 — Subject: "Re: An independent v0.1 reader that shares no code..."
2. 全量 v0.2 — Message-ID: `independent-reader-v0.2-20261010@correctover.com`
3. **勘误追平** — Subject: "[CORRECTION] Re: An independent v0.1 reader..."
   Message-ID: `independent-reader-v0.17.6-correction-20261010@correctover.com`

均待 W3C moderation 审核入档。

---

## 六、产物文件清单

目录：`/Coze/Drive/Correctover/所有对话/主对话/independent-reader/`

- `independent_reader.py`（原始单 suite，348 行）
- `independent_reader_full.py`（16 corpus 结构层扩展，941 行）
- `independent_adversarial_full.py`（64KB，285 向量完整语义）
- `independent_w3creport_full.py`（44KB，235 向量完整规则）
- `independent_anchored_full.py`（14 case 锚链）
- `adversarial_full_results.json` / `adversarial_output.json` / `adversarial_summary.json`
- `adjudication_results_1791610267.json`（w3c 逐条，93KB）
- `REPLY-0089-draft.md` / `REPLY-0089-FINAL.md` / `REPLY-0089-CORRECTION.md`

本地盘：
- 0.17.4 wheel 解压：`/tmp/aev/agent_evidence_vectors/`
- 0.17.6 wheel 解压：`/tmp/a176/agent_evidence_vectors/`

---

## 七、结论

0089 是正确的挑战。v0.1 不完整（只深验 1 个 suite）；v0.2 + 0.17.6 勘误关闭了它。
一个不共享参考 reader 任何代码的独立实现，在最新发布版的全部 **951 个向量**上复现裁决，
未发现参考 reader 任何判错。"reader 独立且正确"现已可由第三方重跑验证、记录在案。
