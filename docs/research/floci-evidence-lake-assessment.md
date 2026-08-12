# Floci 作為 evidence lake 的適配性評估

評估日期：2026-08-12

執行更新：2026-08-13
目標：GitHub issue #25（roadmap tracking shorthand `L2+` → `L4 PRODUCTION`；
目前已證 maturity 仍是 `L2 SANDBOX`）

評估版本：Floci commit
[`c21337c3b185ab0c436cdfbc2bede70dadc8330c`](https://github.com/floci-io/floci/tree/c21337c3b185ab0c436cdfbc2bede70dadc8330c).

## 結論

**Floci 可作為 `L2 SANDBOX` 的 AWS 相容性與失敗注入工具，但不能作為
`L4 PRODUCTION` evidence lake，也不能單獨關閉 #25。**

適合用 Floci 驗證的範圍包括 S3 content-addressed object 行為、IAM policy path、
process separation、WAL restart 與 fresh-process replay。這些測試必須經
provider-neutral AWS interface 注入 endpoint；core contracts 不得依賴 Floci 型別。
它們只能證明 adapter/harness 對 AWS-shaped API 的行為，不能證明 production
durability、managed key custody、HA、backup/restore 或 multi-host recovery。

## #25 要求矩陣

| #25 要求 | Floci 可見能力 | 判定 |
| --- | --- | --- |
| external object/blob storage | Floci 是 [local AWS emulator](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/README.md)；S3 API 可作 contract test，但 object 與 metadata 仍落在本機 backend。 | **不符合 L4**。沒有 external/cloud blob backend 的 production evidence。 |
| metadata/index multi-host writers | [storage modes](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/configuration/storage.md) 是 memory 或 local persistent/hybrid/WAL。 | **不符合 L4**。沒有分散式一致性、leader/fencing 或共享 external index 證據。 |
| immutable/content-addressed semantics | S3 emulator 提供 object/versioning/retention API；digest-as-key、append-only ledger 與拒絕 overwrite 是本專案 adapter 的不變量。 | **可測但未符合 L4**。API 存在不證明 WORM 或 host 管理員不可竄改。 |
| KMS/HSM 或 managed signing | KMS Sign/Verify 是 emulator 能力；[KMS grants 不會在 cryptographic operation 中被評估](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/services/kms.md)。 | **不符合 L4**。不是 managed KMS/HSM 或隔離 key custody。 |
| encryption 與 least-privilege IAM | TLS、SigV4 validation 與 IAM enforcement 都需顯式配置；[IAM enforcement](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/services/iam.md) 仍記載 unknown key、unsigned request 與 unmapped action 等 permissive paths。 | **不符合 L4**。可作 policy test double，不能作 production identity boundary 的證據。 |
| retention/deletion | S3 API 可測 retention path；host 仍可刪除本機檔案或 volume。 | **可測但未符合 L4**。缺少管理員邊界與 production retention audit。 |
| backup/restore/corruption recovery | [AWS Backup 是 simulated](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/docs/services/backup.md)，不複製 resource data，restore jobs 未支援。 | **不符合 L4**。沒有可回復資料的 backup、PITR、replication 或 recovery drill。 |
| fresh verifier on another worker | 可從 fresh process 經 HTTP 重讀同一 emulator 的資料。 | **僅符合本次 L2 SANDBOX scope**。同一 single-node emulator 與 volume 不證明 originating service failure 後仍可存活。 |

## 已執行的 sandbox 結果

GitHub PR [#58](https://github.com/ed3c/blackbox-auto-research/pull/58) 合併了
issue [#50](https://github.com/ed3c/blackbox-auto-research/issues/50) 要求的可重播
bundle。Canonical run 是 `floci-sandbox-20260812-10`：

- provider：`floci-emulator`；
- maturity：`L2 SANDBOX`；
- `production_claim_allowed=false`；
- 已驗證 S3 content-addressed round-trip、WAL restart、fresh-process retrieval、
  IAM delete denial 與 teardown；
- 同一 emulator container 經 restart，由兩個獨立 client process 執行 producer 與
  fresh verifier；兩個 phase 分別綁定 container、image、endpoint 與 runner-owned
  immutable CA snapshot；
- wrong-secret Authorization-header `HeadObject` 被 Floci 接受，因此 final decision
  是 `quarantine`；
- SigV4 enforcement gap 由 GitHub issue
  [#56](https://github.com/ed3c/blackbox-auto-research/issues/56) 繼續追蹤。

這個結果完成的是 #50 的「保存成功或 quarantine 的可重播證據」Definition of Done，
不是 Floci qualification。#25 的 roadmap tracking shorthand 仍是 `L2+`，已證 maturity
仍是 `L2 SANDBOX`，沒有升級為 `L3 LIVE` 或 `L4 PRODUCTION`。#25 曾在 acceptance
criteria 全未完成時被錯誤關閉，已於 2026-08-13 重開，繼續作為 production gate。

## 重播與證據

離線重播不需要連線 Floci：

```bash
python3 scripts/verify_floci_sandbox_bundle.py \
  --receipt evidence/floci/floci-sandbox-20260812-10/runner-receipt.json
```

預期輸出包含：

```json
{"bundle_integrity":"verified","decision":"quarantine","run_id":"floci-sandbox-20260812-10","schema":"blackbox-floci-sandbox-run/v3"}
```

Artifact SHA-256：

- IAM policy：`7d5d46fefc0762f3cdea35fe4d218a21cbcfee46b50a9a4bc1820fad77b95c70`；
- input payload：`da3f4ffac5da5a30f9d42807ddb5fd76123d0111c4269d5d6257a9190d349030`；
- producer manifest：`b13f3006788aeec469a855484d1281515d9a967971893d325b90ae272f4420bb`；
- fresh-process verifier receipt：`f9d849c809f0f5dcbcfc6bd9871c687b51c7da7512dfeeb58919de4f4c92b4b1`；
- final runner receipt：`3367fc734b415618ec11bfa39ead7324696b016949a9eefe9d43eba73a761bd0`。

## Production 前仍需證明

- external object/blob store；
- 適用 multi-host writers 的 production metadata/index service；
- managed KMS/HSM 或等價 signing boundary；
- encryption 與 least-privilege IAM；
- retention/deletion enforcement；
- backup/restore、corruption recovery 與 drift detection；
- multi-host concurrency／failure recovery；
- 另一個獨立 worker 能取回 evidence、驗證 managed provenance 並重現 decision；
- observability、SLO、cost、staged rollout 與 rollback。

Floci 使用 [MIT License](https://github.com/floci-io/floci/blob/c21337c3b185ab0c436cdfbc2bede70dadc8330c/LICENSE)，
在授權上可作開發與 CI dependency；這不改變上述 runtime maturity 判定。
