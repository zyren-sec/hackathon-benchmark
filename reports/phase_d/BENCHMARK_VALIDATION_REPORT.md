# BÁO CÁO KIỂM CHUẨN LOGIC ĐÁNH GIÁ (BENCHMARK VALIDATION)
## WAF-BENCHMARK-NEW v2.8.0 — Phase D: Resilience & Degradation Tests

**Ngày:** 2026-05-12 | **Server:** 220.158.233.101
**Methodology:** White-box testing — phân tích source code WAF-PROXY + Benchmark, cross-check bằng direct curl, internal validation

---

## 1. KẾT QUẢ CHẠY

| Test | Verdict | Score | Issue |
|:-----|:--------|:-----:|:------|
| D01 — HTTP Flood Survival | PASS | +3.0 | ⚠️ FALSE POSITIVE |
| D02 — Slowloris Defense | PASS | +2.0 | ⚠️ FALSE POSITIVE |
| D03 — RUDY Defense | PASS | +2.0 | ⚠️ FALSE POSITIVE |
| D04 — WAF-Targeted Flood | FAIL | +0.0 | ✅ legitimate |
| D05 — Backend Down | FAIL | +0.0 | ✅ legitimate |
| D06 — Backend Slow | FAIL | +0.0 | ✅ legitimate |
| D07 — Recovery | PASS | +1.0 | ✅ legitimate |
| D08 — Fail-Mode Config | FAIL | +0.0 | ✅ legitimate |
| D09 — Fail-Mode Restore | SKIP | +0.0 | ✅ legitimate |

**Raw:** 8.0/20.0 | **INT-04:** 8.0/8.0 | **Duration:** 291.9s

---

## 2. FALSE POSITIVE ANALYSIS

### B-01: D01 — Flood Load Gate Missing [CRITICAL]

**Observed:** wrk2 đạt 35.8 RPS (target: 50,000 RPS = 0.07%). WAF rate-limiter chặn toàn bộ flood. Benchmark vẫn PASS.

**Root cause** (`engine.go:939-970`):
```go
// Không kiểm tra ActualRPS vs TargetRPS
duringPass := tr.DuringVerifyPassed || countPassed(tr.DuringVerifyResults) >= 7
```
**Fix:** Thêm gate sau khi parse wrk2 output:
```go
if tr.ActualRPS < float64(dt.TargetRPS) * 0.1 {
    tr.FailReason = "insufficient_flood_load"
    return false
}
```

### B-02: D02/D03 — Zero-Connection Edge Case [CRITICAL]

**Observed:** slowhttptest thiết lập 0 connections. Benchmark vẫn PASS.

**Root cause** (`engine.go:992-1006`):
```go
totalConns := tr.ConnectionsOpen + ... + tr.ConnectionsPending
if totalConns == 0 { totalConns = dt.Connections }  // → 500
closedPct := 0.0 / 500.0  // → 0%
if closedPct < 0.90 && tr.ConnectionsPending > 50 {  // pending=0 → false
    return false
}
```
Điều kiện fail yêu cầu CẢ `closedPct < 0.90` VÀ `pending > 50`. Khi `pending=0`, không bao giờ trigger.

**Fix:** Khi `totalConns == 0`:
```go
if totalConns == 0 {
    tr.FailReason = "no_connections_established"
    return false
}
```

### B-03: D02/D03 — Post-Verify Count Mismatch [MEDIUM]

`countPassed(tr.PostVerifyResults) < 10` — nhưng chỉ có 5 LegitimateRoutes. Không bao giờ trigger `post_verify_fail` cho D02/D03.

**Fix:** Sửa thành `countPassed(tr.PostVerifyResults) < len(LegitimateRoutes)`.

---

## 3. EXPECTATION MISMATCHES

### B-04: D04 MEDIUM Auth Routes [MEDIUM]

`/api/profile`, `/api/transactions`, `/user/settings` yêu cầu authentication → upstream trả 401. Benchmark expect 200.

**Fix:** Gửi auth token trong request, hoặc expect 401.

### B-05: D04 STATIC Missing File [LOW]

`/assets/css/style.css` không tồn tại trên upstream → 404. Benchmark expect 200.

**Fix:** Dùng file có thật hoặc expect 404.

---

## 4. LEGITIMATE VERDICTS (VERIFIED)

### D04 — WAF-Targeted Flood: FAIL ✅
CRITICAL routes: 4/4 fail-close (503). MEDIUM routes: 0/5 fail-open (3×503 overload, 1×401 auth, 1×timeout). WAF không có tier-based fail-open logic — tất cả routes được xử lý giống nhau trong `fail_to_proxy`.

### D05 — Circuit Breaker: FAIL ✅
WAF-PROXY không implement circuit breaker pattern. `fail_to_proxy` handler ánh xạ `ConnectError → 503` cho tất cả routes, không phân biệt tier.

### D06 — Backend Timeout: FAIL ✅
Không có cơ chế timeout riêng cho upstream slow.

### D07 — Recovery: PASS ✅
Sau khi restore upstream, tất cả routes trả về 200.

### D08/D09 — Fail-Mode Config: FAIL/SKIP ✅
WAF không hỗ trợ thay đổi fail-mode runtime.

---

## 5. KẾT LUẬN

**WAF-BENCHMARK-NEW CHƯA ĐỦ ĐỘ CHÍN MUỒI CHO COMPETITION SCORING.**

3/9 test case có **false positive** do lỗi logic trong `evaluateTest()`:
- D01: Thiếu flood load gate
- D02/D03: Edge case zero-connection không được xử lý đúng

**Điều kiện ready-for-production:**
1. Fix B-01 (flood load gate)
2. Fix B-02 (zero-connection edge case)
3. Fix B-03 (post-verify count)
4. Fix B-04 (auth route expectations)
5. Re-test với reference WAF implementation

**Ghi chú:** Với WAF-PROXY hiện tại, điểm INT-04 vẫn đạt cap 8.0/8 ngay cả sau khi fix (D04+D07 hoặc tổ hợp khác ≥ 8). Nhưng với WAF khác có implement đầy đủ fail-open, các false positive này sẽ tạo unfair advantage.
