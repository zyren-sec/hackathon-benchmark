# Phase E — Caching Correctness Benchmark Blueprint (Spec §7.2)

Nguồn chuẩn chính: [EN_WAF Hackathon - Benchmark Specification v2.md](EN_WAF Hackathon - Benchmark Specification v2.md:350).  
Nguồn bổ sung test matrix: [exploit_catalogue.md](exploit_catalogue.md:506).  
Nguồn interop/cache semantics: [EN_WAF Hackathon - WAF Interop Contract v2.1.md](EN_WAF Hackathon - WAF Interop Contract v2.1.md:215).

---

## 0) Mục tiêu tài liệu
Tài liệu này định nghĩa cho benchmark tool phần **Caching correctness** trong Phase E:
1. Workflow benchmark phải chạy gì.
2. WAF cần trả gì để PASS, không đạt gì thì FAILED.
3. Tiêu chí chấm PASS chính thức.
4. Bộ chỉ số bổ sung sau PASS để so sánh team nào PASS tốt hơn (không đổi PASS/FAILED).

Phạm vi: chỉ bao phủ `E01..E04` theo [Spec §7.2](EN_WAF Hackathon - Benchmark Specification v2.md:350) và [exploit_catalogue.md](exploit_catalogue.md:506).

### 0.1) Giải thích thuật ngữ tier để AI/tool hiểu thống nhất
- **CRITICAL tier**: endpoint nhạy cảm, rủi ro cao, yêu cầu không cache. Theo interop: CRITICAL **NEVER cached** tại [EN_WAF Hackathon - WAF Interop Contract v2.1.md](EN_WAF Hackathon - WAF Interop Contract v2.1.md:219).
- **HIGH tier (auth/dynamic)**: endpoint động, thường có session/user context; mặc định không cache. Theo interop: HIGH **Not cached by default** tại [EN_WAF Hackathon - WAF Interop Contract v2.1.md](EN_WAF Hackathon - WAF Interop Contract v2.1.md:220).
- **HIGH-auth** (cách gọi rút gọn trong tài liệu này): endpoint HIGH có yêu cầu xác thực/session hợp lệ (`sid`), ví dụ `GET /api/profile` ở E04.
- **MEDIUM tier**: static/public assets (ví dụ `/static/*`) được kỳ vọng cache tích cực. Theo interop: MEDIUM **Aggressively cached** tại [EN_WAF Hackathon - WAF Interop Contract v2.1.md](EN_WAF Hackathon - WAF Interop Contract v2.1.md:221).
- **CATCH-ALL tier**: route còn lại không thuộc các tier trên; mặc định không cache theo interop tại [EN_WAF Hackathon - WAF Interop Contract v2.1.md](EN_WAF Hackathon - WAF Interop Contract v2.1.md:222).

---

## 1) Workflow benchmark tổng thể cho E — Caching correctness

### 1.1 Pre-check chung trước E01..E04
1. Gọi `POST /__control/reset` để đảm bảo app state sạch.
2. Verify `GET :9000/health` và `GET :8080/health`.
3. Đồng bộ metadata run:
   - `run_id`, `team_id`, `waf_version`, `benchmark_version`, `environment_tag`, `started_at_utc`.
4. Thiết lập user/session cho case cần auth:
   - E02 cần login hợp lệ.
   - E04 cần session hợp lệ (`sid`).
5. Đồng bộ clock monotonic để đo latency ổn định.

### 1.2 Thứ tự chạy case
Chạy theo thứ tự cố định:
- E01 → E02 → E03 → E04.

Lý do:
- E01/E03 dùng MEDIUM static cache behavior (nhóm route được phép cache).
- E02 kiểm tra CRITICAL không cache; E04 kiểm tra HIGH-auth (auth/dynamic có session) không cache.
- Chạy theo thứ tự giúp report dễ đối chiếu với [Spec §7.2](EN_WAF Hackathon - Benchmark Specification v2.md:350).

### 1.3 Chuẩn thu thập dữ liệu cho mọi case
Mỗi case lưu:
- `case_id`, `start_ts`, `end_ts`
- request/response pair theo thứ tự call
- `status_code`, `latency_ms`
- header cache quan trọng: `X-WAF-Cache` nếu có theo [interop header](EN_WAF Hackathon - WAF Interop Contract v2.1.md:98)
- bằng chứng logic PASS/FAIL (token khác nhau, cache hit/miss, TTL expiry)

---

## 2) PASS/FAILED theo từng test E01–E04

## E01 — MEDIUM cached
Ref: [Spec E01](EN_WAF Hackathon - Benchmark Specification v2.md:354), [Catalogue E01](exploit_catalogue.md:510), [Interop tier cache](EN_WAF Hackathon - WAF Interop Contract v2.1.md:221)

- Workflow:
  1. Gửi `GET /static/js/app.js` lần 1.
  2. Trong vòng <=1s, gửi lại request identical lần 2.
- PASS khi (1 trong 2 điều kiện đúng):
  - Response lần 2 có `X-WAF-Cache: HIT`, hoặc
  - latency lần 2 `< 1ms` (cache infer theo interop) tại [interop rule](EN_WAF Hackathon - WAF Interop Contract v2.1.md:224).
- FAILED khi:
  - lần 2 không có dấu hiệu cache (`HIT` absent và cũng không nhanh hơn ngưỡng infer), hoặc
  - behavior không nhất quán giữa các lần lặp.

## E02 — CRITICAL never cached
Ref: [Spec E02](EN_WAF Hackathon - Benchmark Specification v2.md:355), [Catalogue E02](exploit_catalogue.md:511), [Interop tier cache](EN_WAF Hackathon - WAF Interop Contract v2.1.md:219)

- Workflow:
  1. Gửi `POST /login` hợp lệ lần 1 (cùng user).
  2. Trong vòng <=1s, gửi lại `POST /login` hợp lệ lần 2 với cùng user.
  3. Trích `login_token` từ cả 2 response.
- PASS khi:
  - `login_token` lần 1 và lần 2 **khác nhau** (chứng minh cả hai cùng lên upstream, không replay cache).
- FAILED khi:
  - token trùng nhau,
  - hoặc có dấu hiệu response cache trên CRITICAL (trái với [interop](EN_WAF Hackathon - WAF Interop Contract v2.1.md:219)).

## E03 — TTL expiry honored
Ref: [Spec E03](EN_WAF Hackathon - Benchmark Specification v2.md:356), [Catalogue E03](exploit_catalogue.md:512)

- Workflow:
  1. Gửi `GET /static/css/style.css` để warm cache.
  2. Chờ `max-age + 1s` (spec mặc định 3601s; benchmark có thể dùng TTL test rút gọn theo note spec).
  3. Gửi lại cùng request.
- PASS khi:
  - request sau TTL là cache miss (không phải HIT từ object cũ).
- FAILED khi:
  - vẫn HIT object cũ sau khi TTL đã hết,
  - hoặc TTL handling không deterministic.

## E04 — Auth routes never cached
Ref: [Spec E04](EN_WAF Hackathon - Benchmark Specification v2.md:357), [Catalogue E04](exploit_catalogue.md:513), [Interop tier cache](EN_WAF Hackathon - WAF Interop Contract v2.1.md:220)

- Workflow:
  1. Đăng nhập lấy session `sid`.
  2. Gửi `GET /api/profile` lần 1 với session hợp lệ.
  3. Trong <=1s, gửi lại cùng request lần 2 với cùng session.
- PASS khi:
  - cả hai lần đều hit upstream (không có cache hit trên auth route),
  - latency 2 lần "comparable" (không speedup bất thường do cache).
- FAILED khi:
  - có dấu hiệu cache HIT,
  - hoặc lần 2 nhanh bất thường kiểu cached artifact.

---

## 3) Tiêu chí chấm PASS chính thức

### 3.1 PASS/FAILED từng case
- `E01`: pass nếu đạt đúng tiêu chí E01.
- `E02`: pass nếu token khác nhau.
- `E03`: pass nếu TTL expiry tạo miss.
- `E04`: pass nếu auth route không cache.

### 3.2 PASS cho toàn bộ phần Caching correctness
`phase_e_caching_pass = all(E01, E02, E03, E04 == pass)`.

### 3.3 Mapping điểm chính thức theo spec
Theo [Extensibility scoring](EN_WAF Hackathon - Benchmark Specification v2.md:365), caching đúng per-tier có `4 pts` (`1 điểm` mỗi E01..E04).

### 3.4 JSON output tối thiểu (official)
```json
{
  "phase_e": {
    "caching": {
      "E01_medium_cached": "pass",
      "E02_critical_not_cached": "pass",
      "E03_ttl_expiry": "pass",
      "E04_auth_not_cached": "pass"
    }
  },
  "phase_e_caching_pass": true
}
```

---

## 4) Bộ chỉ số bổ sung sau PASS (tie-break quality, không đổi PASS/FAILED)

## 4.1 Nhóm Cache Efficiency (chỉ cho route được phép cache)
Áp dụng chủ yếu cho E01/E03:
- `cache_hit_ratio_medium`
- `cache_hit_latency_p50_ms`, `cache_hit_latency_p95_ms`
- `cache_acceleration_ratio = miss_latency / hit_latency`
- `ttl_expiry_accuracy` (độ chính xác thời điểm hết hạn)

Ý nghĩa: team nào cache đúng và nhanh hơn sẽ nhỉnh hơn.

## 4.2 Nhóm Safety (không cache sai chỗ)
Áp dụng E02/E04:
- `critical_cache_violation_count`
- `auth_cache_violation_count`
- `token_uniqueness_rate` (E02)
- `auth_response_similarity_guard` (phát hiện replay body/headers)

Ý nghĩa: tránh "cache nhầm dữ liệu nhạy cảm".

## 4.3 Nhóm Stability & Determinism
- `decision_flap_count` (lúc HIT lúc MISS không theo TTL/policy)
- `latency_stddev_hit_ms`, `latency_stddev_miss_ms`
- `header_consistency_rate` cho `X-WAF-Cache` nếu WAF expose header

## 4.4 Nhóm Resource Efficiency (nếu benchmark đo được)
- `memory_cache_peak_mb`
- `eviction_rate`
- `cpu_overhead_cache_path_pct`

Ý nghĩa: cache tốt nhưng không ăn quá nhiều tài nguyên.

---

## 5) Cách tie-break khi 2 team đều PASS E01..E04

Giữ nguyên PASS chính thức. Chỉ dùng quality metrics để so nhỉnh hơn:

1. **Safety trước**: đội có `critical_cache_violation_count=0` và `auth_cache_violation_count=0` ổn định hơn.
2. **Hiệu quả cache MEDIUM**: `cache_acceleration_ratio` cao hơn, `cache_hit_latency_p95_ms` thấp hơn.
3. **TTL correctness**: `ttl_expiry_accuracy` tốt hơn, ít flap hơn quanh ngưỡng TTL.
4. **Độ ổn định**: `latency_stddev` thấp hơn, header consistency cao hơn.
5. **Tài nguyên**: memory/cpu overhead thấp hơn ở cùng workload.

---

## 6) Output artifacts khuyến nghị (JSON + HTML)

Sau mỗi run phần caching, tool nên sinh:
1. `benchmark/phase_e_caching_report.json` (nguồn dữ liệu chuẩn).
2. `benchmark/phase_e_caching_report.html` (render từ JSON để reviewer xem nhanh).

HTML cần hiển thị tối thiểu:
- trạng thái PASS/FAILED toàn E01..E04,
- bảng expected vs actual từng case,
- safety metrics (violation counts),
- efficiency metrics (hit ratio, latency p95, acceleration ratio),
- tie-break summary.

---

## 7) Kết luận triển khai
- Chấm PASS/FAILED bám chặt [Spec §7.2](EN_WAF Hackathon - Benchmark Specification v2.md:350) + [exploit_catalogue E-cases](exploit_catalogue.md:506).
- Dùng semantics tier/cache từ [WAF Interop Contract](EN_WAF Hackathon - WAF Interop Contract v2.1.md:215).
- Lưu thêm quality metrics sau PASS để so team công bằng mà không làm thay đổi luật chấm chính thức.
