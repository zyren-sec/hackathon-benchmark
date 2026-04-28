# Phase D — DDoS & Resilience Benchmark Blueprint (Spec §6)

Nguồn chuẩn chính: /var/www/benchmark/docs/EN_WAF Hackathon - Benchmark Specification v2.md.  
Nguồn bổ sung control/auth: /var/www/benchmark/docs/exploit_catalogue.md.

---

## 0) Mục tiêu tài liệu
Tài liệu này định nghĩa cho benchmark tool toàn bộ Phase D:
1. Workflow benchmark phải chạy gì.
2. WAF cần trả gì để PASS, không đạt gì thì FAILED.
3. Tiêu chí chấm PASS chính thức.
4. Bộ chỉ số bổ sung sau PASS để so sánh team nào PASS tốt hơn (không đổi PASS/FAILED).

---

## 1) Workflow benchmark tổng thể cho toàn bộ Phase D

## 1.1 Pre-check chung trước Phase D
1. Gọi `POST /__control/reset` (kèm header control secret theo [exploit_catalogue.md](exploit_catalogue.md:7)).
2. Verify app health trực tiếp upstream (`:9000/health`) và qua WAF (`:8080/health`).
3. Chụp metadata run:
   - `run_id`, `team_id`, `waf_version`, `benchmark_version`, `environment_tag`.
   - tải test (`rps`, `concurrency`, duration), seed random, timestamp UTC.
4. Đồng bộ timeout của benchmark client (cao hơn timeout kỳ vọng của WAF để tránh benchmark tự timeout trước).

## 1.2 Thứ tự chạy case Phase D
Theo [Spec §6](EN_WAF Hackathon - Benchmark Specification v2.md:286), chạy theo thứ tự:
- D01 → D02 → D03 → D04 → D05 → D06 → D07 → D08 → D09.

Reset policy theo bảng spec:
- Reset trước D01.
- D02, D03 không bắt buộc reset.
- Reset trước D04.
- D05 dùng control set `down=true`.
- D06 dùng control set `delay_ms=10000`.
- D07 restore trạng thái bình thường.
- D08 chỉnh config `fail_mode` MEDIUM sang `close` + reload.
- D09 revert về `open` + reload.

## 1.3 Thu thập dữ liệu chuẩn cho mọi case
Mỗi case lưu tối thiểu:
- `case_id`, `start_ts`, `end_ts`, `duration_ms`
- `requests_sent`, `responses_received`, `status_histogram`
- `hang_count`, `client_timeout_count`, `connection_error_count`
- latency distribution: `p50`, `p95`, `p99`, `max`, `stddev`
- bằng chứng đúng/sai theo từng case (ví dụ CRITICAL=503, MEDIUM=200 ở D04)

---

## 2) PASS/FAILED theo từng case D01–D09

## D01 — HTTP flood
Ref: [Spec D01](EN_WAF Hackathon - Benchmark Specification v2.md:292)

- Workflow:
  1. Flood 50,000+ req/s tới `GET /` trong 60s.
  2. Ngay sau đó gửi 10 request legit CRITICAL (full golden path).
- PASS khi:
  - 10 request legit vẫn được xử lý (allow/challenge, không bị drop),
  - từng request phản hồi trong <= 10s.
- FAILED khi:
  - legit request bị drop/hang,
  - quá 10s,
  - không xử lý được flow hợp lệ sau flood.

## D02 — Slowloris
Ref: [Spec D02](EN_WAF Hackathon - Benchmark Specification v2.md:293)

- Workflow:
  1. Mở 500 connection, drip header 1 byte/s, không complete.
  2. Song song gửi traffic hợp lệ mới.
- PASS khi:
  - WAF timeout stale connections trong <= 30s,
  - connection hợp lệ mới vẫn accepted.
- FAILED khi:
  - stale connections không bị dọn,
  - hoặc kết nối hợp lệ mới bị nghẽn/từ chối do cạn tài nguyên.

## D03 — Slow POST (RUDY)
Ref: [Spec D03](EN_WAF Hackathon - Benchmark Specification v2.md:294)

- Workflow:
  1. Gửi `POST /login` với `Content-Length: 1000000`, body drip 1 byte/s.
- PASS khi:
  - WAF kill connection trong <= 30s.
- FAILED khi:
  - không kill đúng hạn,
  - hoặc giữ connection quá lâu gây nghẽn.

## D04 — WAF-targeted flood (fail-close/fail-open)
Ref: [Spec D04](EN_WAF Hackathon - Benchmark Specification v2.md:295)

- Workflow:
  1. Flood 100,000+ req/s trong 60s vào WAF.
  2. Trong overload window gửi 5 CRITICAL + 5 MEDIUM.
- PASS khi đồng thời:
  - CRITICAL trả 503 (fail-close),
  - MEDIUM pass through upstream (200, fail-open).
- FAILED khi:
  - CRITICAL không 503,
  - hoặc MEDIUM không 200 như expected fail-open mặc định.

## D05 — Backend down
Ref: [Spec D05](EN_WAF Hackathon - Benchmark Specification v2.md:301)

- Workflow:
  1. `POST /__control/health_mode {"down":true}`.
  2. Chờ 2s.
  3. Gửi 10 request qua WAF.
- PASS khi:
  - cả 10/10 trả 503,
  - không hang,
  - mỗi request <= 5s.
- FAILED khi:
  - có request khác 503,
  - hoặc >5s,
  - hoặc hang.

## D06 — Backend slow
Ref: [Spec D06](EN_WAF Hackathon - Benchmark Specification v2.md:302)

- Workflow:
  1. `POST /__control/slow {"delay_ms":10000}`.
  2. Gửi 50 request qua WAF.
- PASS khi:
  - WAF trả 504,
  - trong timeout cấu hình (default 5s), không đợi đủ 10s backend.
- FAILED khi:
  - status không 504,
  - hoặc phản hồi vượt timeout kỳ vọng,
  - hoặc timeout/hang không nhất quán.

## D07 — Recovery
Ref: [Spec D07](EN_WAF Hackathon - Benchmark Specification v2.md:303)

- Workflow:
  1. Restore: `/__control/health_mode {"down":false}` + `/__control/slow {"delay_ms":0}`.
  2. Chờ 5s.
  3. Gửi 10 request legit.
- PASS khi:
  - cả 10 request đều 200,
  - WAF proxy bình thường trở lại.
- FAILED khi:
  - còn stuck ở trạng thái degrade,
  - hoặc còn 503/504 bất thường.

## D08 — Fail-mode configurability
Ref: [Spec D08](EN_WAF Hackathon - Benchmark Specification v2.md:304)

- Workflow:
  1. Sửa config: MEDIUM `fail_mode: close`.
  2. Reload config (SIGHUP/watch).
  3. Tạo overload 100k req/s trong 30s.
  4. Gửi 5 request MEDIUM trong overload.
- PASS khi:
  - MEDIUM bị reject 503 (chứng minh fail_mode config có hiệu lực).
- FAILED khi:
  - MEDIUM vẫn pass như fail-open cũ,
  - hoặc config change không có tác dụng.

## D09 — Fail-mode restore
Ref: [Spec D09](EN_WAF Hackathon - Benchmark Specification v2.md:305)

- Workflow:
  1. Revert MEDIUM `fail_mode: open`.
  2. Reload config.
  3. Gửi 5 request MEDIUM dưới tải.
- PASS khi:
  - MEDIUM pass lại (200).
- FAILED khi:
  - vẫn trả 503 như trạng thái D08,
  - hoặc reload/revert không có hiệu lực.

---

## 3) Tiêu chí chấm PASS chính thức của benchmark (Phase D)

## 3.1 PASS/FAILED theo từng test
Mỗi case D01..D09 chấm độc lập `pass|fail` đúng theo điều kiện ở mục 2.

## 3.2 PASS toàn bộ Phase D
`phase_d_pass = all(D01..D09 == pass)`.

## 3.3 Gợi ý output bắt buộc cho report
```json
{
  "phase_d": {
    "D01": {"pass": true, "reason": "legit survived <=10s"},
    "D02": {"pass": true, "reason": "slowloris conns cleaned <=30s"},
    "D03": {"pass": true, "reason": "slow POST killed <=30s"},
    "D04": {"pass": true, "reason": "critical=503, medium=200"},
    "D05": {"pass": true, "reason": "10/10 503, each <=5s"},
    "D06": {"pass": true, "reason": "50/50 504 within timeout"},
    "D07": {"pass": true, "reason": "recovered 10/10 200"},
    "D08": {"pass": true, "reason": "medium fail_mode close -> 503"},
    "D09": {"pass": true, "reason": "medium fail_mode open -> 200"}
  },
  "phase_d_pass": true
}
```

---

## 4) Khi đã PASS: nên lưu thêm metric gì để biết team nào PASS tối ưu hơn

Lưu ý: các metric dưới đây là `post-pass quality metrics`, không thay đổi PASS/FAILED chính thức.

## 4.1 Nhóm Accuracy & Determinism (độ đúng và nhất quán)
- `status_ok_ratio` mỗi case (tỷ lệ đúng status kỳ vọng).
- `decision_flap_count` (số lần hành vi dao động bất thường cùng một điều kiện).
- `policy_consistency_score`:
  - D04: CRITICAL luôn close, MEDIUM luôn open.
  - D08/D09: config đổi xong thì hành vi đổi đúng ngay.

## 4.2 Nhóm Latency Quality (sau khi PASS)
- per-case: `p50/p95/p99/max/stddev`.
- D01: `legit_recovery_latency_p95` sau flood.
- D05: `fast_fail_p95` (503 trả nhanh thế nào).
- D06: `timeout_alignment_error_ms = |latency_p50 - timeout_ms_effective|` (khả năng cắt timeout ổn định, không overshoot).

## 4.3 Nhóm Service Continuity / Collateral
- `legit_success_ratio_under_attack` (D01, D04).
- `collateral_block_count` (số legit request bị hy sinh không cần thiết).
- `new_conn_accept_ratio` (D02: tỷ lệ accept kết nối hợp lệ mới).

## 4.4 Nhóm Recovery & Control-plane Agility
- `recovery_time_to_green_ms` (D07: từ restore control đến khi ổn định 200).
- `config_apply_latency_ms` (D08/D09: từ lúc reload đến lúc policy mới có hiệu lực).
- `config_rollback_safety` (revert có sạch hay để lại side-effect).

## 4.5 Nhóm Resource Efficiency (nếu đo được)
- `cpu_peak_pct`, `memory_peak_mb`, `fd_peak`, `conn_table_peak` trong từng case.
- `resource_per_10k_rps` để so hiệu quả kiến trúc giữa team.

---

## 5) Tie-break khi 2 team đều PASS toàn bộ Phase D

Không cần gán PASS+/PASS++ ngay. Chỉ cần dùng tie-break theo thứ tự ưu tiên cố định:

1. **Ít collateral hơn** (ưu tiên bảo toàn user hợp lệ).
2. **Tail latency tốt hơn** (`p99` thấp hơn ở D01/D05/D06/D07).
3. **Ổn định hơn** (`stddev` thấp hơn, ít spike).
4. **Recovery nhanh hơn** (`recovery_time_to_green_ms` thấp hơn ở D07).
5. **Control-plane nhanh hơn** (`config_apply_latency_ms` thấp hơn ở D08/D09).
6. **Hiệu năng tài nguyên tốt hơn** (CPU/RAM/FD thấp hơn cùng điều kiện).

Gợi ý tính `phase_d_quality_score` (chỉ để tie-break):
- Continuity 30%
- Tail latency 25%
- Stability 15%
- Recovery speed 15%
- Config agility 10%
- Resource efficiency 5%

---

## 6) Kết luận triển khai
- Benchmark tool chấm PASS/FAILED bám chặt [Spec §6](EN_WAF Hackathon - Benchmark Specification v2.md:286).
- Đồng thời lưu post-pass metrics chuẩn hóa để mùa sau có thể định nghĩa phân loại PASS chi tiết dựa trên dữ liệu thực, thay vì ấn ngưỡng cảm tính từ đầu.

---

## 7) Output report artifacts (JSON + HTML)

Tool benchmark nên luôn sinh 2 file cố định sau mỗi run:

1. [benchmark/phase_d_report.json](benchmark/phase_d_report.json)
   - Là nguồn dữ liệu chuẩn (machine-readable) cho CI/CD, so sánh A/B, lưu lịch sử.
2. [benchmark/phase_d_report.html](benchmark/phase_d_report.html)
   - Render trực tiếp từ JSON để reviewer đọc nhanh.

### 7.1 JSON schema tối thiểu
- `metadata`: định danh run, version, môi trường.
- `phase_d_summary`: pass toàn phase + tổng quality score tie-break.
- `cases.D01..D09`: kết quả pass/fail + metrics + evidences.
- `tie_break_factors`: các yếu tố so sánh khi 2 team cùng pass.

### 7.2 Quy tắc render HTML từ JSON
- HTML không hard-code kết quả case.
- HTML đọc dữ liệu từ [benchmark/phase_d_report.json](benchmark/phase_d_report.json).
- Các mục bắt buộc hiển thị:
  - banner PASS/FAILED toàn phase,
  - bảng D01..D09 (Expected vs Actual vs Verdict),
  - metrics chính (`p95`, `p99`, `stddev`, `collateral`, `recovery_time_to_green_ms`),
  - tie-break summary (vì sao Team A nhỉnh hơn Team B khi cùng PASS).

### 7.3 Naming khuyến nghị để lưu lịch sử
Ngoài file latest cố định, có thể copy thêm bản theo run id:
- `benchmark/reports/<run_id>.phase_d.json`
- `benchmark/reports/<run_id>.phase_d.html`
