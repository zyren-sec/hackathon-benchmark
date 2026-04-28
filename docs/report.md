# Báo cáo Đối chiếu Benchmark (Code là Source of Truth)

Ngày: 2026-04-22  
Phạm vi: chỉ `benchmark/`  
Đường cơ sở mang tính authoritative: implementation trong Go code, sau đó đối chiếu docs/TODO với hành vi thực tế của code.

---

## A) Kiến trúc & Workflow đã triển khai (As-Built)

### A.1 Topology thực thi và control flow

Implementation benchmark hiện tại được điều phối bởi `BenchmarkRunner` trong `internal/orchestrator/runner.go`, thực hiện khởi tạo target/WAF clients, load capabilities, chạy pre-flight checks, rồi thực thi các phase theo thứ tự (`a,b,c,d,e,risk`) khi chọn `all`.

Chuỗi điều khiển as-built:

1. Benchmark tool gửi crafted traffic tới WAF.
2. WAF forward/block/challenge đối với upstream target app.
3. Benchmark phân loại outcome thông qua các heuristics dựa trên status/body/header.
4. Marker extraction quét response body + headers để tìm bằng chứng `__V*__` / `__L*__`.
5. Metrics ở cấp phase được aggregate vào scoring report.

### A.2 Hai execution surface đang hoạt động cho Phase A

Hiện có hai implementation Phase A đáng kể:

- `cmd/waf-benchmark-phase-a/*`: standalone Phase A engine với attack-mode logic phong phú hơn (bao gồm các pathway malformed/smuggling/header-cannibalism/slow-post/chunked-variation).
- `internal/phases/phase_a.go`: đường chạy phase tích hợp trong orchestrator.

Kiến trúc dual-path này mạnh cho experimentation, nhưng tạo ra consistency risk không nhỏ: kết quả và semantics có thể diverge tùy executable path mà ban giám khảo thực sự chạy.

### A.3 Pipeline marker và decision

- Marker detection dùng regex `__[VL]\d+[a-b]?_\w+__`, quét cả body và headers.
- Decision classifier chuẩn hóa các outcome chính (`block`, `challenge`, `rate_limit`, `circuit_breaker`, `timeout`, `allow`, `prevented_sanitized`) chủ yếu dựa trên status code cùng challenge-indicator heuristics.

Cách làm này nhìn chung aligned với mục tiêu interop contract, có hành vi fallback thực tiễn dựa trên chỉ báo từ body/header.

---

## B) Gap Analysis: Spec + TODO so với hiện trạng code

### B.1 Độ lệch lớn giữa architecture/documentation

1. **Spec vẫn mô tả các interface lý tưởng hóa, chưa phản ánh đầy đủ chi tiết implementation hiện tại.**
   - Ví dụ interface trong spec có nhắc challenge solver abstractions trực tiếp và thiết kế scoring trộn manual-review phong phú hơn, trong khi runtime scorer hiện dùng automated model 77 điểm gọn hơn.

2. **Ví dụ project layout trong spec đã cũ một phần.**
   - Spec tham chiếu `pkg/httpclient`..., trong khi runtime wiring cốt lõi thực tế nằm ở `internal/httpclient` và các đường `internal/*` của orchestrator.

3. **Khẳng định về Phase D lệch so với hành vi triển khai ở D08/D09.**
   - Code set fail-mode score = 0 và skip thực thi D08-D09 trong `RunPhaseD` (comment ghi rõ thao tác config vẫn pending).

4. **Xử lý challenge ở risk lifecycle mới là mô phỏng, chưa tích hợp solver đầy đủ.**
   - Step 7 hiện chỉ chờ ngắn rồi gửi follow-up legitimate request; chưa có implementation dedicated challenge package (`internal/challenge/*`) hoạt động trên runtime path.

### B.2 Kiểm tra độ chính xác trạng thái TODO

`TODO.md` đánh dấu đúng một số hạng mục chính là pending/in-progress, nhưng một số claim completed đang optimistic so với độ sâu chất lượng của code:

- **Acceptance text của 7.6** ngụ ý có thao tác control-hook đầy đủ cho backend modes; comments và flow trong code cho thấy vẫn còn pathway mô phỏng một phần.
- **Acceptance text của 10.1** nói scoring khớp CSV matrix; scoring engine hiện tại tổng là 77 và chưa triển khai đầy đủ các category của matrix 120 điểm.
- **9.3 challenge solver integration được đánh dấu complete** nhưng các mục challenge module dedicated ở Phase 11 vẫn chưa check xong, và logic step 7 của lifecycle vẫn là mô phỏng nhẹ.

### B.3 Điểm mạnh bị docs mô tả thiếu

1. Standalone Phase A engine có offensive corpus phong phú và chiến lược thực thi request đa mode mạnh hơn mức được nhấn trong narrative trung tâm của spec.
2. Độ phủ catalog Phase B (AB/AR/BA/TF/RE) là đáng kể và về cấu trúc code thì đã đầy đủ vận hành.
3. Orchestrator có các tính năng resilience thực tế (pre-flight checks, lưu partial-result khi có signal) vượt mức ví dụ tối thiểu trong specification.

### B.4 Nơi implementation làm yếu chất lượng đánh giá

1. **Lệch scoring (77 vs 120) ảnh hưởng trực tiếp đến fairness và comparability.**
2. **D08/D09 bị skip trong score path** làm yếu độ sâu xác thực deployment/fail-mode.
3. **Risk challenge solving chưa được exercise thật sự** có thể over-credit hệ thống trong vòng đời closure.
4. **Một số test dùng tín hiệu placeholder/simplified** (ví dụ marker-check placeholders ở một phần abuse flow), làm giảm black-box rigor.

---

## C) Phân tích Scoring Matrix & rủi ro bypass kiểu Black-box

### C.1 Lệch cấu trúc scoring

`docs/scoring_matrix.csv` định nghĩa paradigm 120 điểm gồm:

- SEC (40)
- PERF (20)
- INT (20)
- EXT (10)
- ARCH (15)
- UI (10)
- DEP (5)

Runtime scoring hiện tại (`internal/scoring/calculator.go`) tính:

- Phase A: 20
- Phase B: 10
- Phase C: 20
- Phase D: 9
- Phase E: 10
- Risk lifecycle: 8
- **Tổng tối đa: 77**

Điều này tạo ra bất nhất trực tiếp giữa framework chấm điểm được công bố và score output thực thi.

### C.2 Rủi ro lệch chuẩn CSV parser

`LoadFromCSV()` trong `internal/scoring/matrix.go` parse `record[3]` là points. Trong schema CSV thực tế, cột index 3 là description và points nằm ở index 4 (`max_points`). Việc này có thể gây mis-parse điểm một cách silent và làm sụp integrity của matrix nếu đường load CSV được dùng.

### C.3 Các vector bypass kiểu black-box

Những vector bypass chính trong paradigm hiện tại:

1. **Spoofing heuristic challenge detection**
   - Heuristics theo keyword trong body/header khi gặp 429 có thể bị qua mặt bởi crafted responses thiếu semantics challenge chuẩn tắc rõ ràng.

2. **Ẩn marker nhưng không mitigation thật sự**
   - Một WAF hoặc upstream strip proof markers nhưng vẫn cho hành vi nguy hiểm chạy thật có thể vẫn được chấm prevented/sanitized theo logic quá marker-centric.

3. **Hardcode hành vi theo tier**
   - Hệ thống có thể hardcode endpoint/class mong đợi của bộ test (hoặc tối ưu riêng cho các path đã biết) nếu không cưỡng chế mutation-based randomization cho path/payload.

4. **Optimism ở risk lifecycle**
   - Step-7 mô phỏng không có solving challenge token thật có thể cho điểm cao dù không có năng lực anti-bot thực sự.

### C.4 Đề xuất hardening cho verification

1. Thêm mutation testing cho các họ payload tương đương và route aliases.
2. Bổ sung invariant checks vượt qua mức “không có marker” (state-change validation, side-effect verification).
3. Cưỡng chế strict challenge contract validation (token issuance, solver proof, replay rejection).
4. Chặn publish score nếu matrix schema/hash và runtime scoring model chưa aligned.

---

## D) Kế hoạch cải tiến (Ưu tiên)

### D.1 Ưu tiên cao (fairness-critical)

1. Thống nhất scoring contract theo full 120-point matrix hoặc version-gate rõ ràng cho “77-point automated profile”.
2. Sửa mapping index khi parse CSV và validate theo header names.
3. Triển khai D08/D09 end-to-end với config mutation + bằng chứng hành vi quan sát được.
4. Thay Step-7 mô phỏng bằng pipeline challenge solver thực tế.

### D.2 Ưu tiên trung bình (quality và robustness)

1. Hợp nhất execution surfaces của Phase A hoặc định nghĩa một mode mang tính judge-authoritative duy nhất.
2. Thêm anti-overfitting mutation suite rõ ràng cho payloads/routes.
3. Tăng cường evidence checks ở Phase B/RE bằng marker/state assertions dứt khoát.

### D.3 Quản trị tài liệu

1. Duy trì mục “as-built delta” chuyên biệt trong spec có provenance theo ngày/phiên bản.
2. Gắn chuyển trạng thái TODO với các executable acceptance scripts.
3. Thêm compatibility manifest dạng machine-readable: `spec_version`, `scoring_profile`, `implemented_tests`.

---

## Tóm tắt Reverse-Update (Spec bây giờ nên ghi gì)

1. Scoring theo orchestrator hiện tại là **77-point automated** và chưa tương đương rubric 120 điểm đầy đủ.
2. Phase D hiện chạy D01-D07; scoring của D08-D09 đang pending/zeroed.
3. Risk lifecycle Step 7 hiện chưa dựa trên dedicated PoW/JS solver package.
4. Phase A có standalone engine path phong phú hơn, với các advanced attack modes vượt ra ngoài narrative tối thiểu của core-phase.

Các điểm này đã được áp dụng vào ghi chú cập nhật specification để giữ cho docs trung thực với implementation reality.