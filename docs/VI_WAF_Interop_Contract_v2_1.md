# WAF Interop Contract (Hợp Đồng Tương Tác WAF) v2.1

**Đối tượng đọc**: Nhà phát triển Benchmarking Tool (Công cụ Đánh giá) · Ban Tổ chức Cuộc thi · Participants (Đội thi) — đính kèm vào quy chế cuộc thi  
**Phạm vi**: CHỈ mô tả cách benchmarker (công cụ chấm điểm tự động) phát hiện và phân loại quyết định của WAF. Không liên quan đến target app (ứng dụng đích) hay trọng số tính điểm.

---

## 1. Mục Đích

Benchmarking tool (công cụ chấm điểm) cần phân loại mọi quyết định của WAF **mà không cần truy cập source code hay trạng thái nội bộ** của WAF. Tài liệu này định nghĩa các output (đầu ra) quan sát được từ bên ngoài để phục vụ việc phân loại tự động.

Các đội thi **bắt buộc hỗ trợ ít nhất một** trong hai cơ chế output dưới đây: **response headers** (HTTP header trong phản hồi) hoặc **audit log** (nhật ký kiểm tra). Hỗ trợ cả hai sẽ được cộng điểm thưởng ở mục Dashboard/Observability (Quan sát hệ thống).

---

## 2. Các Loại Quyết Định của WAF (WAF Decision Classes)

Mỗi request (yêu cầu HTTP) đi qua WAF sẽ cho ra **đúng một** quyết định trong bảng sau:

| Quyết định | Ý nghĩa |
|:---|:---|
| `allow` | Request được chuyển tiếp (proxy) lên upstream; response từ upstream được trả về client |
| `block` | Request bị từ chối trước khi đến upstream |
| `challenge` | Request bị giữ lại; client phải vượt qua JS challenge (thử thách JavaScript) hoặc proof-of-work (bằng chứng tính toán) mới được tiếp tục |
| `rate_limit` | Request bị từ chối vì đã vượt ngưỡng tốc độ (rate threshold) |
| `timeout` | WAF đã proxy request nhưng upstream không phản hồi kịp thời |
| `circuit_breaker` | WAF từ chối proxy vì upstream đang bị đánh dấu là không khỏe mạnh (unhealthy) |

---

## 3. Phát Hiện Qua HTTP Response (Phương thức Chính)

Benchmarker phân loại quyết định của WAF bằng cách kiểm tra HTTP response. Các quy tắc dưới đây được đánh giá **theo thứ tự ưu tiên** — quy tắc đầu tiên khớp sẽ thắng.

| Độ ưu tiên | Điều kiện | Phân loại |
|:---|:---|:---|
| 1 | Status code `403` | `block` |
| 2 | Status code `429` VÀ response body chứa chuỗi `challenge` (không phân biệt hoa thường) | `challenge` |
| 3 | Status code `429` VÀ response body KHÔNG chứa `challenge` | `rate_limit` |
| 4 | Status code `503` VÀ response body chứa chuỗi `circuit` (không phân biệt hoa thường) | `circuit_breaker` |
| 5 | Status code `504` | `timeout` |
| 6 | Bất kỳ status code nào khác | `allow` |

> **Chủ ý thiết kế**: Các quy tắc này được đặt ra ở mức rộng có chủ đích. Đội thi tự do sử dụng bất kỳ định dạng response body nào — trang HTML, JSON object, plain text (văn bản thuần) — miễn là status code và keyword (từ khóa) có mặt đúng chỗ. Benchmarker **không parse cấu trúc body** — chỉ kiểm tra status + substring (chuỗi con).

### Định Dạng Challenge Response

Khi WAF trả về `challenge` (status `429` + body chứa `challenge`), response body **BẮT BUỘC** phải chứa đủ thông tin để benchmarker giải quyết challenge theo chương trình. Hai định dạng được hỗ trợ:

**Format A — JSON challenge:**

```json
{
  "challenge": true,
  "challenge_type": "proof_of_work",
  "challenge_token": "abc123...",
  "difficulty": 4,
  "submit_url": "/challenge/verify",
  "submit_method": "POST"
}
```

**Format B — HTML challenge:**

```html
<!-- Body phải chứa "challenge" để được nhận diện -->
<form action="/challenge/verify" method="POST">
  <input type="hidden" name="challenge_token" value="abc123..." />
  <!-- JS tính toán nonce -->
</form>
```

**Nộp bài giải challenge**: Benchmarker gửi `POST <submit_url>` với body `{"challenge_token":"...","nonce":"..."}`. Khi thành công, WAF trả về `200` kèm session cookie (cookie phiên) hoặc token cho phép request gốc tiếp tục.

Nếu WAF sử dụng định dạng challenge mà benchmarker không thể parse được, challenge đó sẽ được ghi nhận là `challenge_unsolvable` (thử thách không giải được) — WAF vẫn được tính điểm đã phát challenge, nhưng không được điểm test "challenge thành công làm giảm risk score".

### Yêu Cầu Tối Thiểu Cho Các Quyết Định Không Phải `allow`

WAF **BẮT BUỘC** phải đính kèm một `request_id` (ID yêu cầu) có thể đọc bằng máy trong response để benchmarker có thể tương quan (correlate). Chọn một trong các cách sau:

- Response header: `X-Request-Id: <uuid>`
- JSON body field: `"request_id": "<uuid>"`
- HTML meta tag: `<meta name="request-id" content="<uuid>">`

Benchmarker thử cả ba theo thứ tự trên.

---

## 4. Observability Headers (Header Quan Sát) — Tùy Chọn

Nếu WAF bao gồm các headers này, benchmarker sẽ dùng chúng để tính điểm chi tiết hơn (độ chính xác của risk score, rule attribution). Nếu không có, benchmarker sẽ fallback (dự phòng) về phân loại chỉ qua response (§3) và audit log (§5).

| Header | Kiểu dữ liệu | Mô tả | Định dạng chính xác |
|:---|:---|:---|:---|
| `X-WAF-Request-Id` | UUID | ID request chuẩn | UUID v4, ví dụ: `550e8400-e29b-41d4-a716-446655440000` |
| `X-WAF-Risk-Score` | integer (số nguyên) 0–100 | Risk score (điểm rủi ro) tích lũy cho tổ hợp {IP + thiết bị + phiên} tại thời điểm đó | Số nguyên thuần, không dấu cách. Ví dụ: `42` |
| `X-WAF-Action` | string (chuỗi) | Một trong 6 quyết định: `allow`, `block`, `challenge`, `rate_limit`, `timeout`, `circuit_breaker` | Chữ thường, khớp chính xác |
| `X-WAF-Rule-Id` | string hoặc `none` | ID của rule đã kích hoạt quyết định | Chữ-số + gạch ngang, ví dụ: `sqli-001` hoặc `none` |
| `X-WAF-Cache` | `HIT` / `MISS` / `BYPASS` | Response có được phục vụ từ cache (bộ nhớ đệm) của WAF không | Chữ hoa, khớp chính xác |

Các headers này **không bắt buộc** để WAF được coi là hoạt động. Chúng là observability (khả năng quan sát) bonus giúp tính điểm chi tiết hơn.

> **Với các quyết định `allow`**: WAF NÊN bao gồm các headers này ngay cả trên các request được cho phép. Benchmarker dùng `X-WAF-Risk-Score` trên response `allow` để kiểm tra vòng đời risk score (§8 của benchmark spec).

---

## 5. Audit Log (Nhật Ký Kiểm Tra) — Phương thức Phụ

WAF ghi log có cấu trúc JSON vào file `./waf_audit.log` (đường dẫn có thể cấu hình). Dạng append-only (chỉ ghi thêm), mỗi dòng là một JSON object (định dạng JSONL), tương thích với SIEM (Security Information and Event Management — Hệ thống quản lý thông tin và sự kiện bảo mật).

### Các Trường Bắt Buộc Mỗi Entry

```json
{
  "request_id": "uuid",
  "ts_ms": 1714000000000,
  "ip": "1.2.3.4",
  "method": "POST",
  "path": "/login",
  "action": "block",
  "risk_score": 75
}
```

| Trường | Kiểu | Ràng buộc |
|:---|:---|:---|
| `request_id` | string (UUID v4) | Phải khớp với `X-WAF-Request-Id` header nếu cả hai đều tồn tại |
| `ts_ms` | integer (số nguyên) | Milliseconds theo Unix epoch (thời gian Unix) |
| `ip` | string | TCP peer address (địa chỉ TCP thực tế từ socket). IPv4 dạng dotted decimal (ví dụ: `1.2.3.4`) |
| `method` | string | HTTP method viết hoa (GET, POST, ...) |
| `path` | string | Request path (đường dẫn) kể cả query string (tham số URL) |
| `action` | string | Một trong 6 loại quyết định ở §2 |
| `risk_score` | integer (số nguyên) 0–100 | Risk score tại thời điểm ra quyết định |

### Các Trường Tùy Chọn (Được Tính Điểm Dưới Tiêu Chí Dashboard)

```json
{
  "device_fp": "abc123",
  "rule_id": "sqli-001",
  "session_id": "uuid",
  "tier": "CRITICAL",
  "latency_ms": 2.3,
  "upstream_status": 200,
  "cache": "MISS"
}
```

Benchmarker đọc file này sau khi chạy xong nếu headers không đủ thông tin để tính điểm đầy đủ.

### Ngữ Nghĩa Trường IP Trong Audit Log

Trường `ip` **BẮT BUỘC** là TCP peer address (`peer_addr` / `remote_addr` từ socket), **KHÔNG PHẢI** giá trị được parse từ `X-Forwarded-For` hay bất kỳ header nào. Điều này rất quan trọng vì:

1. Benchmarker mô phỏng các source IP khác nhau thông qua loopback aliases (địa chỉ loopback phụ).
2. XFF (X-Forwarded-For) có thể bị giả mạo (spoof) — WAF có thể tin hoặc không tin nó.
3. Benchmarker tương quan (correlate) các audit log entry theo TCP source IP.

---

## 6. Ma Trận Chuẩn Hóa Quyết Định (Decision Normalization Matrix)

Các tình huống biên (borderline scenarios) phải được phân loại nhất quán. Benchmarker dùng ma trận này:

| Tình huống | Phân loại | Lý do |
|:---|:---|:---|
| WAF trả `403` cho request độc hại | `prevented` (đã ngăn chặn) | Block tường minh |
| WAF trả `429` (rate limit hoặc challenge) cho request độc hại | `prevented` | Bị từ chối trước khi đến upstream |
| WAF viết lại/làm sạch (sanitize) payload → upstream trả `200` không có proof marker | `prevented_sanitized` (đã ngăn và làm sạch) | Tấn công bị vô hiệu dù request đã đến upstream |
| WAF proxy request → upstream response chứa proof marker | `passed` (đã bị lọt) | Exploit thành công — WAF thất bại |
| WAF trả `503`/`504` cho request độc hại | `prevented` | Bị từ chối do circuit breaker hoặc timeout |
| Request hợp lệ bị WAF trả `403` hoặc `429` (không phải trong lúc DDoS) | `false_positive` (kết quả dương tính giả) | Traffic tốt bị chặn |
| Request hợp lệ bị `challenge` → benchmarker solver vượt challenge → upstream phản hồi bình thường | `allowed_after_challenge` (được phép sau khi vượt thử thách) | Không phải false positive |
| Request hợp lệ trong đợt DDoS burst bị `429` | `collateral` (thiệt hại phụ) | Tính riêng, khác false_positive; là điều có thể chấp nhận khi tải cực cao |
| WAF trả `401` trước khi logic auth của app cho request đăng nhập độc hại | `prevented` | WAF chặn trước lớp auth của app |
| WAF pass request nhưng filter response (xóa proof marker, loại PII) | `outbound_filtered` (đã lọc đầu ra) | Tính điểm dưới outbound protection, không phải inbound |
| WAF pass request, response vẫn chứa proof marker nhưng một số trường bị redact | `partially_filtered` (lọc một phần) | Điểm một phần cho outbound protection |
| WAF trả `503` khi tự quá tải cho request tầng CRITICAL | `prevented` (fail-close hoạt động đúng) | Hành vi mong đợi theo quy chế cuộc thi |
| WAF proxy request khi tự quá tải cho request tầng MEDIUM | `allow` (fail-open hoạt động đúng) | Hành vi mong đợi theo quy chế cuộc thi |

**Quy tắc**: Một request là `prevented` khi và chỉ khi proof marker **KHÔNG** xuất hiện trong response body trả về benchmarker VÀ response đó không phải là phản hồi thành công bình thường từ upstream.

**Kiểm tra proof marker**: Benchmarker áp dụng regex `__[VL]\d+[a-b]?_\w+__` lên toàn bộ response body VÀ tất cả response headers. Bất kỳ kết quả khớp nào = marker có mặt.

---

## 7. Hợp Đồng Khởi Động WAF (WAF Startup & Binary Contract)

Từ quy chế cuộc thi — nhắc lại ở đây để benchmark tooling (công cụ chấm điểm) hiểu rõ:

```
Binary (file thực thi): ./waf
Khởi động:              ./waf run
Config (cấu hình):      ./waf.yaml (hoặc ./waf.toml) — phải tồn tại trong thư mục làm việc
Logs (nhật ký):         ./waf_audit.log (mặc định, có thể cấu hình trong file config)
```

Benchmarker kỳ vọng:

1. WAF binary tồn tại tại `./waf`
2. `./waf run` khởi động WAF và WAF bắt đầu lắng nghe (listen) trong vòng 10 giây
3. WAF đọc upstream target (đích upstream) từ config file (benchmarker đặt `upstream: http://127.0.0.1:9000`)
4. WAF lắng nghe trên port được chỉ định trong config (mặc định `8080`)
5. `./waf_audit.log` được tạo ngay khi request đầu tiên được xử lý

### Health Check (Kiểm Tra Sức Khỏe)

Sau khi chạy `./waf run`, benchmarker poll (thăm dò) `GET http://127.0.0.1:8080/health` mỗi 500ms trong tối đa 10 giây. Response `200` đầu tiên = WAF đã sẵn sàng.

Nếu WAF không phản hồi trong 10 giây, benchmarker hủy bỏ và ghi nhận `startup_failed` (khởi động thất bại).

---

## 8. Caching Observability (Quan Sát Bộ Nhớ Đệm)

Nếu WAF triển khai smart caching (bộ nhớ đệm thông minh), benchmarker kiểm tra hành vi đúng theo từng tier (tầng) sử dụng `X-WAF-Cache` header hoặc bằng cách đo thời gian phản hồi của các request lặp lại.

| Tier (Tầng) | Hành vi cache kỳ vọng |
|:---|:---|
| CRITICAL (Tầng Quan Trọng) | **KHÔNG BAO GIỜ** được cache — mọi request đều phải đến upstream |
| HIGH (Tầng Cao) | Không cache mặc định (đã xác thực, nội dung động) |
| MEDIUM (Tầng Trung, đường dẫn `/static/*`, `/assets/*`, `/public/*`) | Cache tích cực — request thứ hai giống nhau phải nhanh hơn hoặc trả về `HIT` |
| CATCH-ALL (Tầng Bắt Tất Cả) | Không cache mặc định |

Nếu thiếu `X-WAF-Cache` header, benchmarker suy ra hành vi cache từ chênh lệch thời gian phản hồi (response cached kỳ vọng < 1ms so với latency upstream thông thường).

---

## 9. Source IP Trust Model (Mô Hình Tin Tưởng Địa Chỉ IP Nguồn)

Phần này làm rõ cách WAF xử lý source IP và proxy headers trong cuộc thi:

| Tín hiệu | Nguồn thật | WAF nên... |
|:---|:---|:---|
| TCP peer address (`peer_addr`) | Tầng socket | Luôn ghi vào trường `ip` trong audit log. Dùng làm IP chính cho rate limiting và risk scoring. |
| `X-Forwarded-For` | Request header (có thể bị giả mạo) | Dùng cho relay detection tests (kiểm tra phát hiện relay) AR01–AR06. So sánh với `peer_addr` để phát hiện bất khớp. **KHÔNG** dùng làm định danh IP duy nhất. |
| `X-Real-IP` | Request header (có thể bị giả mạo) | Giống XFF — tín hiệu bổ sung, không phải định danh. |
| `Host` | Request header | Validate (xác minh) so với hostname kỳ vọng. Từ chối hoặc sanitize (làm sạch) các giá trị bất thường (ngăn chặn V11). |

> **Trong sandbox (môi trường thử nghiệm)**: Tất cả traffic đến từ địa chỉ loopback `127.0.0.x`. WAF **BẮT BUỘC** phải xử lý các địa chỉ `127.0.0.x` khác nhau như các client riêng biệt (IP khác nhau cho rate limiting, risk scoring, v.v.).

---

## Changelog (Lịch Sử Thay Đổi)

| Phiên bản | Ngày | Thay đổi |
|:---|:---|:---|
| 2.1 | 2026-04-09 | Giải quyết phản hồi review: (1) Định rõ định dạng challenge response với hai format được hỗ trợ. (2) Làm rõ ngữ nghĩa trường `ip` trong audit log — phải là TCP peer, không phải XFF. (3) Thêm §9 Source IP Trust Model. (4) Observability headers nên có mặt cả trên response `allow`. (5) Định rõ định dạng chính xác của header value. (6) Regex proof marker áp dụng cho cả headers VÀ body. (7) Thêm các hàng chuẩn hóa fail-close/fail-open. (8) Ghi rõ protocol health check polling. |
| 2.0 | 2026-04-09 | Tách ra từ monolithic interface contract. |
