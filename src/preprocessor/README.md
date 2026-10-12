# Preprocessor — Bài tập 2

Module kiểm tra và chuẩn hóa dictionary sau Decoder, chuẩn bị dữ liệu cho Flow Tracker. Không truy cập Scapy packet, không giải mã lại payload, không duy trì flow.

## Các file

| File | Vai trò |
|---|---|
| `__init__.py` | Export `preprocess_event` |
| `preprocessor.py` | Điều phối validation, normalization, bổ sung giá trị thiếu và áp dụng chính sách |
| `normalizer.py` | Chuẩn hóa IP, timestamp, protocol, domain và HTTP headers |
| `validator.py` | Kiểm tra số nguyên/range, port, TCP flags và sự phù hợp protocol network/transport |

## API

```python
from src.preprocessor import preprocess_event

result = preprocess_event(event, invalid_policy='keep', unsupported_policy='keep')
if result['processing_action'] == 'keep':
    normalized = result['normalized']
```

Hai policy nhận `keep` hoặc `drop`. Cấu hình sai gây ValueError. Input event không hợp lệ được trả về với status invalid thay vì làm dừng chương trình. Hàm không sửa event đầu vào.

`main.py` đã gọi module sau Decoder và trước JSONL writer. Mặc định giữ event để phục vụ kiểm tra. Khi action là drop, callback không ghi event. Module không tự xóa event hay ghi file.

## Output

Các trường parser, raw Base64 và `decoded` được giữ nguyên. Bản chuẩn hóa nằm riêng trong `normalized`, gồm `network`, `transport`, `application`, `timestamp`.

Metadata ở cấp event:

```json
{
  "preprocess_status": "partial",
  "processing_action": "keep",
  "reason": ["unsupported_application"]
}
```

- `valid`: không phát hiện lỗi hoặc thiếu sót trong các kiểm tra hiện có.
- `partial`: thiếu dữ liệu phụ, protocol chưa hỗ trợ, hoặc bước decode/parser báo dữ liệu chưa đầy đủ.
- `invalid`: sai field bắt buộc, sai kiểu/range hoặc protocol không nhất quán.
- `reason`: danh sách lý do, rỗng khi valid.

Status không đồng nghĩa action: invalid vẫn có thể keep để điều tra. Flow Tracker sau này chỉ nên track khi các field định danh đã hợp lệ; không dùng action keep như bằng chứng event hợp lệ.

## Validation

Bắt buộc có hai địa chỉ IP hợp lệ và timestamp có timezone. Với TCP/UDP, cần src_port và dst_port là số nguyên 0–65535; boolean không được xem là port. Network protocol nếu có phải nằm trong 0–255 và phù hợp TCP=6/UDP=17. HTTP/SMTP yêu cầu TCP.

Các field length/id kiểm tra 0–65535, ttl 0–255. Thiếu length/ttl/id được đánh dấu partial và dùng null. TCP flags nếu có phải chứa ký hiệu hỗ trợ; thiếu flags là partial.

Đây là kiểm tra schema/event, không tính lại checksum, không xác minh handshake, không kiểm tra tính đúng đắn toàn bộ HTTP/DNS/SMTP.

## Normalization an toàn

- IP: loại khoảng trắng ngoài và dùng biểu diễn chuẩn của ipaddress, hỗ trợ cả IPv4/IPv6 ở cấp event. Capture/parser hiện vẫn phục vụ IPv4.
- Timestamp: chuỗi ISO 8601 có timezone chuyển về UTC, sáu chữ số microsecond và hậu tố Z. Không đoán timezone cho timestamp thiếu timezone.
- Protocol: bỏ khoảng trắng ngoài và viết hoa; thiếu protocol dùng UNKNOWN.
- HTTP header name: viết thường, giá trị luôn là list; gộp header khác kiểu chữ và giữ nguyên thứ tự giá trị.
- DNS owner/question name và dữ liệu NS/CNAME/PTR: viết thường, dùng dấu chấm root cuối tên.
- URI/path: giữ nguyên case, slash, percent escapes và query; kiểm tra kiểu và control characters. Không gộp slash, không bỏ dot segments, không decode lần nữa để tránh thay đổi cách server hiểu request.
- Không lowercase toàn bộ HTTP Host value hoặc email local-part. Chưa normalize domain lồng trong MX/SOA/SRV.

## Missing fields và dữ liệu không hỗ trợ

- Field scalar phụ dùng null.
- DNS sections và SMTP entries thiếu dùng [].
- HTTP headers thiếu dùng {} vì đây là mapping.
- Body/URI HTTP và MIME SMTP thiếu dùng null.
- DNS section sai kiểu tạo lý do invalid; malformed record không gây exception.
- HTTP/parser errors hoặc decoder error/partial khiến preprocess_status ít nhất partial.
- UNKNOWN ở tầng application là partial; đây có thể là TCP ACK bình thường, không đồng nghĩa tấn công.

## Kiểm thử

```bash
.venv/bin/python -B -m pytest -v TEST/TEST-02/test_preprocessor.py
.venv/bin/python -B -m pytest -v TEST
```

Test tập trung T05 normalization, T06 missing fields và T14 malformed event, cùng port/range, timezone, protocol mismatch, policy và bảo toàn đầu vào. Báo cáo lần chạy được lưu trong TEST/legacy-results/preprocessor_regression.txt và .xml.

## AI hỗ trợ

OpenAI Codex hỗ trợ triển khai module, nối pipeline, xây test và tài liệu này. Người nộp cần kiểm tra, hiểu và giải thích được mã nguồn.
