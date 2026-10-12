# Decoder — Bài tập 2

Module nhận dictionary từ parser bài 1, giải mã dữ liệu application và trả về một dictionary mới. Không đọc Scapy packet, không sửa event đầu vào, không thực hiện validation/normalization hay tracking flow.

## Các thành phần

| File | Nhiệm vụ |
|---|---|
| `__init__.py` | Export API `decode_event` |
| `decoder.py` | Sao chép event, chọn decoder theo application protocol, tổng hợp status và lỗi |
| `common.py` | Khôi phục raw bytes từ Base64, giới hạn kích thước, decode ASCII/UTF-8 và percent escapes |
| `http_decoder.py` | Decode URI, form URL-encoded và HTML entities trong text HTTP |
| `smtp_decoder.py` | Đọc MIME metadata, decode transfer encoding rồi character encoding |

## API và pipeline

```python
from src.decoder import decode_event

result = decode_event(event, max_field_bytes=1048576)
```

`max_field_bytes` là giới hạn byte cho mỗi field raw, mặc định 1 MiB. Giá trị cấu hình phải là số nguyên dương; cấu hình sai gây ValueError. Đây không phải giới hạn tổng bộ nhớ của event hay TCP stream.

`main.py` gọi decoder sau parser và thêm timestamp, trước khi ghi JSONL. Live capture và PCAP sử dụng chung luồng này. Không cần đổi lệnh chạy.

Output giữ nguyên các field cũ, thêm ba field ở cấp event:

```json
{
  "decoded": {"uri": "/' OR 1=1"},
  "decode_status": "success",
  "decode_errors": []
}
```

| Status | Ý nghĩa |
|---|---|
| `success` | Có kết quả decode và không ghi nhận lỗi |
| `partial` | Có kết quả nhưng có lỗi hoặc message chưa đầy đủ |
| `error` | Có lỗi và không tạo được kết quả decode |
| `skipped` | Không có field phù hợp để decode, ví dụ DNS hoặc SMTP command |

Status này mô tả bước decoder, không thay thế trạng thái hợp lệ của packet hay preprocessor.

## HTTP

- Khôi phục URI từ `raw_uri_base64`, percent-decode đúng một lần, chuyển UTF-8 và lưu `decoded.uri`.
- Dấu `+` trong URI được giữ nguyên. `%2520` thành `%20`, không decode lần hai.
- Body chỉ được xử lý khi Content-Type cho biết `text/*` hoặc `application/x-www-form-urlencoded`.
- Form: tách cặp theo `&`, tách tên/giá trị trước khi decode; đổi `+` thành khoảng trắng. `decoded.form_fields` là list để giữ thứ tự, tên trùng và giá trị rỗng.
- Text: lưu character-decoded body vào `decoded.body`, phiên bản HTML entity decoded vào `decoded.html_text`. Không chạy nội dung HTML.
- Charset mặc định của module cho HTTP là UTF-8; có hỗ trợ ASCII. Charset khác được báo lỗi, không tự đoán.
- Không tự giải nén Content-Encoding hoặc xử lý Transfer-Encoding; body đó được bỏ qua với lý do rõ ràng. URI vẫn có thể được decode.

## SMTP/MIME

Input là `application.mime` do parser cung cấp, gồm raw body, Content-Type, charset và Content-Transfer-Encoding.

Có hai lớp Base64 khác nhau:

1. `raw_body_base64` chỉ là cách giữ bytes gốc trong JSON. Luôn khôi phục lớp này trước.
2. Chỉ giải mã Base64 của nội dung thư nếu MIME header chỉ định `base64`.

Quoted-Printable cũng chỉ được giải mã khi header chỉ định. Thiếu encoding dùng `7bit`; `7bit`, `8bit`, `binary` không thực hiện biến đổi transfer encoding. Base64 lỗi bị từ chối; QP escape lỗi được đánh dấu và vẫn giữ kết quả xử lý có thể có.

Sau bước transfer decoding, `decoded.body_base64` giữ bytes kết quả. Với MIME text, decoder tạo thêm `decoded.body` theo charset; mặc định ASCII khi thiếu charset. Binary không bị ép thành text. MIME thiếu phần kết thúc được đánh dấu partial.

## Lỗi và bảo toàn dữ liệu

Các `raw_*_base64` trong application được giữ nguyên. Byte ASCII/UTF-8 lỗi được thay bằng U+FFFD ở bản text và ghi lỗi; raw vẫn cho phép kiểm tra lại. Không dùng bản text mà parser đã thay thế ký tự để làm đầu vào giải mã.

Sai raw Base64, charset không hỗ trợ, sai schema field hoặc vượt giới hạn đều có lỗi trong output. Không có field raw thì không tự dựng lại bytes từ text mất dữ liệu.

## Giới hạn hiện tại

- Chưa ghép TCP stream/SMTP DATA nhiều packet; phụ thuộc dữ liệu parser đã trích xuất.
- Chưa xử lý multipart MIME hoặc attachment đệ quy; multipart được báo không hỗ trợ.
- Chưa giải mã TLS/HTTPS, nén HTTP hoặc chunked body.
- Chỉ hỗ trợ charset ASCII/UTF-8; chưa decode MIME encoded-word trong Subject.
- Module không duy trì flow hoặc bộ đệm phiên.

## Kiểm thử

Từ thư mục gốc repo:

```bash
.venv/bin/python -B -m pytest -v TEST/test_decoder.py
.venv/bin/python -B -m pytest -v TEST
```

Test decoder bao phủ URL (T01), HTML entity (T02), MIME Base64/QP (T03), invalid bytes (T04), form trùng key, giữ raw, decode một lần, input lỗi và giới hạn kích thước. Đây là kiểm thử module, chưa thay thế toàn bộ test bài 2.

## AI hỗ trợ

OpenAI Codex hỗ trợ triển khai module, tích hợp main.py, viết test và tài liệu này. Người nộp cần kiểm tra và hiểu mã nguồn.
