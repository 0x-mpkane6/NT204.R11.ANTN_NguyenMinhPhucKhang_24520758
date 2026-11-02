# Engine input — bước nền bài 3

Hiện chỉ có `context.py`, chưa có rule parser/matcher/evaluator.

```python
from src.engine import build_context
context = build_context(event, max_buffer_bytes=1048576)
```

Đầu vào: event sau Preprocessor và FlowTracker; không truyền Scapy packet. Hàm không sửa event, trả dictionary nội bộ có buffers dạng bytes. Không ghi trực tiếp context vào JSONL vì bytes không JSON-compatible. Chưa gọi adapter trong main khi engine chưa được xây; main đã xuất dữ liệu cần thiết cho adapter.

- normalized network/transport cung cấp IP, port, protocol và timestamp.
- TCP/UDP parser giữ `payload_length` và `raw_payload_base64`, kể cả application UNKNOWN. ACK rỗng có length=0 và raw="".
- `payload_size` dành cho dsize; không dùng IP total length.
- `buffers.payload` là bytes gốc, buffer mặc định cho content sau này.
- Các buffer decoded nằm riêng, được mã hóa UTF-8: http.uri.decoded, http.body.decoded hoặc smtp.body.decoded. Offset trong buffer decoded là byte của biểu diễn UTF-8, không phải offset trong payload gốc.
- context_status là valid/partial/invalid; context_errors giải thích vấn đề. Thiếu payload không biến thành b"". Sai length/Base64 hoặc vượt giới hạn không tạo payload buffer.
- max_buffer_bytes giới hạn từng buffer, không phải tổng kích thước event; cấu hình sai gây ValueError.

## Flow context

Flow event nay có snapshot gồm endpoint, counters, state và các field mới:

| Field | Ý nghĩa |
|---|---|
| client/server | Endpoint suy luận từ SYN hoặc SYN/ACK; None khi chưa xác định |
| role_source | tcp_syn hoặc tcp_synack |
| service_direction | to_server/to_client, None nếu chưa biết vai trò |
| established | True/False/None (không xác định hoặc không áp dụng UDP) |
| established_source | observed_handshake, inferred_midstream, handshake_in_progress hoặc None |

forward/backward vẫn căn cứ endpoint đầu tiên, độc lập với hướng client/server. ACK bắt giữa phiên giữ suy luận established của tracker cũ nhưng có nhãn inferred_midstream, không giả làm handshake đã quan sát. established ghi nhớ việc đã thiết lập, không mất khi CLOSING/CLOSED/RESET. Matcher sau này cần dùng cả state và nguồn suy luận theo chính sách đã chốt.

Giới hạn: quan sát handshake theo flags/direction, chưa kiểm tra đầy đủ sequence; chưa xử lý simultaneous open hay thay đổi vai trò. UDP chưa suy luận client/server. Core Engine chưa có và adapter chưa tự xác nhận snapshot flow từ nguồn ngoài là đáng tin.

## Kiểm thử

`TEST/BT3/test_context.py`: payload TCP/UDP (rỗng và binary), bảo toàn đầu vào, flow roles, handshake/midstream, FIN, thiếu/sai/giới hạn buffer và buffer decoded độc lập. Đây là test nền, chưa phải đủ 14 testcase của đề bài 3.

OpenAI Codex hỗ trợ triển khai và kiểm thử bước này.
