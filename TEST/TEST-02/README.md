# Báo cáo kiểm thử TEST-02

Kết quả chạy thực tế: **44 PASS, 0 FAIL, 0 SKIP**.

Nguồn: [pytest.txt](result/pytest.txt), [JUnit XML](result/pytest.xml). PASS chỉ áp dụng cho các đầu vào/assert đã kiểm chứng, không khẳng định mọi trường hợp của giao thức đều đúng.

| Testcase trong đề | Kiểm chứng điều gì | Cơ chế / bằng chứng trong hệ thống | Script và hàm test | Kết quả |
|---|---|---|---|---|
| T01 — HTTP URL decode | Decoded URI đúng, giữ raw | Decode percent một lần, giữ dấu + và kiểm tra đầu vào không đổi | [test_decoder.py](test_decoder.py) — `test_url_preserves_raw_and_decodes_once` | PASS |
| T02 — HTML entity | Decode text HTTP an toàn | Assert &lt;script&gt; thành &lt;script&gt; | [test_decoder.py](test_decoder.py) — `test_http_text_and_form` | PASS |
| T03 — SMTP Base64/QP | Body và decode_status | Hai encoding cho hello, status success | [test_decoder.py](test_decoder.py) — `test_mime_transfer` | PASS |
| T04 — Invalid bytes | Partial, không crash | UTF-8 lỗi thành U+FFFD và có decode_errors | [test_decoder.py](test_decoder.py) — `test_invalid_utf8` | PASS |
| T05 — Normalization | Representation nhất quán | Protocol/header/IP/timestamp và DNS domain được chuẩn hóa | [test_preprocessor.py](test_preprocessor.py) — `test_t05_normalization_preserves_original`, `test_dns_and_missing_optional_fields` | PASS |
| T06 — Missing field | null/[] nhất quán | Thiếu TTL thành null, answers thành [], status partial | [test_preprocessor.py](test_preprocessor.py) — `test_dns_and_missing_optional_fields` | PASS |
| T07 — TCP handshake | Một flow ESTABLISHED | S→SA→A, assert cùng flow_id và state cuối | [test_flow_tracker.py](test_flow_tracker.py) — `test_handshake_bidirectional_statistics` | PASS |
| T08 — Bidirectional flow | Cùng flow_id, đúng direction | Đảo endpoint, assert backward và cùng ID | [test_flow_tracker.py](test_flow_tracker.py) — `test_handshake_bidirectional_statistics` | PASS |
| T09 — TCP close | CLOSED/RESET phù hợp | FIN hai chiều và ACK xác nhận; RST xuất flow ngay | [test_flow_tracker.py](test_flow_tracker.py) — `test_fin_close_and_rst` | PASS |
| T10 — UDP query/response | Một flow, counters đúng | DNS query/response Scapy qua parser và preprocessor; assert cùng ID, tổng và hai chiều packet/byte count | [test_flow_tracker.py](test_flow_tracker.py) — `test_dns_udp_query_response_pipeline` | PASS |
| T11 — Concurrent flows | Không gộp nhầm | Port khác nhau tạo hai active flows | [test_flow_tracker.py](test_flow_tracker.py) — `test_udp_timeout_concurrency_capacity` | PASS |
| T12 — Idle timeout | Xuất và xóa flow | expire theo timestamp, kiểm tra active rỗng và close_reason | [test_flow_tracker.py](test_flow_tracker.py) — `test_udp_timeout_concurrency_capacity`, `test_tcp_timeout_reuse_and_out_of_order` | PASS |
| T13 — Statistics | Packet/byte/flag/duration | Assert 3 packet, 120 byte, duration=2, forward/backward và SYN/ACK | [test_flow_tracker.py](test_flow_tracker.py) — `test_handshake_bidirectional_statistics` | PASS |
| T14 — Malformed event | Status/reason, không crash | Invalid schema và unsupported policy ở preprocessor; tracker bỏ qua event lỗi | [test_preprocessor.py](test_preprocessor.py) — `test_t14_malformed`, `test_unsupported_policy` | PASS |

## Phạm vi và cách chạy

```bash
.venv/bin/python -B -m pytest -v TEST/TEST-02 --junitxml=TEST/TEST-02/result/pytest.xml > TEST/TEST-02/result/pytest.txt 2>&1
```

Bảng trên ánh xạ testcase yêu cầu sang test tự động, không phải mỗi hàng tương ứng đúng một lần chạy pytest. Parametrize tạo nhiều biến thể; một hàm có thể kiểm chứng nhiều yêu cầu.

Live capture được giả lập trong test. Bộ test đang chạy trên phiên bản code hiện tại sau khi tích hợp hai bài; đây không phải chạy lại snapshot lịch sử bài 1. File PCAP/JSONL tạm do pytest tạo không phải minh chứng capture mạng thực tế.

Sau khi sửa code và chạy lại test, cần cập nhật bảng này nếu thay đổi kết quả hoặc phạm vi assert. Báo cáo TXT/XML là bằng chứng máy đọc; báo cáo Markdown này dùng để đối chiếu yêu cầu.

## Các kiểm thử bổ sung

- [test_decoder.py](test_decoder.py)
- [test_flow_tracker.py](test_flow_tracker.py)
- [test_preprocessor.py](test_preprocessor.py)
- [test_raw_mime.py](test_raw_mime.py)

Giới hạn: chưa reassembly TCP/multipart MIME; TCP state là mô hình logic.
