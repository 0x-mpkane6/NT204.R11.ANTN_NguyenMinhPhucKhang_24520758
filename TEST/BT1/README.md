# Báo cáo kiểm thử TEST-01

Kết quả chạy thực tế: **53 PASS, 0 FAIL, 0 SKIP**.

Nguồn: [pytest.txt](result/pytest.txt), [JUnit XML](result/pytest.xml). PASS chỉ áp dụng cho các đầu vào/assert đã kiểm chứng, không khẳng định mọi trường hợp của giao thức đều đúng.

| Testcase trong đề | Kiểm chứng điều gì | Cơ chế / bằng chứng trong hệ thống | Script và hàm test | Kết quả |
|---|---|---|---|---|
| TCP handshake | Đọc SYN, SYN/ACK, ACK | TCP parser trích xuất flags, port, seq/ack, window | [test_transport.py](test_transport.py) — `test_tcp_handshake` | PASS |
| TCP data | Parse TCP có payload | TCP PA và HTTP POST có body abc | [test_transport.py](test_transport.py) — `test_tcp_data` | PASS |
| UDP | Trích xuất UDP fields | So sánh port, length=11 và checksum đã được Scapy tính | [test_transport.py](test_transport.py) — `test_udp_and_ipv4` | PASS |
| HTTP GET | Nhận diện HTTP request | Payload GET, xác nhận request và headers_complete | [test_application_parsers.py](test_application_parsers.py) — `test_http` | PASS |
| HTTP POST | Request có body | Content-Length=3, assert body=abc | [test_application_parsers.py](test_application_parsers.py) — `test_http` | PASS |
| HTTP response | Status code và header | Assert status=200 và hai Set-Cookie được giữ | [test_application_parsers.py](test_application_parsers.py) — `test_http` | PASS |
| DNS Query | Domain và query type | Query AAAA; test DNS khác kiểm tra domain example.org. | [test_application_parsers.py](test_application_parsers.py) — `test_dns_query_and_bad_pointer`, `test_dns` | PASS |
| DNS Response | Ít nhất một answer | Assert answer A=1.2.3.4 qua UDP/TCP và compression | [test_application_parsers.py](test_application_parsers.py) — `test_dns` | PASS |
| SMTP command | HELO/EHLO, MAIL FROM, RCPT TO | Tạo command và assert tên lệnh, detector SMTP | [test_application_parsers.py](test_application_parsers.py) — `test_smtp_commands` | PASS |
| SMTP response | Đọc status code | Assert hai mã 250 và continuation đúng | [test_application_parsers.py](test_application_parsers.py) — `test_smtp_responses_and_ambiguity` | PASS |
| Unknown protocol | Không crash | Empty/unsupported/TLS payload trả UNKNOWN | [test_application_parsers.py](test_application_parsers.py) — `test_unknown` | PASS |
| Malformed packet | Không crash, tiếp tục xử lý | Packet lỗi đi trước; event hợp lệ sau vẫn được ghi | [test_error_handling.py](test_error_handling.py) — `test_bad_packet_does_not_block_next_packet` | PASS |

## Phạm vi và cách chạy

```bash
.venv/bin/python -B -m pytest -v TEST/TEST-01 --junitxml=TEST/TEST-01/result/pytest.xml > TEST/TEST-01/result/pytest.txt 2>&1
```

Bảng trên ánh xạ testcase yêu cầu sang test tự động, không phải mỗi hàng tương ứng đúng một lần chạy pytest. Parametrize tạo nhiều biến thể; một hàm có thể kiểm chứng nhiều yêu cầu.

Live capture được giả lập trong test. Bộ test đang chạy trên phiên bản code hiện tại sau khi tích hợp hai bài; đây không phải chạy lại snapshot lịch sử bài 1. File PCAP/JSONL tạm do pytest tạo không phải minh chứng capture mạng thực tế.

Sau khi sửa code và chạy lại test, cần cập nhật bảng này nếu thay đổi kết quả hoặc phạm vi assert. Báo cáo TXT/XML là bằng chứng máy đọc; báo cáo Markdown này dùng để đối chiếu yêu cầu.

## Các kiểm thử bổ sung

- [test_application_parsers.py](test_application_parsers.py)
- [test_error_handling.py](test_error_handling.py)
- [test_jsonl_writer.py](test_jsonl_writer.py)
- [test_main_logging.py](test_main_logging.py)
- [test_pcap_pipeline.py](test_pcap_pipeline.py)
- [test_transport.py](test_transport.py)
