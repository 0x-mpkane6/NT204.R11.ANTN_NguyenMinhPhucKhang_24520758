# Bài 3 — Báo cáo Core Engine và Snort Rule Matching

Đối chiếu mục 7 của `Bai-tap-03_Core_Engine_IDS.pdf`. Lần chạy ngày 02/11/2026: **88 test instances PASS**, không FAIL/SKIP. Hồi quy cả BT1–BT3: **185 PASS**. Số instance có tính các biến thể parametrize, không phải số testcase trong đề.

Bằng chứng: [báo cáo BT3](result/pytest.txt), [JUnit XML](result/pytest.xml), [hồi quy toàn bộ](result/regression.txt). Bảng dưới ánh xạ 14 yêu cầu vào cơ chế và assert thực tế; PASS chỉ áp dụng phạm vi kiểm thử được mô tả.

| # | Testcase theo đề | Kiểm chứng / kết quả mong đợi | Hệ thống đáp ứng bằng gì | Script và hàm test | Kết quả |
|---|---|---|---|---|---|
| 1 | Nạp file rule hợp lệ, comment, dòng trống | Chỉ dòng rule được parse, giữ vị trí nguồn | Loader bỏ dòng rỗng/# ngoài quoted string, hỗ trợ BOM, không cắt # trong msg | [test_rule_loader.py](test_rule_loader.py): `test_comments_blank_and_source` | PASS |
| 2 | Rule sai cú pháp | invalid có lý do, tiếp tục rule khác | Parser trả RuleParseResult; Loader thu diagnostics; batch có cả rule sai và rule hợp lệ | [test_rule_parser.py](test_rule_parser.py): `test_invalid`, `test_batch_continues_and_requires_identification`; [test_rule_loader.py](test_rule_loader.py): `test_bad_rule_does_not_stop_other_files` | PASS |
| 3 | Keyword ngoài phạm vi | unsupported, không crash | pcre/flow option/content negation chưa hỗ trợ bị từ chối toàn rule | [test_rule_parser.py](test_rule_parser.py): `test_unsupported`; [test_rule_loader.py](test_rule_loader.py): `test_bad_rule_does_not_stop_other_files` | PASS |
| 4 | Header TCP, any/single IP/CIDR, port/range | Internal Rule Object đúng | Chuẩn hóa IPv4 network, port thành tuple, giữ metadata | [test_rule_parser.py](test_rule_parser.py): `test_header_and_metadata`, `test_header_variants`; [test_repository.py](test_repository.py): `test_bidirectional_and_source_port` | PASS |
| 5 | Direction -> và <> | Đúng chiều và chiều đảo | Repository lập entry chiều đảo; matcher kiểm tra endpoint hai chiều | [test_repository.py](test_repository.py): `test_bidirectional_and_source_port`; [test_matching.py](test_matching.py): `test_matcher_direction_reverse` | PASS |
| 6 | Indexer với IP, TCP, UDP và any | Đúng tập candidates | Nhóm protocol cụ thể cùng nhóm ip/any; lọc IP/CIDR, exact/range/any port | [test_repository.py](test_repository.py): `test_ip_tcp_udp_any_candidates`, `test_protocol_exact_range_any_cidr`, `test_index_prunes_unrelated_ports` | PASS trong phạm vi IPv4 TCP/UDP (*) |
| 7 | Header không match | Loại trước content | Matcher kiểm tra header trước khi đọc buffer; test cố tình để buffers=None | [test_matching.py](test_matching.py): `test_header_short_circuits_content` | PASS |
| 8 | flow:to_server,established | Match theo Flow Tracker | Packet S→SA→A qua parser/preprocessor/tracker/context/matcher; chỉ ACK client sau handshake match | [test_matching.py](test_matching.py): `test_flow_tracker_to_server_established_integration`, `test_flow_observed_inferred_unknown` | PASS |
| 9 | content có/không nocase | Đúng phân biệt case | So sánh bytes thường hoặc ASCII lowercase | [test_matching.py](test_matching.py): `test_conditions` — ABC/abc có và không nocase | PASS |
| 10 | offset/depth | Pattern nằm trọn cửa sổ | Start theo offset, end theo offset+depth | [test_matching.py](test_matching.py): `test_conditions` — offset/depth match và không match | PASS |
| 11 | Hai content distance/within | Relative matching đúng | Cửa sổ từ cuối content trước; xét nhiều vị trí, kể cả lần đầu thất bại | [test_matching.py](test_matching.py): `test_conditions`, `test_evidence_and_limits` | PASS |
| 12 | flags và dsize | Match/không match theo event | Exact flag set; dsize =, <, >, khoảng loại trừ cận | [test_matching.py](test_matching.py): `test_conditions`; [test_rule_parser.py](test_rule_parser.py): `test_packet_and_flow_options` | PASS |
| 13 | Một event match ≥2 rule | Sinh đầy đủ kết quả | Evaluator không dừng ở rule đầu; CLI PCAP ghi hai detections dù có rule lỗi/disabled | [test_evaluator.py](test_evaluator.py): `test_multiple_matches_and_detection_schema`; [test_engine_cli.py](test_engine_cli.py): `test_cli_pcap_multiple_detection_and_disable` | PASS |
| 14 | Detection Event | Đủ SID/rev/msg/priority/classtype, timestamp, 5-tuple, application, flow, evidence | Generator tạo JSON-compatible detection; kiểm tra giá trị field và vị trí content | [test_evaluator.py](test_evaluator.py): `test_multiple_matches_and_detection_schema`, `test_generator_guard_and_optional_fields` | PASS |

(*) Bảng phạm vi trong đề yêu cầu tcp/udp, nhưng testcase 6 nhắc IP và any. Để bao phủ, project mở rộng rule protocol `ip` và `any` thành nhóm chung cho event IPv4 TCP/UDP hiện có. `any` ở vị trí protocol là quy ước mở rộng của project; không tuyên bố đây là toàn bộ cú pháp Snort. Chưa hỗ trợ event ICMP/IPv6 hay toàn bộ IP protocol. Any ở IP/port vẫn hoạt động độc lập. Flags/connection-state options vẫn yêu cầu rule TCP.

## Chạy và cập nhật bằng chứng

Từ thư mục gốc repo:

```bash
.venv/bin/python -B -m pytest -v TEST/BT3 \
  --junitxml=TEST/BT3/result/pytest.xml > TEST/BT3/result/pytest.txt 2>&1
.venv/bin/python -B -m pytest -q TEST/BT1 TEST/BT2 TEST/BT3 \
  --junitxml=TEST/BT3/result/regression.xml > TEST/BT3/result/regression.txt 2>&1
```

TXT để đọc, XML cho công cụ báo cáo; README này được đối chiếu thủ công, không tự cập nhật sau khi sửa source. Các báo cáo tên context/rule_parser/rule_loader/repository/matching/evaluation/integration là kết quả lịch sử theo từng giai đoạn, không dùng thay tổng kết mới nhất.

## Phạm vi còn lại

- CLI offline được chạy bằng subprocess với PCAP thật do test tạo; live callback vẫn giả lập, chưa chứng minh capture mạng thực tế.
- Rule file mỗi dòng một rule; chưa multiline. Không hỗ trợ pcre, biến/list/negation, flag masks hay toàn bộ Snort.
- Content matching dùng payload packet, không TCP stream reassembly. Buffer decoded có thể chọn qua API, chưa có keyword sticky-buffer Snort.
- Thiếu dữ liệu/vượt giới hạn matching có complete=False và evaluation partial; không được diễn giải thành không có tấn công.
- TCP established mặc định cần handshake quan sát; trạng thái tracker là mô hình logic, chưa xác minh đầy đủ sequence.
- Rule mẫu là signature demo, không phải bộ rule Snort chính thức hay bộ bảo vệ production.

Các điểm trên là giới hạn được công bố, không che giấu bằng tổng số test PASS. Báo cáo này chứng minh 14 nhóm testcase trong phạm vi hiện tại; không chứng minh tương thích toàn bộ Snort hoặc mọi hidden input.
