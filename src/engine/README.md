# Engine input — bước nền bài 3

Hiện có context adapter, Internal Rule Object, Parser/Validator và Rule Loader. Đã có Repository/Indexer, Matching Engine, Evaluation Engine và Detection Generator. Đã tích hợp main/CLI; xem phần cuối tài liệu.

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

## Internal Rule Object và Parser/Validator

Parser/Validator đã có; Rule Loader được trình bày bên dưới. Repository/Indexer được trình bày bên dưới; chưa có Matching Engine.

| File | Vai trò |
|---|---|
| models.py | Dataclass RuleHeader, ContentCondition, Rule, RuleParseResult |
| rule_parser.py | Tách header/options theo dấu nháy và escape, parse content text/hex, tạo object |
| rule_validator.py | Kiểm tra IPv4/CIDR, port, số nguyên, quan hệ giữa các option |

```python
from src.engine import parse_rule

result = parse_rule(
    'alert tcp any any -> 192.0.2.0/24 80 (msg:"Demo"; content:"admin"; nocase; sid:100001; rev:1;)',
    source='local.rules', line_number=1,
)
if result.status == 'valid':
    internal_rule = result.rule
else:
    print(result.status, result.reasons)
```

Rule giữ header, msg/sid/rev, danh sách content theo thứ tự, flow, flags, dsize, classification và vị trí nguồn. Pattern là bytes để matcher dùng byte offset. Object nội bộ không phải JSON output. Parser không đọc file, không match event và không in thông báo.

### Phạm vi cú pháp

- alert; tcp/udp; direction -> hoặc <>.
- IP any, IPv4 hoặc CIDR (chuẩn hóa network); port any, số đơn, khoảng a:b, :b, a:.
- msg, sid và rev bắt buộc theo chính sách project; sid/rev/priority là số nguyên dương.
- content dạng chuỗi, hex block như `|00 FF|`, escape quote/backslash/semicolon/colon/pipe. Text literal được mã hóa UTF-8; nên dùng hex cho bytes đặc biệt.
- nocase, offset/depth/distance/within gắn với content gần nhất. Offset/distance hỗ trợ số không âm; depth/within dương và không nhỏ hơn pattern. Relative cần content đứng trước; không trộn absolute/relative trên cùng content.
- flags dạng tập cờ chính xác hoặc 0; chưa hỗ trợ masks/modifiers.
- dsize: n, >n, <n, a<>b; object lưu (operator, low, high). Matcher sau này phải áp dụng khoảng a<>b với hai cận loại trừ, so theo byte payload gốc.
- flow: to_server/to_client và established/not_established; cặp mâu thuẫn bị từ chối.
- classtype giữ tên ký hiệu; chưa tra classification.config hay suy ra priority.

### Phân loại kết quả

- valid: có rule object.
- invalid: cú pháp/giá trị sai, field bắt buộc thiếu, duplicate option đơn hoặc điều kiện mâu thuẫn.
- unsupported: action/protocol/keyword nằm ngoài tập hỗ trợ, biến $HOME_NET, IP/port list/negation, content negation, flag modifier, escape ngoài tập hỗ trợ.

Rule lỗi không trả object có thể chạy một phần. Parser báo vấn đề đầu tiên gặp; một rule vừa có lỗi vừa có keyword unsupported có thể được phân loại theo vấn đề gặp trước. Comment/dòng trống, rule nhiều dòng và enable/disable thuộc Loader sẽ làm sau. Protocol ip/any hiện là nhóm chung cho event IPv4 TCP/UDP để bao phủ testcase 6; any protocol là mở rộng của project, không tuyên bố tương thích toàn bộ Snort.

Test: TEST/BT3/test_rule_parser.py. Chạy cùng context và hồi quy hai bài trước; kết quả tại TEST/BT3/result/rule_parser.txt và .xml.

## Rule Loader

`rule_loader.py` đọc một/nhiều file và gọi Parser/Validator cho từng dòng có nội dung. Loader chưa được nối CLI/main; đã có Repository bên dưới, chưa có Matching Engine.

```python
from src.engine import RuleFile, load_rules

report = load_rules(
    [RuleFile('rules/local.rules'), RuleFile('rules/disabled.rules', enabled=False)],
    disabled_sids={100002},
    enabled_sids=None,
)
for rule in report.rules:
    print(rule.sid, rule.source, rule.line_number)
for warning in report.diagnostics:
    print(warning)
print(report.counts)
```

- RuleFile gồm path và enabled; cũng nhận trực tiếp str/Path. Path tương đối tính từ working directory.
- disabled_sids là danh sách SID không được nạp. enabled_sids=None cho phép tất cả, tập rỗng không cho phép SID nào; nếu SID nằm trong cả hai thì disable ưu tiên.
- File bị disable không được mở. Rule bị disable vẫn được parse để lấy SID chính xác; rule sai/unsupported vẫn được báo lỗi.
- Bỏ dòng trống và comment bắt đầu bằng # ngoài quoted string. Dấu # trong msg/content được giữ; xử lý escaped quote. Hỗ trợ UTF-8 BOM đầu file.
- Mỗi dòng chứa một rule hoàn chỉnh. Chưa nối multiline/backslash continuation; các dòng đó sẽ được parser phân loại thay vì đoán nội dung.
- Lỗi mở/đọc file có file_error; lỗi UTF-8 của một dòng là invalid và tiếp tục dòng sau. Rule invalid/unsupported không nằm trong report.rules.
- SID trùng: giữ rule valid/enabled đầu tiên theo thứ tự file/dòng, báo duplicate_sid cho rule sau, không tự chọn revision cao nhất.

RuleLoadReport.rules là danh sách dùng cho Repository sau này. results giữ kết quả parse kể cả rule valid bị disable/trùng. diagnostics chứa status, source, line_number, reasons, sid; caller hiển thị/ghi cảnh báo, Loader không tự in ra stdout. counts tổng hợp loaded, invalid, unsupported, disabled_rules/files, file_errors và duplicates. Cấu hình sai kiểu SID/enabled gây ValueError, khác với lỗi dữ liệu rule được thu thập an toàn.

Test: TEST/BT3/test_rule_loader.py; báo cáo hồi quy: TEST/BT3/result/rule_loader.txt và .xml.

## Rule Repository / Indexer

`repository.py` cung cấp `RuleRepository`, nhận các Rule đã validate từ Loader:

```python
from src.engine import load_rules, RuleRepository, build_context

report = load_rules(['rules/local.rules'])
repository = RuleRepository(report.rules)
context = build_context(event)
candidates = repository.candidates(context)
print(repository.last_query)
```

Chỉ khởi tạo repository một lần khi nạp rule. `add(rule)` thêm rule hợp lệ; SID trùng gây ValueError, vì Loader đã có chính sách xử lý duplicate. Repository kiểm tra header tối thiểu; caller vẫn phải dùng Parser/Validator cho toàn bộ option.

### Chỉ mục và lựa chọn

1. Tách protocol TCP/UDP.
2. Theo destination port của event, lấy rule exact từ dictionary, rule any từ set, rule range chứa port từ danh sách range.
3. Với rule <>, lập thêm entry theo source port của rule để không bỏ sót chiều đảo.
4. Kiểm tra cả hai IP/CIDR, source/destination port và direction trên tập vừa lấy.
5. Trả rule không trùng, giữ thứ tự nạp ban đầu.

IP any là wildcard và port any là khoảng 0–65535. Protocol ip/any là nhóm rule chung, được truy vấn cùng bucket TCP hoặc UDP; chỉ áp dụng event IPv4 TCP/UDP hiện có. CIDR được biên dịch thành IPv4Network một lần khi thêm rule.

### Hiệu năng và bảo toàn dữ liệu

Rule exact port không liên quan được loại qua chỉ mục mà không kiểm tra từng header. Range hiện duyệt tuyến tính theo số range của protocol; không bung khoảng 0–65535 thành hàng nghìn phần tử. Nếu nhiều rule any hoặc range phủ rộng thì vẫn có nhiều candidates. Đây là index cơ bản, chưa phải thuật toán interval tree.

`last_query` chứa indexed_rules, header_checks, candidates và reason. header_checks đếm số rule đã kiểm tra đầy đủ header, không bao gồm số range đã quét; đây không phải tổng số phép toán. Test 500 exact-port rules xác nhận chỉ một header được kiểm tra cho port 80.

Repository sao chép rule lúc thêm và khi trả kết quả để code bên ngoài không sửa rule làm lệch index. Context invalid/thiếu field, port/IP sai hoặc protocol không hỗ trợ trả [] và last_query.reason. Context partial vẫn có thể chọn theo header nếu các field header hợp lệ.

Candidate chưa phải MATCH: chưa kiểm tra content, flags/dsize hoặc flow conditions. Matching Engine sẽ kiểm tra các điều kiện còn lại, không được sinh Detection Event chỉ vì rule nằm trong candidates. Module chưa nối main/CLI vì chưa có Evaluator.

Test: TEST/BT3/test_repository.py, bao phủ protocol, any/CIDR, exact/range/boundaries, ->/<>, source port, chống trùng, bảo toàn index, malformed context và nối Loader. Báo cáo: TEST/BT3/result/repository.txt và .xml.

## Rule Matching Engine

`matcher.py` cung cấp `RuleMatcher` và `MatchResult`; `matchers/` chứa header.py, flow.py, packet.py, content.py. Đây là một module matching với các thành phần nội bộ. Evaluator/Detection Generator được trình bày bên dưới; chưa tích hợp CLI.

```python
from src.engine import RuleMatcher

matcher = RuleMatcher()
for rule in repository.candidates(context):
    result = matcher.match(rule, context)
    print(result.status, result.reason, result.matched)
```

Input rule phải từ Parser/Validator; context từ build_context. Matcher không in alert và không sửa input. Kết quả gồm status MATCH/NO_MATCH, sid, reason, matched và complete. complete=False báo chưa đánh giá đầy đủ do context/buffer lỗi hoặc giới hạn tài nguyên; không được coi là bằng chứng payload sạch. matched chứa content_index, field, start/end (end loại trừ) và pattern_hex, dùng được trong JSON Detection Event sau này. Rule không có content có thể MATCH với matched=[] nếu các điều kiện khác thỏa.

Thứ tự: header → flow → packet → content. Header không khớp thì không truy cập payload. Header hỗ trợ protocol, IPv4/CIDR/any, port range và ->/<>; vẫn kiểm tra lại dù Repository đã lọc.

Flow to_server/to_client dựa service_direction, không dựa forward/backward. established mặc định cần established=True và established_source=observed_handshake. Có thể bật allow_inferred_established=True để chấp nhận trạng thái suy luận bắt giữa phiên. not_established chỉ chấp nhận False, không coi None là False. Tracker giữ established khi đóng; matcher sử dụng giá trị này để biết flow đã thiết lập trước đó.

Flags khớp tập cờ chính xác, không phụ thuộc thứ tự; 0 biểu diễn không có cờ. dsize dùng payload_size gốc, hỗ trợ =, >, < và khoảng hai cận loại trừ.

Content mặc định tìm trong buffers.payload. Có thể chọn buffer_name khi tạo matcher, ví dụ http.uri.decoded; đây là cấu hình của project, chưa hỗ trợ keyword chọn buffer Snort. Mọi content của rule dùng cùng buffer. dsize không đổi theo buffer decoded.

- nocase dùng bytes.lower(), chỉ gấp chữ hoa ASCII, không case-fold Unicode.
- offset là vị trí bắt đầu tuyệt đối; depth là số byte từ offset.
- distance là số byte bỏ qua từ cuối content trước; within là giới hạn từ cuối content trước, bao gồm khoảng distance.
- Không có relative modifier thì content được tìm độc lập từ đầu buffer (hoặc offset).
- Pattern phải nằm trọn trong cửa sổ. Vị trí tính theo byte, không phải ký tự.
- Giữ các trạng thái vị trí kết thúc khác nhau để thử chuỗi relative ở các lần xuất hiện khác; không chỉ chọn lần xuất hiện đầu tiên. Các trạng thái cùng end được gộp vì các điều kiện sau chỉ phụ thuộc end.

Giới hạn mặc định: max_buffer_bytes=1 MiB, max_content_steps=100000 lần tìm kiếm trong một rule. Vượt giới hạn trả NO_MATCH với complete=False và reason riêng. Không có stream reassembly, regex hay keyword ngoài phạm vi parser.

Test: TEST/BT3/test_matching.py; bao phủ header short-circuit, flow observed/inferred/unknown, content case, offset/depth, distance/within, backtracking, binary, flags/dsize, evidence và giới hạn. Báo cáo hồi quy: TEST/BT3/result/matching.txt và .xml.

## Evaluation Engine và Detection Event Generator

`evaluator.py` có `EvaluationEngine`, `EvaluationResult`. `detection.py` có hàm thuần `generate_detection`. Đã nối main/CLI; cấu hình rule và output detection được trình bày bên dưới.

```python
from src.engine import load_rules, RuleRepository, EvaluationEngine

report = load_rules(['rules/local.rules'])
engine = EvaluationEngine(RuleRepository(report.rules))
result = engine.evaluate(event)
for detection in result.detections:
    writer.write(detection)
print(result.status, result.diagnostics)
print(engine.stats)
```

`evaluate` nhận event sau preprocessing/tracking (không nhận context hoặc Scapy packet). Engine gọi build_context → repository.candidates → matcher cho từng candidate → generator. Một instance engine dùng cho cả phiên để tích lũy counters. Không dừng ở match đầu tiên, không tự in alert hoặc ghi file.

EvaluationResult gồm status, detections, diagnostics, candidate_count, evaluated_count. Status complete nghĩa đánh giá hoàn tất trong phạm vi matcher hiện có, không đồng nghĩa packet an toàn. partial nghĩa context thiếu dữ liệu, giới hạn matching hoặc lỗi riêng một rule; vẫn giữ detections hợp lệ của rule khác. invalid là context/header không dùng được, không đánh giá rule. Lỗi matcher/generator được thu thập theo SID và tiếp tục; lỗi cấu hình/repository là lỗi hệ thống, không bị âm thầm che giấu.

Stats là bản sao: events_received, events_evaluated (context/header hợp lệ, kể cả 0 candidates), invalid_events, candidate_rules, rules_evaluated, matches (detection được tạo thành công), incomplete_rules, rule_errors. Các counters cộng dồn, không reset sau mỗi event.

Detection có event_type=detection, timestamp packet, packet_id, sid/rev/msg, priority/classtype (null khi thiếu), src/dst IP/port, protocol, application_protocol, flow_id (null khi không có), match_info, rule_source/rule_line. match_info chứa vị trí byte và pattern_hex của content. Rule chỉ có header/flags có thể match với contents=[]; không tạo evidence content giả. Không đưa bytes payload hoặc toàn bộ context vào JSON detection.

Generator chỉ chấp nhận complete MATCH có SID đúng rule. Không deduplicate giữa các packet: cùng rule match hai event sẽ sinh hai detection. Event JSONL, flow JSONL và detection JSONL là ba loại dữ liệu khác nhau.

Test: TEST/BT3/test_evaluator.py, kiểm tra nhiều rule cùng match (yêu cầu 13), schema detection (14), counters, không có candidates, invalid input, giới hạn và lỗi rule riêng lẻ. Báo cáo: TEST/BT3/result/evaluation.txt và .xml.

## Tích hợp chạy live/PCAP

main.py đã nạp rule một lần, tạo Repository/Matcher/Evaluator một lần, gọi evaluate sau tracking và packet_id. Ghi detection qua JsonlWriter riêng; event có evaluation metadata. Matching Engine vẫn không in/ghi alert; CLI in thông báo detection và thống kê cuối phiên.

```bash
.venv/bin/python main.py --pcap pcap/test-traffic.pcap --rules rules/local.rules
sudo .venv/bin/python main.py --interface wlp8s0 --rules rules/local.rules
```

Mặc định dùng rules/local.rules theo thư mục repo. Đây là rule demo tự viết theo cú pháp hỗ trợ, không phải bộ rule Snort sản xuất. Không truyền --rules vẫn bật engine với file mặc định.

| Cờ | Ý nghĩa |
|---|---|
| --rules PATH | Có thể lặp lại để nạp nhiều file; thay danh sách mặc định |
| --disable-rule-file PATH | Có thể lặp; bỏ mở file tương ứng trong danh sách --rules |
| --disable-sid N | Có thể lặp; disable SID, ưu tiên hơn enable |
| --enable-sid N | Allowlist; khi có cờ thì chỉ nạp các SID đã chỉ định |
| --detection-output PATH | File JSONL detection, mặc định detections_<cùng mốc tên event>.jsonl |
| --allow-inferred-established | Cho flow:established chấp nhận suy luận midstream; mặc định chỉ handshake quan sát |

Rule invalid/unsupported, file thiếu, SID disable/trùng đều có diagnostic trên stderr. Không còn rule active thì cảnh báo rõ và tiếp tục capture với 0 detection. File output append; ba đường dẫn output phải khác nhau và không trùng file PCAP/rule đầu vào. Detection file rỗng nếu không có match là bình thường.

Live và PCAP dùng chung callback. Lỗi ghi detection được truyền ra ngoài để dừng có kiểm soát; không giả vờ ghi thành công. Khi kết thúc in counters engine. Event/flow/detection được ghi riêng, chưa có transaction đảm bảo cả ba đồng thời khi lỗi đĩa.

Test CLI chạy subprocess thật với PCAP và hai rule cùng match; live callback được giả lập, chưa chứng minh live interface thực. TEST/BT3/test_engine_cli.py, báo cáo TEST/BT3/result/integration.txt và .xml.
