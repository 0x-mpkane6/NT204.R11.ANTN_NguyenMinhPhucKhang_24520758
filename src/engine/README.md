# Engine input — bước nền bài 3

Hiện có context adapter, Internal Rule Object, Parser/Validator và Rule Loader. Đã có Repository/Indexer; chưa có matcher/evaluator.

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

Rule lỗi không trả object có thể chạy một phần. Parser báo vấn đề đầu tiên gặp; một rule vừa có lỗi vừa có keyword unsupported có thể được phân loại theo vấn đề gặp trước. Comment/dòng trống, rule nhiều dòng và enable/disable thuộc Loader sẽ làm sau. ip/any ở vị trí protocol chưa được hỗ trợ, giữ phạm vi bắt buộc tcp/udp của bảng đề bài; không nhầm với any ở địa chỉ/port.

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

IP any là wildcard và port any là khoảng 0–65535. Protocol ip/any chưa được parser hỗ trợ; không được coi chúng là wildcard một cách âm thầm. CIDR được biên dịch thành IPv4Network một lần khi thêm rule.

### Hiệu năng và bảo toàn dữ liệu

Rule exact port không liên quan được loại qua chỉ mục mà không kiểm tra từng header. Range hiện duyệt tuyến tính theo số range của protocol; không bung khoảng 0–65535 thành hàng nghìn phần tử. Nếu nhiều rule any hoặc range phủ rộng thì vẫn có nhiều candidates. Đây là index cơ bản, chưa phải thuật toán interval tree.

`last_query` chứa indexed_rules, header_checks, candidates và reason. header_checks đếm số rule đã kiểm tra đầy đủ header, không bao gồm số range đã quét; đây không phải tổng số phép toán. Test 500 exact-port rules xác nhận chỉ một header được kiểm tra cho port 80.

Repository sao chép rule lúc thêm và khi trả kết quả để code bên ngoài không sửa rule làm lệch index. Context invalid/thiếu field, port/IP sai hoặc protocol không hỗ trợ trả [] và last_query.reason. Context partial vẫn có thể chọn theo header nếu các field header hợp lệ.

Candidate chưa phải MATCH: chưa kiểm tra content, flags/dsize hoặc flow conditions. Matching Engine sẽ kiểm tra các điều kiện còn lại, không được sinh Detection Event chỉ vì rule nằm trong candidates. Module chưa nối main/CLI vì chưa có Evaluator.

Test: TEST/BT3/test_repository.py, bao phủ protocol, any/CIDR, exact/range/boundaries, ->/<>, source port, chống trùng, bảo toàn index, malformed context và nối Loader. Báo cáo: TEST/BT3/result/repository.txt và .xml.
