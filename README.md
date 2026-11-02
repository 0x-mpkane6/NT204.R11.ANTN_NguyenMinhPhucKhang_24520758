# NT204 — Hệ thống IDS: Capture, Parser, Flow Tracker và Core Engine

- **Sinh viên:** Nguyễn Minh Phúc Khang
- **MSSV:** 24520758
- **Lớp:** NT204.R11.ANTN

Repository chứa các bài tập phát triển từng phần của hệ thống IDS bằng Python. Hiện hỗ trợ thu thập packet, phân tích giao thức, giải mã nội dung, chuẩn hóa event, theo dõi flow hai chiều và phát hiện dấu hiệu bằng signature/rule. Core Engine hỗ trợ một tập con cú pháp Snort; chưa có Feature Extractor hoặc cơ chế ngăn chặn traffic.

## Tổng quan chức năng

| Bài | Nội dung | Thành phần |
|---|---|---|
| **Bài 1** | Packet Capture & Parser | Live capture/PCAP, IPv4, TCP, UDP, HTTP/1.x, DNS, SMTP, timestamp và JSONL |
| **Bài 2** | Decoder, Preprocessor & Flow/Connection Tracker | Giải mã application, kiểm tra/chuẩn hóa event, flow hai chiều, TCP state, timeout và thống kê |
| **Bài 3** | Core Engine & Snort Rule Matching | Loader, Parser/Validator, Repository/Indexer, Matcher, Evaluator và Detection Event |

Hai chế độ live capture và đọc PCAP sử dụng chung pipeline:

```text
Capture / PCAP → Parser → Decoder → Preprocessor → Flow Tracker → Core Engine
                                                      │               │
                                                Flow JSONL      Detection JSONL
                                                                      │
                                                            Event JSONL + terminal

.rules → Loader → Parser/Validator → Repository/Indexer
                                          ↓
                      Normalized Event + Flow Context → Evaluator → Matcher
```

- Detector kết hợp payload và port, hỗ trợ một số giao thức trên port không chuẩn.
- Decoder giữ dữ liệu gốc, bổ sung kết quả decode và trạng thái lỗi.
- Preprocessor giữ bản chuẩn hóa riêng trong `normalized`, kèm status và action.
- Tracker gắn flow_id/direction, client/server và nguồn suy luận established, đếm packet/byte/flags và xuất flow khi đóng, hết hạn hoặc kết thúc capture.
- Core Engine nạp rule một lần, lọc candidates theo header, kiểm tra flow/flags/dsize/content và cho phép nhiều rule cùng match một event. Event có evaluation status/diagnostics; detection giữ SID và vị trí content match.

## Cấu trúc repository

```text
main.py                         CLI và điều phối pipeline
requirements.txt                Dependencies
src/
├── capture/                    Live capture và đọc PCAP
├── parser/                     Parser network/transport/application và detector
├── decoder/                    URL/form, HTML entity, MIME Base64/QP, charset
├── preprocessor/               Validation, normalization, policy keep/drop
├── flow/                       Flow hai chiều, TCP state, timeout, counters
├── engine/                     Context, rule loader/parser/indexer, matcher/evaluator/detection
└── logging/                    JSONL writer
TEST/
├── README.md                   Chỉ mục kiểm thử
├── BT1/
│   ├── test_*.py               Test bài 1
│   ├── README.md               Bảng đối chiếu testcase bài 1
│   └── result/                 Báo cáo pytest TXT/XML
├── BT2/
│   ├── test_*.py               Test bài 2
│   ├── README.md               Bảng đối chiếu T01–T14
│   └── result/                 Báo cáo pytest TXT/XML
├── BT3/                        Script, bảng 14 testcase và result/ của bài 3
└── legacy-results/             Báo cáo cũ, không phải kết quả mới nhất
rules/
└── local.rules                 Signature demo, mặc định được nạp khi chạy
pcap/
└── test-traffic.pcap            File mẫu đã capture để kiểm tra offline
output/                         Event/flow/detection JSONL sinh khi chạy, không commit
```

Tài liệu chi tiết: [Decoder](src/decoder/README.md), [Preprocessor](src/preprocessor/README.md), [Flow Tracker](src/flow/README.md), [Core Engine](src/engine/README.md), [Rule mẫu](rules/README.md).

## 1. Dựng môi trường

Chạy các lệnh từ thư mục gốc repo trên Linux. Cần Python và module venv; môi trường phát triển đã dùng Python 3.14.

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Các ví dụ bên dưới dùng `.venv/bin/python` trực tiếp để bảo đảm dùng đúng môi trường, kể cả khi chạy với `sudo`. Phân tích PCAP và test tự động thường không cần sudo; live capture cần quyền bắt packet.

Xem hướng dẫn CLI:

```bash
.venv/bin/python main.py --help
```

## 2. Các cờ và tham số cần lưu ý

| Cờ | Giá trị truyền vào | Ý nghĩa / mặc định |
|---|---|---|
| `-h`, `--help` | Không có | Hiển thị hướng dẫn rồi thoát |
| `--interface` | Tên interface, ví dụ `wlp8s0` | Bắt traffic realtime |
| `--pcap` | Đường dẫn file | Đọc PCAP đã capture; ví dụ mẫu: `pcap/test-traffic.pcap` |
| `--output` | Đường dẫn `.jsonl` | Event log; mặc định tạo tên theo thời gian trong `output/` |
| `--flow-output` | Đường dẫn `.jsonl` | Tổng kết flow; mặc định cùng thư mục và mốc tên với event log, tiền tố `flows_` |
| `--tcp-timeout` | Số giây dương, hữu hạn | Idle timeout TCP; mặc định `120` |
| `--udp-timeout` | Số giây dương, hữu hạn | Idle timeout UDP; mặc định `30` |
| `--max-flows` | Số nguyên dương | Tối đa active flows; mặc định `10000` |
| `--rules` | File `.rules`, có thể lặp | Mặc định `rules/local.rules`; khi chỉ định thì thay danh sách mặc định |
| `--disable-rule-file` | Đường dẫn, có thể lặp | Tắt file tương ứng trong danh sách nạp |
| `--disable-sid` | SID dương, có thể lặp | Tắt rule; ưu tiên hơn enable |
| `--enable-sid` | SID dương, có thể lặp | Chỉ cho phép các SID được chỉ định; không truyền thì không giới hạn |
| `--detection-output` | Đường dẫn `.jsonl` | File detection; mặc định cùng mốc tên event, tiền tố `detections_` |
| `--allow-inferred-established` | Không có giá trị | Cho phép established suy luận khi bắt giữa phiên; mặc định cần handshake đã quan sát |

- Bắt buộc chọn **đúng một** trong `--interface` và `--pcap`; không truyền cả hai.
- `pcap/test-traffic.pcap` là file mẫu dùng trong hướng dẫn, **không phải giá trị CLI tự chọn** khi bỏ `--pcap`.
- Timeout là thời gian flow không có packet mới, không phải thời gian tự dừng capture. Khi hết hạn, flow được xuất và xóa khỏi active table.
- Khi đầy active table, chương trình xuất flow có last_seen cũ nhất để tạo chỗ cho flow mới.
- Ba đường dẫn output phải khác nhau và không trùng đường dẫn PCAP/rule đầu vào. File chỉ định đã tồn tại sẽ được ghi nối tiếp; muốn tách từng lần chạy thì bỏ các cờ output để dùng tên theo thời gian.
- Decoder có giới hạn API `max_field_bytes`; Preprocessor có API `invalid_policy`/`unsupported_policy`. Các tham số này chưa có cờ CLI riêng.

## 3. Kiểm tra với traffic realtime

### Chọn interface

```bash
ip link show
```

Chọn interface đang có traffic cần quan sát. Ví dụ Wi-Fi trên máy phát triển là `wlp8s0`; traffic giữa các chương trình trên cùng máy có thể đi qua `lo`.

### Chạy capture

Mặc định engine nạp `rules/local.rules`. Đây là rule demo nhận diện GET/EHLO và chuỗi `../`; match không tự chứng minh một cuộc tấn công.

```bash
sudo .venv/bin/python main.py --interface wlp8s0
```

Hoặc chỉ định cấu hình flow:

```bash
sudo .venv/bin/python main.py --interface wlp8s0 \
  --tcp-timeout 120 --udp-timeout 30 --max-flows 10000
```

Chạy khoảng **60 giây** bằng GNU `timeout`:

```bash
sudo timeout --signal=INT --kill-after=10s 60s \
  .venv/bin/python main.py --interface wlp8s0 --rules rules/local.rules
```

Sau 60 giây, SIGINT yêu cầu dừng sạch, xuất các flow còn lại và in `Engine statistics:`. Nếu vẫn kẹt thêm 10 giây, timeout cưỡng bức kết thúc; khi đó không bảo đảm xuất hết active flows. Mã thoát 124 của timeout khi hết thời gian là bình thường. Code đã bật `chainCC=True` để Scapy truyền Ctrl+C lên vòng điều phối thay vì bắt lại rồi tiếp tục sniff.

Trong lúc chương trình chạy, tạo traffic từ ứng dụng hoặc máy chủ thử nghiệm: DNS query, HTTP plaintext, SMTP plaintext. HTTPS/TLS không được giải mã nên application có thể là UNKNOWN; điều đó không đồng nghĩa capture bị lỗi.

Theo dõi ngay trên terminal:

- Event có địa chỉ IP, port và timestamp của packet.
- HTTP/DNS/SMTP được nhận diện khi payload phù hợp và đủ dữ liệu.
- `decoded`, `decode_status` thể hiện kết quả decoder.
- `normalized`, `preprocess_status` thể hiện kết quả preprocessor.
- `flow` chứa flow_id, direction và state nếu packet đủ điều kiện tracking.
- `evaluation` chứa trạng thái, số candidate/evaluated rule, số detection và diagnostics. CLI in `[DETECTION]` khi có match, cảnh báo rule lỗi khi nạp và thống kê engine cuối phiên.

Chương trình đồng thời ghi file trong `output/`, hiển thị đường dẫn lúc khởi động. Nhấn **Ctrl+C** để dừng; các flow còn lại được xuất trước khi đóng file. Flow log có thể trống lúc đầu vì flow chưa đóng hoặc chưa timeout.

Live mode hiện ghi **event/flow/detection JSONL**, không tự lưu raw packet thành PCAP. Nếu cần lưu thêm PCAP cho lần chạy sau, dùng công cụ capture riêng như Wireshark hoặc tcpdump. File mẫu bên dưới đã được capture sẵn, không cần bước tự sinh dữ liệu.

## 4. Phân tích file PCAP đã capture

File mẫu đặt tại **`pcap/test-traffic.pcap`**. Chạy từ thư mục gốc repo:

```bash
.venv/bin/python main.py --pcap pcap/test-traffic.pcap
```

Chương trình chạy cùng pipeline như realtime, đọc đến hết file rồi xuất các flow còn lại. Timestamp event lấy từ PCAP; timeout flow dựa trên thời gian packet, không dựa tốc độ đọc file.

Để chỉ định rõ tên file kết quả:

```bash
.venv/bin/python main.py --pcap pcap/test-traffic.pcap \
  --output output/events_test-traffic.jsonl \
  --flow-output output/flows_test-traffic.jsonl \
  --detection-output output/detections_test-traffic.jsonl \
  --rules rules/local.rules \
  --tcp-timeout 120 \
  --udp-timeout 30 \
  --max-flows 10000
```

Kiểm tra kết quả bằng cách mở ba file JSONL trong editor. Không so sánh flow_id giữa live/offline vì ID được tạo mới mỗi lần chạy; đối chiếu endpoint, protocol, direction, counters và nội dung giải mã. Kết quả phụ thuộc traffic thực sự có trong PCAP; không mặc định file có đủ tất cả giao thức/testcase.

Nếu clone repo mà thiếu file mẫu, đặt bản capture vào đúng đường dẫn trên; `*.pcap` đang được bỏ qua bởi `.gitignore`.

## Đọc kết quả output

Mặc định một lần chạy tạo ba file:

```text
output/events_HH-MM-SS-microseconds_DD-MM-YYYY.jsonl
output/flows_HH-MM-SS-microseconds_DD-MM-YYYY.jsonl
output/detections_HH-MM-SS-microseconds_DD-MM-YYYY.jsonl
```

**Event JSONL:** mỗi dòng là một event, gồm dữ liệu parser, timestamp, packet_id, decoded, normalized, các trạng thái xử lý và liên kết flow. Event không đủ điều kiện tracking có `flow: null` và `track_reason`.

**Flow JSONL:** mỗi dòng là bản tổng kết flow được xuất, gồm endpoint A/B, protocol, thời gian, packet/byte counters, TCP flag counters, state và close_reason. File có thể chưa có dòng khi mọi flow vẫn hoạt động; chúng sẽ được xuất khi đóng, timeout, chạm giới hạn hoặc dừng chương trình.

**Detection JSONL:** mỗi dòng là một rule match, có timestamp, packet_id, SID/rev/msg, priority/classtype, 5-tuple, application protocol, flow_id và match_info. Dùng packet_id để nối với event trong cùng phiên và flow_id để nối với flow summary. File rỗng khi không có match là bình thường.

Rule lỗi/unsupported được báo rồi bỏ qua; không có rule active thì cảnh báo và vẫn capture. Matching bị giới hạn/thiếu buffer có thể cho evaluation `partial`, không được coi là bằng chứng traffic an toàn.

Quy ước:

- Timestamp event lấy từ `packet.time`, biểu diễn UTC; tên file dùng giờ địa phương.
- `packet_id` bắt đầu từ 1 mỗi lần chạy.
- `flow_id` ổn định trong vòng đời flow, không giống nhau giữa các lần replay.
- Endpoint A là nguồn packet đầu tiên quan sát được, không mặc định là client.
- Byte count dùng IPv4 total length, không phải riêng application payload.
- Chỉ định lại file đã tồn tại sẽ **ghi nối tiếp**, không xóa nội dung cũ.

## Kiểm thử và đối chiếu đề bài

| Bài | Xem script | Bảng testcase, cơ chế kiểm chứng và PASS/FAIL | Kết quả đã lưu |
|---|---|---|---|
| Bài 1 | [TEST/BT1](TEST/BT1) | [Báo cáo bài 1](TEST/BT1/README.md) | 54 PASS |
| Bài 2 | [TEST/BT2](TEST/BT2) | [Báo cáo bài 2 — T01–T14](TEST/BT2/README.md) | 44 PASS |
| Bài 3 | [TEST/BT3](TEST/BT3) | [Báo cáo bài 3 — 14 testcase](TEST/BT3/README.md) | 88 PASS |

Các con số trên là kết quả lần chạy được lưu trong repo, không tự cập nhật khi sửa code. Theo [lần kiểm tra cuối](TEST/BT3/result/final_audit.txt), tổng cộng **186 test instances**, bao gồm các biến thể parametrize; số này không phải số testcase trong đề.

Chạy từng bài hoặc toàn bộ:

```bash
.venv/bin/python -B -m pytest -v TEST/BT1
.venv/bin/python -B -m pytest -v TEST/BT2
.venv/bin/python -B -m pytest -v TEST/BT3
.venv/bin/python -B -m pytest -v TEST/BT1 TEST/BT2 TEST/BT3
```

Tạo lại bằng chứng chạy cho từng bài:

```bash
mkdir -p TEST/BT1/result TEST/BT2/result TEST/BT3/result
.venv/bin/python -B -m pytest -v TEST/BT1 \
  --junitxml=TEST/BT1/result/pytest.xml > TEST/BT1/result/pytest.txt 2>&1
.venv/bin/python -B -m pytest -v TEST/BT2 \
  --junitxml=TEST/BT2/result/pytest.xml > TEST/BT2/result/pytest.txt 2>&1
.venv/bin/python -B -m pytest -v TEST/BT3 \
  --junitxml=TEST/BT3/result/pytest.xml > TEST/BT3/result/pytest.txt 2>&1
```

- `result/pytest.txt`: báo cáo để đọc trực tiếp.
- `result/pytest.xml`: JUnit XML cho công cụ báo cáo/CI; không cần chạy hay import vào IDS.
- `README.md` của từng bài: bảng đối chiếu yêu cầu; cần cập nhật thủ công khi kết quả/phạm vi test thay đổi.

Test live capture sử dụng giả lập; PCAP pipeline có test đọc file thực được tạo trong thư mục tạm. PASS chỉ chứng minh các đầu vào và assert đã kiểm thử. Test bài 1 hiện chạy trên pipeline tích hợp mới nhất, không phải snapshot code lịch sử bài 1.

### Kiểm chứng live đã thực hiện

Phiên `20-58-02-052410_02-11-2026` ghi 10.103 event, 1 detection SID 100001 (HTTP GET) với packet/flow liên kết đúng. Có 3 event transport chưa hỗ trợ được báo lý do. Phiên này bị dừng cưỡng bức: 147 flow đã xuất, 23 flow xuất hiện trong event chưa có summary. Vì vậy đây là bằng chứng matching live, **chưa phải bằng chứng dừng sạch sau bản sửa Ctrl+C**. Bản sửa đã có test hồi quy tự động; chưa chạy lại live để xác nhận. Log runtime trong output/ không nằm trong Git.

## Giới hạn hiện tại

- Chưa tái lắp TCP stream hoặc ghép SMTP DATA nhiều packet; chưa xử lý multipart MIME.
- Không giải mã HTTPS/TLS, HTTP compression hoặc chunked body; charset decoder hỗ trợ ASCII/UTF-8.
- TCP tracking là mô hình logic, chưa thực hiện đầy đủ TCP state machine/sequence validation; retransmission vẫn được đếm.
- Live capture chạy theo các lượt sniff ngắn để kiểm tra timeout, có thể có khoảng hở khi mở lại socket.
- File PCAP hỏng không đọc tiếp được sẽ báo lỗi và dừng có kiểm soát; một số trường hợp cắt file có thể bị Scapy xem là EOF.
- Chưa có Feature Extractor hoặc cơ chế ngăn chặn; bộ rule hiện tại chỉ là demo, không phải bộ rule Snort chính thức.
- Rule mỗi dòng một rule; chỉ hỗ trợ subset đã công bố, chưa pcre, multiline, variables/lists/negation hoặc toàn bộ Snort.
- Rule protocol ip/any là nhóm chung cho event IPv4 TCP/UDP hiện có; any protocol là mở rộng của project. Chưa hỗ trợ mọi IP protocol.
- Content tìm theo từng packet, nocase theo ASCII, có giới hạn buffer/search; buffer decoded chọn qua API, chưa có keyword sticky-buffer Snort.

## Sử dụng AI

**Công cụ:** OpenAI Codex. **Mục đích:** hỗ trợ triển khai, rà soát, kiểm thử và viết tài liệu.

Các phần có AI hỗ trợ gồm application detector và parser HTTP/DNS/SMTP, bảo toàn raw/MIME, tích hợp pipeline, JSONL writer và timestamp, xử lý lỗi, Decoder, Preprocessor, Flow Tracker, Core Engine (context, rule loader/parser/validator/indexer, matching, evaluation, detection), script/báo cáo kiểm thử và README. Người thực hiện cần kiểm tra, hiểu và giải thích được mã nguồn đã nộp.
