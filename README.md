# NT204 — Hệ thống IDS: Capture, Parser và Flow Tracker

- **Sinh viên:** Nguyễn Minh Phúc Khang
- **MSSV:** 24520758
- **Lớp:** NT204.R11.ANTN

Repository chứa các bài tập phát triển từng phần của hệ thống IDS bằng Python. Hiện hỗ trợ thu thập packet, phân tích giao thức, giải mã nội dung, chuẩn hóa event và theo dõi flow hai chiều. Chưa triển khai Feature Extractor hoặc Detection Engine để kết luận tấn công.

## Tổng quan chức năng

| Bài | Nội dung | Thành phần |
|---|---|---|
| **Bài 1** | Packet Capture & Parser | Live capture/PCAP, IPv4, TCP, UDP, HTTP/1.x, DNS, SMTP, timestamp và JSONL |
| **Bài 2** | Decoder, Preprocessor & Flow/Connection Tracker | Giải mã application, kiểm tra/chuẩn hóa event, flow hai chiều, TCP state, timeout và thống kê |

Hai chế độ live capture và đọc PCAP sử dụng chung pipeline:

```text
Capture / PCAP → Parser → Decoder → Preprocessor → Flow Tracker
                                                       │
                                     ┌─────────────────┴────────────────┐
                                     ▼                                  ▼
                            Event JSONL + terminal                Flow summary JSONL
```

- Detector kết hợp payload và port, hỗ trợ một số giao thức trên port không chuẩn.
- Decoder giữ dữ liệu gốc, bổ sung kết quả decode và trạng thái lỗi.
- Preprocessor giữ bản chuẩn hóa riêng trong `normalized`, kèm status và action.
- Tracker gắn flow_id/direction, đếm packet/byte/flags và xuất flow khi đóng, hết hạn hoặc kết thúc capture.

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
└── logging/                    JSONL writer
TEST/
├── README.md                   Chỉ mục kiểm thử
├── TEST-01/
│   ├── test_*.py               Test bài 1
│   ├── README.md               Bảng đối chiếu testcase bài 1
│   └── result/                 Báo cáo pytest TXT/XML
├── TEST-02/
│   ├── test_*.py               Test bài 2
│   ├── README.md               Bảng đối chiếu T01–T14
│   └── result/                 Báo cáo pytest TXT/XML
└── legacy-results/             Báo cáo cũ, không phải kết quả mới nhất
output/                         Event/flow JSONL sinh khi chạy, không commit
```

Tài liệu chi tiết: [Decoder](src/decoder/README.md), [Preprocessor](src/preprocessor/README.md), [Flow Tracker](src/flow/README.md).

## Cài đặt

Các lệnh dưới đây chạy từ thư mục gốc repo trên Linux. Môi trường phát triển đã dùng Python 3.14.

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```

## Usage

### Live capture

Xem danh sách interface:

```bash
ip link show
```

Thay `wlp8s0` bằng interface thực tế trên máy:

```bash
sudo .venv/bin/python main.py --interface wlp8s0
```

Chương trình vừa in event ra terminal vừa ghi JSONL. Nhấn **Ctrl+C** để dừng và xuất các flow còn lại. Timeout là thời gian flow không có packet mới, **không phải thời gian tự dừng chương trình**.

### Đọc PCAP

```bash
.venv/bin/python main.py --pcap /path/to/capture.pcap
```

Chương trình xử lý đến hết file rồi xuất flow còn lại. Cần cung cấp file PCAP có sẵn; `*.pcap` đang được bỏ qua trong `.gitignore`.

### Chọn file output và cấu hình flow

```bash
.venv/bin/python main.py --pcap /path/to/capture.pcap \
  --output output/events_demo.jsonl \
  --flow-output output/flows_demo.jsonl \
  --tcp-timeout 120 \
  --udp-timeout 30 \
  --max-flows 10000
```

| Tham số | Ý nghĩa | Mặc định |
|---|---|---|
| `--interface` | Interface để bắt packet | Chọn một trong interface/pcap |
| `--pcap` | File PCAP đầu vào | Chọn một trong interface/pcap |
| `--output` | File event JSONL | File mới theo thời gian trong output/ |
| `--flow-output` | File tổng kết flow | Cùng thư mục với event, tên có tiền tố flows_ |
| `--tcp-timeout` | Idle timeout TCP, giây | 120 |
| `--udp-timeout` | Idle timeout UDP, giây | 30 |
| `--max-flows` | Số flow hoạt động tối đa | 10000 |

Hai đường dẫn output phải khác nhau. Decoder có giới hạn qua API `max_field_bytes`; Preprocessor có policy qua API `invalid_policy`/`unsupported_policy`. Các tùy chọn API này chưa có CLI riêng.

## Đọc kết quả output

Mặc định một lần chạy tạo cặp file:

```text
output/events_HH-MM-SS-microseconds_DD-MM-YYYY.jsonl
output/flows_HH-MM-SS-microseconds_DD-MM-YYYY.jsonl
```

**Event JSONL:** mỗi dòng là một event, gồm dữ liệu parser, timestamp, packet_id, decoded, normalized, các trạng thái xử lý và liên kết flow. Event không đủ điều kiện tracking có `flow: null` và `track_reason`.

**Flow JSONL:** mỗi dòng là bản tổng kết flow được xuất, gồm endpoint A/B, protocol, thời gian, packet/byte counters, TCP flag counters, state và close_reason. File có thể chưa có dòng khi mọi flow vẫn hoạt động; chúng sẽ được xuất khi đóng, timeout, chạm giới hạn hoặc dừng chương trình.

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
| Bài 1 | [TEST/TEST-01](TEST/TEST-01) | [Báo cáo bài 1](TEST/TEST-01/README.md) | 53 PASS |
| Bài 2 | [TEST/TEST-02](TEST/TEST-02) | [Báo cáo bài 2 — T01–T14](TEST/TEST-02/README.md) | 44 PASS |

Các con số trên là kết quả lần chạy được lưu trong repo, không tự cập nhật khi sửa code. Tổng cộng **97 test instances**, bao gồm các biến thể parametrize; số này không phải số testcase trong đề.

Chạy từng bài hoặc toàn bộ:

```bash
.venv/bin/python -B -m pytest -v TEST/TEST-01
.venv/bin/python -B -m pytest -v TEST/TEST-02
.venv/bin/python -B -m pytest -v TEST/TEST-01 TEST/TEST-02
```

Tạo lại bằng chứng chạy cho từng bài:

```bash
mkdir -p TEST/TEST-01/result TEST/TEST-02/result
.venv/bin/python -B -m pytest -v TEST/TEST-01 \
  --junitxml=TEST/TEST-01/result/pytest.xml > TEST/TEST-01/result/pytest.txt 2>&1
.venv/bin/python -B -m pytest -v TEST/TEST-02 \
  --junitxml=TEST/TEST-02/result/pytest.xml > TEST/TEST-02/result/pytest.txt 2>&1
```

- `result/pytest.txt`: báo cáo để đọc trực tiếp.
- `result/pytest.xml`: JUnit XML cho công cụ báo cáo/CI; không cần chạy hay import vào IDS.
- `README.md` của từng bài: bảng đối chiếu yêu cầu; cần cập nhật thủ công khi kết quả/phạm vi test thay đổi.

Test live capture sử dụng giả lập; PCAP pipeline có test đọc file thực được tạo trong thư mục tạm. PASS chỉ chứng minh các đầu vào và assert đã kiểm thử. Test bài 1 hiện chạy trên pipeline tích hợp mới nhất, không phải snapshot code lịch sử bài 1.

## Giới hạn hiện tại

- Chưa tái lắp TCP stream hoặc ghép SMTP DATA nhiều packet; chưa xử lý multipart MIME.
- Không giải mã HTTPS/TLS, HTTP compression hoặc chunked body; charset decoder hỗ trợ ASCII/UTF-8.
- TCP tracking là mô hình logic, chưa thực hiện đầy đủ TCP state machine/sequence validation; retransmission vẫn được đếm.
- Live capture chạy theo các lượt sniff ngắn để kiểm tra timeout, có thể có khoảng hở khi mở lại socket.
- File PCAP hỏng không đọc tiếp được sẽ báo lỗi và dừng có kiểm soát; một số trường hợp cắt file có thể bị Scapy xem là EOF.
- Chưa có Feature Extractor, luật phát hiện tấn công hoặc cơ chế ngăn chặn.

## Sử dụng AI

**Công cụ:** OpenAI Codex. **Mục đích:** hỗ trợ triển khai, rà soát, kiểm thử và viết tài liệu.

Các phần có AI hỗ trợ gồm application detector và parser HTTP/DNS/SMTP, bảo toàn raw/MIME, tích hợp pipeline, JSONL writer và timestamp, xử lý lỗi, Decoder, Preprocessor, Flow Tracker, script/báo cáo kiểm thử và README. Người thực hiện cần kiểm tra, hiểu và giải thích được mã nguồn đã nộp.
