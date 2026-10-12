# Flow / Connection Tracker — Bài tập 2

## Thành phần và API

`tracker.py` chứa `FlowTracker`, active-flow table, logic TCP, thống kê và xuất flow. `__init__.py` export class. Không cần Scapy: đầu vào là event dictionary có `normalized` do Preprocessor tạo.

```python
from src.flow import FlowTracker

tracker = FlowTracker(tcp_timeout=120, udp_timeout=30,
                      max_flows=10000, emit=print)
result = tracker.track(event)
closed = tracker.expire(now_epoch_seconds)
remaining = tracker.flush('end_of_input')
```

Khởi tạo tracker một lần cho cả phiên capture. `track` trả bản sao event kèm `track_status`, `track_reason`, `flow`. `flow` gồm flow_id, direction, state; event không track được có flow=null. `expire` và `flush` trả danh sách flow đã xuất, đồng thời gọi callback emit nếu có. Lỗi ghi output được truyền ra ngoài, không coi là lỗi packet để rồi âm thầm mất log.

## Định danh và direction

Khóa nội bộ gồm transport protocol và hai endpoint IP/port đã sắp xếp, vì vậy A→B và B→A dùng cùng khóa. Endpoint A là nguồn của packet đầu tiên quan sát được, không nhất thiết client. A→B là forward, chiều còn lại backward.

flow_id là UUID, giữ nguyên trong vòng đời flow. Cùng 5-tuple sau timeout/close tạo flow_id mới. UUID không tái lập giống nhau giữa các lần replay PCAP.

## TCP

- NEW → HANDSHAKE khi thấy SYN.
- SYN, SYN/ACK ngược chiều, ACK phía khởi tạo → ESTABLISHED.
- Bắt giữa phiên: ACK khi chưa thấy handshake được suy luận ESTABLISHED.
- FIN → CLOSING. Đóng khi thấy FIN hai chiều và ACK xác nhận FIN mỗi chiều; xét sequence/acknowledgment theo modulo 2^32.
- RST → RESET và xuất ngay.
- ACK không payload vẫn được đếm và cập nhật state.

Đây là trạng thái logic, chưa phải máy trạng thái TCP đầy đủ: không xác minh sequence handshake, không tái lắp payload, không loại retransmission, không xử lý TIME_WAIT. FIN cần seq/ack; thiếu thông tin thì chờ timeout. main.py bổ sung transport.payload_length từ packet để tính FIN sequence sau payload; input trực tiếp thiếu field này mặc định 0.

## Thống kê

Mỗi flow có protocol, application_protocol, endpoint_a/b; start_time, last_seen, duration; packet_count/byte_count và forward/backward counters; SYN_count, ACK_count, FIN_count, RST_count và state.

Byte count là tổng `normalized.network.length` (IPv4 total length gồm IP header), không phải kích thước Ethernet hoặc payload. Packet retransmission vẫn được đếm. Thiếu độ dài hợp lệ thì bỏ tracking thay vì tự đoán. Application protocol là giao thức hỗ trợ được nhận diện gần nhất, UNKNOWN không ghi đè giao thức đã biết.

UDP dùng state ACTIVE và flag counters bằng 0. start_time=min(timestamp), last_seen=max(timestamp), duration tính theo giây, không âm.

## Timeout, dung lượng và kết thúc

- TCP mặc định 120 giây, UDP 30 giây; idle >= timeout thì xuất và xóa khỏi active table.
- PCAP sử dụng watermark timestamp lớn nhất đã gặp. Packet quá cũ hơn watermark trừ timeout bị bỏ tracking; packet đảo thứ tự trong cửa sổ cập nhật min/max thời gian.
- Live capture kiểm tra timeout mỗi khoảng một giây kể cả khi không có packet.
- Tối đa 10000 active flows; đầy thì xuất flow có last_seen cũ nhất với close_reason=capacity_limit.
- EOF, Ctrl+C hoặc lỗi capture xuất các flow còn lại với lý do tương ứng. State TCP quan sát được giữ nguyên; close_reason phân biệt timeout/end-of-input với FIN/RST thực sự.

Không có luồng nền dùng chung table; callback packet và timeout chạy tuần tự. Phiên bản live hiện chạy sniff theo khoảng một giây, có thể có khoảng hở nhỏ khi mở lại capture socket; không bảo đảm capture không mất packet.

## CLI và output

```bash
sudo .venv/bin/python main.py --interface wlp8s0 --tcp-timeout 120 --udp-timeout 30 --max-flows 10000
.venv/bin/python main.py --pcap test.pcap --output output/events_demo.jsonl --flow-output output/flows_demo.jsonl
```

Mặc định file flow có cùng mốc thời gian với file event. Hai đường dẫn output phải khác nhau. Event JSONL chứa liên kết flow; flow JSONL chỉ ghi bản tổng kết khi flow được xuất. Không ghi lại toàn bộ snapshot mỗi packet. Output vẫn append nếu chỉ định file có sẵn.

## Test và giới hạn

`TEST/test_flow_tracker.py` bao phủ handshake (T07), hai chiều (T08), FIN/RST (T09), UDP (T10), concurrent flows (T11), timeout (T12), thống kê (T13), malformed (T14), capacity và tái sử dụng 5-tuple. Test pipeline PCAP kiểm tra event flow_id khớp flow output.

```bash
.venv/bin/python -B -m pytest -v TEST
```

Báo cáo: TEST/result/flow_regression.txt và .xml. Live capture được giả lập trong test, cần kiểm chứng thêm với traffic thực tế. Module không thay thế TCP reassembly hay SMTP DATA buffering.

OpenAI Codex hỗ trợ triển khai, tích hợp pipeline, test và README. Người nộp cần kiểm tra và hiểu mã nguồn.
