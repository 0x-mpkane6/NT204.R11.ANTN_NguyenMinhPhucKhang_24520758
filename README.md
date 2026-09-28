# NT204.R11.ANTN_NguyenMinhPhucKhang_24520758

> Packet Capture & Parser cho IDS

- Họ tên: Nguyễn Minh Phúc Khang - 24520758
- Lớp: NT204.R11.ANTN

## Chức năng hiện tại

- Capture trực tiếp từ network interface hoặc đọc file PCAP.
- Hai chế độ sử dụng chung parsing pipeline.
- Parse IPv4, TCP, UDP, HTTP/1.x, DNS và SMTP.
- Nhận diện application protocol dựa trên payload kết hợp port.
- Xuất event gồm network, transport, application, timestamp và packet_id.
- In kết quả ra terminal và ghi file JSON Lines trong output/.
- Bỏ qua packet gặp lỗi parse; báo lỗi đọc PCAP hoặc ghi file.

## Cài đặt
```python
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
```
## Cách chạy 
### Chạy trên interface
```python
sudo .venv/bin/python main.py --interface <interface>
```
### Đọc pcap
```python
.venv/bin/python main.py --pcap test.pcap
```

### Chọn file output:
```python
.venv/bin/python main.py --pcap test.pcap --output output/demo.jsonl
```

## Output

Mặc định mỗi lần chạy tạo file:
`output/events_HH-MM-SS-microseconds_DD-MM-YYYY.jsonl`

- Mỗi dòng là một event JSON. 
- Timestamp của event lấy từ `packet.time` và biểu diễn theo **UTC**.
- Tên file sử dụng giờ địa phương.
- `packet_id` bắt đầu từ 1 mỗi lần chạy.
- Khi chỉ định --output, chương trình ghi nối tiếp vào file đó.

## Kiểm thử

Chạy toàn bộ test:
```python
.venv/bin/python -m pytest -v TEST
```

Báo cáo:
- TEST/result/pytest.txt: kết quả dành cho người đọc.
- TEST/result/pytest.xml: kết quả theo định dạng JUnit XML.

Kết quả lần chạy đã lưu: 53 tests passed.

Test bao gồm application parser, TCP/UDP, JSONL writer,
pipeline PCAP và xử lý lỗi.
Live capture được giả lập trong bộ test tự động.

## Sử dụng AI

Công cụ: `OpenAI Codex`.

Mục đích: hỗ trợ triển khai, rà soát code và xây dựng kiểm thử.

Các phần có AI hỗ trợ:
- Application detector.
- JSONL writer, timestamp và tích hợp CLI.
- Xử lý lỗi capture/parsing/logging.
- Các script kiểm thử trong TEST/.
- Soạn tài liệu README.