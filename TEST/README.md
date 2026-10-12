# Kiểm thử theo bài tập

| Bài | Script | Báo cáo đối chiếu testcase trong đề |
|---|---|---|
| Bài 1 — Capture & Parser | TEST-01/test_*.py | [Bảng kết quả bài 1](TEST-01/README.md) |
| Bài 2 — Decoder, Preprocessor, Flow Tracker | TEST-02/test_*.py | [Bảng kết quả bài 2](TEST-02/README.md) |

Mỗi thư mục có result/pytest.txt và result/pytest.xml làm bằng chứng chạy. README.md là báo cáo Markdown gồm yêu cầu, cách kiểm chứng, cơ chế hệ thống, hàm test và kết quả. legacy-results/ giữ nguyên các báo cáo cũ trước khi sắp xếp, không dùng làm kết quả mới nhất.

Chạy tất cả từ thư mục gốc repo:

```bash
.venv/bin/python -B -m pytest -v TEST/TEST-01 TEST/TEST-02
```

Các test raw/MIME phục vụ đầu vào decoder được xếp vào bài 2. Test PCAP bài 1 có thêm kiểm tra liên kết flow vì đang chạy trên pipeline tích hợp hiện tại.
