# Rule mẫu

local.rules là các signature demo tương thích subset Snort của project, không phải bộ rule bảo vệ đầy đủ hay rule tải từ Snort. HTTP GET/EHLO chỉ là traffic bình thường; detection không tự chứng minh tấn công. Rule traversal cũng có thể false positive.

Mỗi dòng một rule, comment #. Parser hỗ trợ tcp/udp, IPv4/CIDR, any, port range, ->/<>, content và các option mô tả trong src/engine/README.md. Rule không hỗ trợ được báo và bỏ qua.
