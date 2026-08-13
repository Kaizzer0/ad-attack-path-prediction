# AD Stealthiest Attack Path

Ứng dụng Streamlit + Neo4j để phân tích và tìm đường tấn công "ẩn mình nhất" (ít khả năng bị phát hiện nhất) trong Active Directory, dựa trên dữ liệu thu thập bởi SharpHound và mô hình chi phí phát hiện tham chiếu MITRE ATT&CK.

Bản này đã được vá lỗi theo kết quả code review toàn bộ dự án. Danh sách lỗi đã vá nằm ở mục cuối README.

## Cấu trúc thư mục

- `main.py`, giao diện Streamlit, CRUD Neo4j, thuật toán Dijkstra, trực quan hóa đồ thị.
- `data_cleaner.py`, chuyển đổi dữ liệu SharpHound thô sang `nodes_clean.json` và `edges_clean.json`.
- `cost_builder.py`, tạo từ điển cost từ SQLite, cache bằng Streamlit.
- `graph_enricher.py`, gán thuộc tính `cost` cho từng cạnh dựa trên từ điển cost.
- `database.sql`, schema và dữ liệu gốc cho SQLite (`cost_matrix.db`).
- `docker-compose.yml`, `Dockerfile`, chạy Neo4j và Streamlit.
- `neo4j_conf/`, cấu hình Neo4j và APOC.
- `data/`, 6 file JSON mẫu xuất từ SharpHound, dùng để test nhanh.
- `shared_data/`, thư mục được mount vào Neo4j làm thư mục import (APOC đọc file từ đây).
- `graph.cypher`, script Cypher tham khảo, chạy tay trực tiếp trong Neo4j Browser.
- `requirements.txt`, ghim version các thư viện Python.

## Chạy nhanh với Docker Compose

```bash
docker compose up --build
```

Lần đầu chạy sẽ build image Streamlit từ Dockerfile (cài đúng version trong `requirements.txt`) và tải image Neo4j 5.26.0. Đợi khoảng 20 đến 40 giây để Neo4j khởi động xong trước khi kết nối.

Truy cập:
- Streamlit UI, http://localhost:8501
- Neo4j Browser, http://localhost:7474

Tài khoản mặc định Neo4j: user `neo4j`, password `password`. Đây là giá trị demo cho môi trường cục bộ, cần đổi mật khẩu trước khi triển khai ở môi trường khác.

## Quy trình sử dụng

1. Mở http://localhost:8501, bấm "Connect to Neo4j" ở sidebar, giữ giá trị mặc định, bấm Connect.
2. Bấm "Import Graph from JSON", tải lên tối đa 6 file JSON trong thư mục `data/` (hoặc dữ liệu SharpHound thật của bạn), bấm "Bắt đầu Import".
3. Sau khi import thành công, đồ thị hiện ra ở phần "Graph Visualization" phía dưới, màu sắc theo từng loại node.
4. Bấm "View Cost Dictionary" để xem bảng chi phí phát hiện của từng loại quyền.
5. Bấm "Find Shortest Path", nhập Node ID nguồn và đích (SID của đối tượng AD, xem trong tooltip khi click vào node), bấm "Find Path" để tìm đường tấn công ít bị phát hiện nhất.
6. Dùng "Manage Nodes" / "Manage Edges" để chỉnh sửa thủ công khi cần mô phỏng kịch bản.
7. "Reset Graph" nay yêu cầu gõ đúng chữ "CONFIRM" trước khi xóa, tránh mất dữ liệu do bấm nhầm.

## Các lỗi đã vá (tóm tắt)

Bản này đã sửa các lỗi được phát hiện trong buổi code review trước đó, gồm:

- Sai đường dẫn file khi import JSON vào Neo4j, khiến tính năng import không hoạt động.
- Thiếu bước gán cost cho cạnh, khiến Dijkstra không có trọng số hợp lệ.
- Sai tên trường `masks` / `filters` khi nạp dữ liệu, làm mất thông tin detection filter.
- Danh sách loại cạnh dùng cho Dijkstra bị hard code và thiếu, nay được sinh động từ SQLite.
- Lỗ hổng Cypher Injection qua các ô nhập Relationship Type và Attribute Name, nay đã được kiểm tra allowlist.
- Dữ liệu tên đối tượng AD chưa được escape trước khi đưa vào HTML trực quan hóa (XSS), nay đã escape.
- Lỗi cache kết nối Neo4j khiến đổi URI/user/password không có tác dụng, nay đã sửa.
- Bốn loại cạnh cấu trúc (MemberOf, Contains, GPLink, DCFor) thiếu trong bảng cost, nay đã bổ sung.
- Thiếu requirements.txt, nay đã ghim version và tách Dockerfile riêng.
- Reset Graph thiếu xác nhận, nay đã thêm bước nhập "CONFIRM".

## Lưu ý về hành vi thiết kế

Các ACE (quyền) có đối tượng đích là Domain sẽ được tự động gán (fan-out) cho toàn bộ các Domain Controller đã xác định trong dữ liệu, thay vì tạo node Domain riêng. Với môi trường nhiều Domain Controller, một quyền cấp Domain sẽ xuất hiện thành nhiều cạnh riêng biệt tới từng DC. Đây là thiết kế chủ đích của `data_cleaner.py`, không phải lỗi, nhưng cần lưu ý khi đọc số liệu thống kê số cạnh trong đồ thị.

## Môi trường

- Neo4j, đọc biến môi trường chuẩn của image chính thức (`NEO4J_AUTH`, v.v.).
- Streamlit, đọc `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD` để đặt giá trị kết nối mặc định, có thể đổi trực tiếp trên giao diện.

## Xử lý sự cố thường gặp

- Neo4j chưa sẵn sàng khi Streamlit vừa khởi động xong, thử bấm lại Connect sau vài giây.
- Cổng 7474/7687/8501 bị chiếm dụng, kiểm tra bằng `docker ps` hoặc đổi port mapping trong `docker-compose.yml`.
- Lỗi khi Import Graph, kiểm tra file JSON tải lên đúng định dạng xuất từ SharpHound (có trường `data` là mảng các object).
