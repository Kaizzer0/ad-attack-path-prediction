# Vá bug: trước đây không có Dockerfile riêng, docker-compose.yml chạy "pip install"
# trực tiếp trong command mỗi lần container khởi động (không ghim version, không tận
# dụng được cache layer của Docker, khởi động chậm).
FROM python:3.11-slim

WORKDIR /app

# Copy riêng requirements.txt trước để tận dụng Docker layer cache: chỉ khi
# requirements.txt thay đổi thì bước cài đặt thư viện mới phải chạy lại.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "main.py", "--server.port=8501", "--server.address=0.0.0.0"]
