FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY engine.py .

# /rules/sigma  : mount từ ../rules/sigma (đọc rule, xem docker-compose.yml)
# /certs        : mount CA cert để verify TLS tới es01
# /data         : lưu state.json (thời điểm poll gần nhất của từng rule)
VOLUME ["/data"]

CMD ["python", "engine.py"]
