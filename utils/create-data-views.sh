#!/bin/bash
set -e

# Danh sách nguồn đang bật (khớp với pipeline.id trong config/logstash/pipelines.yml).
# Thêm tên nguồn mới vào đây khi bạn thêm pipeline mới.
SOURCES=("nginx" "linux-auth" "linux-auditd")

KIBANA_URL="https://localhost:${KIBANA_PORT}"
CA_CERT="./config/certs/ca/ca.crt"

echo "=========================================="
echo "[DATA-VIEWS] Tạo Kibana Data View tự động"
echo "=========================================="

create_data_view() {
  local TITLE="$1"
  local NAME="$2"

  echo "[DATA-VIEWS] Tạo data view: ${NAME} (${TITLE})"

  RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
    -k -u "elastic:${ELASTIC_PASSWORD}" \
    -H "Content-Type: application/json" \
    -H "kbn-xsrf: true" \
    "${KIBANA_URL}/api/data_views/data_view" \
    -d "{\"data_view\":{\"title\":\"${TITLE}\",\"name\":\"${NAME}\",\"timeFieldName\":\"@timestamp\"}}")

  HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
  if [ "$HTTP_CODE" == "200" ]; then
    echo "[DATA-VIEWS]   OK"
  elif echo "$RESPONSE" | grep -q "Duplicate"; then
    echo "[DATA-VIEWS]   Đã tồn tại, bỏ qua"
  else
    echo "[DATA-VIEWS]   Thất bại (HTTP $HTTP_CODE) — kiểm tra thủ công sau: $RESPONSE"
  fi
}

for SRC in "${SOURCES[@]}"; do
  create_data_view "logs-${SRC}-default*" "${SRC} logs"
done

# Data view riêng cho index alert do rule-engine sinh ra (không theo quy ước
# logs-<source>-default vì đây không phải log thô mà là kết quả phát hiện).
create_data_view "siem-alerts-default*" "SIEM alerts"

echo "[DATA-VIEWS] Hoàn tất."