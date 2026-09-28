#!/usr/bin/env bash
# =========================================================
# setup.sh — Điều phối toàn bộ: sinh secret, kiểm tra host,
#            dựng stack, tạo Kibana Data View.
# Chạy: bash setup.sh
# =========================================================
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1. Chuẩn bị file .env =="
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Đã tạo .env từ .env.example."
fi

# shellcheck disable=SC1091
source .env

if [ -z "${SIEM_EXTERNAL_HOST}" ] || [ "${SIEM_EXTERNAL_HOST}" == "CHANGE_ME" ]; then
  echo ""
  echo "CẦN ĐIỀN SIEM_EXTERNAL_HOST trong .env trước khi tiếp tục."
  echo "Đây là IP thật của máy/VM này trong mạng — nơi collector và trình duyệt ở máy khác sẽ kết nối vào."
  DETECTED_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "")
  if [ -n "$DETECTED_IP" ]; then
    echo "Gợi ý phát hiện được: ${DETECTED_IP}"
    read -p "Dùng địa chỉ này? (Y/n) " -n 1 -r REPLY
    echo
    if [[ ! $REPLY =~ ^[Nn]$ ]]; then
      sed -i "s/^SIEM_EXTERNAL_HOST=.*/SIEM_EXTERNAL_HOST=${DETECTED_IP}/" .env
      echo "Đã điền SIEM_EXTERNAL_HOST=${DETECTED_IP} vào .env."
    else
      echo "Hãy tự điền SIEM_EXTERNAL_HOST trong .env rồi chạy lại setup.sh."
      exit 1
    fi
  else
    echo "Không tự phát hiện được IP. Hãy tự điền SIEM_EXTERNAL_HOST trong .env rồi chạy lại."
    exit 1
  fi
  source .env
fi

echo "== 2. Tự sinh mật khẩu/khoá mã hoá nếu thiếu (không in ra terminal/log) =="
CHANGED=0
if [ -z "${ELASTIC_PASSWORD}" ]; then
  NEW_PW=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)
  sed -i "s/^ELASTIC_PASSWORD=.*/ELASTIC_PASSWORD=${NEW_PW}/" .env
  CHANGED=1
fi
if [ -z "${KIBANA_PASSWORD}" ]; then
  NEW_PW=$(openssl rand -base64 24 | tr -d '/+=' | cut -c1-20)
  sed -i "s/^KIBANA_PASSWORD=.*/KIBANA_PASSWORD=${NEW_PW}/" .env
  CHANGED=1
fi
if [ -z "${ENCRYPTION_KEY}" ]; then
  NEW_KEY=$(openssl rand -hex 32)
  sed -i "s/^ENCRYPTION_KEY=.*/ENCRYPTION_KEY=${NEW_KEY}/" .env
  CHANGED=1
fi
if [ "$CHANGED" == "1" ]; then
  echo "Đã tự sinh mật khẩu/khoá còn thiếu vào .env (chỉ lưu trong file, không in ra đây)."
fi
source .env

echo "== 3. Kiểm tra Docker =="
command -v docker &>/dev/null || { echo "Chưa cài Docker."; exit 1; }
docker compose version &>/dev/null || { echo "Chưa có Docker Compose plugin (v2)."; exit 1; }

echo "== 4. Kiểm tra vm.max_map_count (yêu cầu của Elasticsearch) =="
if [ "$(uname)" == "Linux" ]; then
  CURRENT=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
  if [ "$CURRENT" -lt 262144 ]; then
    echo "Đang set vm.max_map_count=262144 (cần sudo)..."
    sudo sysctl -w vm.max_map_count=262144
  fi
else
  echo "Không phải Linux thuần — Docker Desktop tự quản lý, bỏ qua."
fi

echo "== 5. Dựng stack (lần đầu chạy setup-certs mất 1-2 phút để sinh chứng chỉ) =="
docker compose up -d

echo "== 6. Chờ các service khỏe =="
for s in siem-es01 siem-kibana siem-logstash; do
  echo -n "Đang chờ $s..."
  for i in $(seq 1 60); do
    STATUS=$(docker inspect --format='{{.State.Health.Status}}' "$s" 2>/dev/null || echo "starting")
    [ "$STATUS" == "healthy" ] && { echo " OK"; break; }
    sleep 5; echo -n "."
    [ "$i" -eq 60 ] && echo " chưa khỏe sau 5 phút — kiểm tra: docker logs $s"
  done
done

echo "== 7. Tạo Kibana Data View =="
export ELASTIC_PASSWORD KIBANA_PORT
bash utils/create-data-views.sh || echo "Bỏ qua bước data view (có thể chạy lại sau: bash utils/create-data-views.sh)"

echo "== 8. Tạo dashboard 'SIEM Overview' (tuỳ chọn — xem README mục 8 về rủi ro) =="
bash utils/create-dashboard.sh || echo "Bỏ qua bước dashboard (có thể chạy lại sau: bash utils/create-dashboard.sh)"

CA_PATH="./config/certs/ca.crt"
docker cp siem-es01:/usr/share/elasticsearch/config/certs/ca/ca.crt "$CA_PATH" 2>/dev/null || true

cat <<EOF

=========================================================
Stack đã sẵn sàng.

  Kibana        : https://${SIEM_EXTERNAL_HOST}:${KIBANA_PORT}  (user: elastic)
  Elasticsearch : https://${SIEM_EXTERNAL_HOST}:${ES_PORT}
  Kafka UI      : http://${SIEM_EXTERNAL_HOST}:${KAFKA_UI_PORT}
  Kafka broker  : ${SIEM_EXTERNAL_HOST}:${KAFKA_EXTERNAL_PORT}  (dùng cho Filebeat ở máy chủ web, xem web-server-agent/)

  Mật khẩu 'elastic': xem trong file .env (ELASTIC_PASSWORD) — KHÔNG commit file này lên git.

  Bước tiếp theo: sang thư mục web-server-agent/ (trên MÁY CHỦ WEB, máy khác), điền
  SIEM_EXTERNAL_HOST=${SIEM_EXTERNAL_HOST} vào .env rồi chạy 'sudo bash install.sh'.

  Chứng chỉ CA đã export ra: ${CA_PATH}
  → Import file này vào trình duyệt/máy collector để tin cậy HTTPS, tránh cảnh báo self-signed
    khi demo trước hội đồng.

  Đổi SIEM_EXTERNAL_HOST sau này (đổi máy/mạng)? Chứng chỉ đã sinh sẽ KHÔNG còn khớp SAN.
  Phải: docker compose down -v (xoá cả volume certs) rồi chạy lại setup.sh từ đầu.

Reset về trạng thái sạch (giữ nguyên .env, xoá dữ liệu + chứng chỉ):
  docker compose down -v && bash setup.sh
=========================================================
EOF