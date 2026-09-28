#!/bin/bash
set -e

echo "=========================================="
echo "[SETUP] Sinh chứng chỉ TLS tự động"
echo "=========================================="

if [ -z "${ELASTIC_PASSWORD}" ] || [ -z "${KIBANA_PASSWORD}" ]; then
  echo "[SETUP] LỖI: ELASTIC_PASSWORD/KIBANA_PASSWORD rỗng — chạy setup.sh ở host trước, đừng gọi docker compose up trực tiếp lần đầu."
  exit 1
fi

if [ -z "${SIEM_EXTERNAL_HOST}" ] || [ "${SIEM_EXTERNAL_HOST}" == "CHANGE_ME" ]; then
  echo "[SETUP] LỖI: SIEM_EXTERNAL_HOST chưa được điền trong .env (đang là CHANGE_ME hoặc rỗng)."
  echo "[SETUP] Điền IP thật của máy/VM chạy Docker vào .env rồi chạy lại."
  exit 1
fi

# Xác định SIEM_EXTERNAL_HOST là IP hay hostname, để thêm đúng loại SAN vào chứng chỉ
if [[ "${SIEM_EXTERNAL_HOST}" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
  EXTRA_SAN_LINE="      - ${SIEM_EXTERNAL_HOST}"
  EXTRA_SAN_KEY="ip"
else
  EXTRA_SAN_LINE="      - ${SIEM_EXTERNAL_HOST}"
  EXTRA_SAN_KEY="dns"
fi

# --------------------------------------------
# 1. Tạo CA (idempotent — bỏ qua nếu đã tồn tại)
# --------------------------------------------
if [ ! -f config/certs/ca.zip ]; then
  echo "[SETUP] Đang tạo CA..."
  bin/elasticsearch-certutil ca --silent --pem -out config/certs/ca.zip
  unzip -q config/certs/ca.zip -d config/certs
else
  echo "[SETUP] CA đã tồn tại, bỏ qua (chạy lại từ đầu: xoá volume 'certs' trước)."
fi

# --------------------------------------------
# 2. Tạo chứng chỉ cho es01 và kibana, SAN bao gồm SIEM_EXTERNAL_HOST
# --------------------------------------------
if [ ! -f config/certs/certs.zip ]; then
  echo "[SETUP] Đang tạo chứng chỉ cho es01, kibana (SAN thêm: ${SIEM_EXTERNAL_HOST})..."
  cat > config/certs/instances.yml <<EOF
instances:
  - name: es01
    dns:
      - es01
      - localhost
    ip:
      - 127.0.0.1
$( [ "$EXTRA_SAN_KEY" == "ip" ] && echo "      - ${SIEM_EXTERNAL_HOST}" || true )
  - name: kibana
    dns:
      - kibana
      - localhost
$( [ "$EXTRA_SAN_KEY" == "dns" ] && echo "      - ${SIEM_EXTERNAL_HOST}" || true )
    ip:
      - 127.0.0.1
$( [ "$EXTRA_SAN_KEY" == "ip" ] && echo "      - ${SIEM_EXTERNAL_HOST}" || true )
EOF

  bin/elasticsearch-certutil cert --silent --pem \
    -out config/certs/certs.zip \
    --in config/certs/instances.yml \
    --ca-cert config/certs/ca/ca.crt \
    --ca-key config/certs/ca/ca.key

  unzip -q config/certs/certs.zip -d config/certs
else
  echo "[SETUP] Chứng chỉ đã tồn tại, bỏ qua."
fi

# --------------------------------------------
# 3. Quyền file — càng chặt càng tốt (chỉ root/owner đọc được key)
# --------------------------------------------
echo "[SETUP] Chỉnh quyền truy cập chứng chỉ..."
chown -R root:root config/certs
find config/certs -type d -exec chmod 750 {} \;
find config/certs -type f -exec chmod 640 {} \;

echo "[SETUP] Chứng chỉ đã sẵn sàng — es01/kibana có thể khởi động ngay bây giờ."
echo "[SETUP] Đang chờ Elasticsearch lên để set mật khẩu kibana_system..."

# --------------------------------------------
# 4. Chờ ES rồi set mật khẩu kibana_system
#    (chạy sau bước 3 nên healthcheck của service 'setup' đã pass,
#     es01 được phép khởi động song song trong lúc đoạn này đang chờ)
# --------------------------------------------
until curl -s --cacert config/certs/ca/ca.crt https://es01:9200 2>/dev/null | grep -q "missing authentication credentials"; do
  sleep 5
done
echo "[SETUP] Elasticsearch đã sẵn sàng."

echo "[SETUP] Đang set mật khẩu cho user kibana_system..."
until curl -s -X POST \
  --cacert config/certs/ca/ca.crt \
  -u "elastic:${ELASTIC_PASSWORD}" \
  -H "Content-Type: application/json" \
  https://es01:9200/_security/user/kibana_system/_password \
  -d "{\"password\":\"${KIBANA_PASSWORD}\"}" | grep -q "^{}"; do
  sleep 5
done

echo "=========================================="
echo "[SETUP] Hoàn tất — TLS + mật khẩu đã được cấu hình tự động."
echo "=========================================="