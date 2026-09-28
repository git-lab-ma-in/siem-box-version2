#!/usr/bin/env bash
# =========================================================
# install.sh — Cài Filebeat + rule auditd TRỰC TIẾP trên máy chủ web
#              (KHÔNG chạy trong Docker, KHÔNG chạy trên máy SIEM box).
# Chạy trên chính máy/VM đóng vai trò "Linux Web Server" cần giám sát:
#   cd web-server-agent
#   sudo bash install.sh
# Yêu cầu: Ubuntu/Debian (dùng apt). Máy này PHẢI có kết nối mạng TCP tới
# cổng Kafka EXTERNAL đã publish trên máy SIEM box.
# =========================================================
set -euo pipefail
cd "$(dirname "$0")"

if [ "$(id -u)" -ne 0 ]; then
  echo "Cần chạy với quyền root (sudo bash install.sh)."
  exit 1
fi

echo "== 1. Chuẩn bị file .env =="
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Đã tạo .env từ .env.example."
fi
# shellcheck disable=SC1091
source .env

if [ -z "${SIEM_EXTERNAL_HOST:-}" ] || [ "${SIEM_EXTERNAL_HOST}" == "CHANGE_ME" ]; then
  echo ""
  echo "CẦN ĐIỀN SIEM_EXTERNAL_HOST trong web-server-agent/.env trước khi tiếp tục."
  echo "Đây là IP thật của máy SIEM box (giá trị PHẢI trùng với SIEM_EXTERNAL_HOST"
  echo "trong siem-box/.env đang chạy trên máy kia)."
  exit 1
fi
KAFKA_EXTERNAL_PORT="${KAFKA_EXTERNAL_PORT:-9094}"

echo "== 2. Kiểm tra kết nối mạng tới Kafka trên SIEM box (${SIEM_EXTERNAL_HOST}:${KAFKA_EXTERNAL_PORT}) =="
if command -v nc &>/dev/null; then
  if ! nc -z -w 5 "${SIEM_EXTERNAL_HOST}" "${KAFKA_EXTERNAL_PORT}"; then
    echo "CẢNH BÁO: không kết nối được tới ${SIEM_EXTERNAL_HOST}:${KAFKA_EXTERNAL_PORT} ngay bây giờ."
    echo "  Kiểm tra: SIEM box đã 'docker compose up -d' chưa, firewall/security group đã mở cổng"
    echo "  ${KAFKA_EXTERNAL_PORT}/tcp chưa, 2 máy có cùng mạng/route tới nhau không."
    read -p "Vẫn tiếp tục cài đặt? (y/N) " -n 1 -r REPLY
    echo
    [[ $REPLY =~ ^[Yy]$ ]] || exit 1
  else
    echo "OK — kết nối được."
  fi
else
  echo "Không có lệnh 'nc' để kiểm tra trước — bỏ qua bước này, cài đặt tiếp."
fi

echo "== 3. Cài đặt auditd =="
if ! command -v auditctl &>/dev/null; then
  apt-get update -qq
  apt-get install -y auditd audispd-plugins
else
  echo "auditd đã có sẵn, bỏ qua."
fi

echo "== 4. Cài rule auditd webshell_exec =="
install -m 640 -o root -g root audit-rules/siem-webshell.rules /etc/audit/rules.d/siem-webshell.rules
if command -v augenrules &>/dev/null; then
  augenrules --load
else
  service auditd restart
fi
systemctl enable --now auditd
echo "Rule đã nạp — kiểm tra: auditctl -l | grep webshell_exec"

echo "== 5. Cài đặt Filebeat (Elastic APT repo, nhánh 8.x) =="
if ! command -v filebeat &>/dev/null; then
  apt-get install -y gnupg apt-transport-https ca-certificates
  curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | gpg --dearmor -o /usr/share/keyrings/elastic.gpg
  echo "deb [signed-by=/usr/share/keyrings/elastic.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list
  apt-get update -qq
  apt-get install -y filebeat
else
  echo "Filebeat đã cài sẵn ($(filebeat version 2>/dev/null | head -1)), bỏ qua bước cài, chỉ cập nhật config."
fi

echo "== 6. Ghi cấu hình /etc/filebeat/filebeat.yml =="
if [ -f /etc/filebeat/filebeat.yml ] && [ ! -f /etc/filebeat/filebeat.yml.orig ]; then
  cp /etc/filebeat/filebeat.yml /etc/filebeat/filebeat.yml.orig
  echo "Đã sao lưu config gốc -> /etc/filebeat/filebeat.yml.orig"
fi
export SIEM_EXTERNAL_HOST KAFKA_EXTERNAL_PORT
if command -v envsubst &>/dev/null; then
  envsubst '${SIEM_EXTERNAL_HOST} ${KAFKA_EXTERNAL_PORT}' \
    < filebeat/filebeat.yml > /etc/filebeat/filebeat.yml
else
  apt-get install -y gettext-base
  envsubst '${SIEM_EXTERNAL_HOST} ${KAFKA_EXTERNAL_PORT}' \
    < filebeat/filebeat.yml > /etc/filebeat/filebeat.yml
fi
chmod 600 /etc/filebeat/filebeat.yml

echo "== 7. Test output Kafka của Filebeat =="
filebeat test output || echo "CẢNH BÁO: test output thất bại — xem log ở trên trước khi tiếp tục."
filebeat test config

echo "== 8. Khởi động Filebeat =="
systemctl enable --now filebeat
systemctl status filebeat --no-pager -l | head -10

cat <<EOF

=========================================================
Đã cài xong trên máy chủ web này.

  - Nginx access log : /var/log/nginx/access.log  -> topic logs-nginx-default
  - SSH/PAM auth log  : /var/log/auth.log hoặc /var/log/secure -> topic logs-linux-auth-default
  - auditd (webshell) : /var/log/audit/audit.log  -> topic logs-linux-auditd-default
  - Đích              : ${SIEM_EXTERNAL_HOST}:${KAFKA_EXTERNAL_PORT}  (Kafka, SIEM box)

Kiểm tra log Filebeat  : tail -f /var/log/filebeat/filebeat.log
Kiểm tra rule auditd    : auditctl -l | grep webshell_exec
Xem dữ liệu đã tới chưa : mở Kafka UI trên SIEM box (http://${SIEM_EXTERNAL_HOST}:<KAFKA_UI_PORT>)
                          hoặc Kibana > Discover, chọn data view tương ứng.

Nếu /var/log/nginx/access.log chưa tồn tại vì máy này chưa cài nginx thật —
đó là bình thường nếu ứng dụng web thật của bạn dùng path log khác: sửa lại
đường dẫn trong filebeat/filebeat.yml rồi chạy lại install.sh.
=========================================================
EOF
