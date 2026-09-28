# web-server-agent — Agent cài trên máy chủ Web (máy RIÊNG, tách khỏi SIEM box)

Thư mục này **không phải** một phần của `docker-compose` trong `siem-box/`. Đây là những
gì cần copy sang và cài **trực tiếp** trên máy chủ web Linux mà bạn muốn giám sát — đúng
kiến trúc thật: **2 máy vật lý/VM riêng biệt**, nói chuyện với nhau qua mạng (Kafka),
không co-locate như bản demo trước.

```
Máy A: SIEM box (siem-box/)              Máy B: Web server (máy này)
┌─────────────────────────────┐          ┌─────────────────────────────┐
│ Kafka (cổng EXTERNAL 9094)   │◄── mạng ─┤ Filebeat                    │
│ Logstash → Elasticsearch     │          │  - nginx access.log         │
│ Kibana                       │          │  - auth.log / secure        │
│ rule-engine (Sigma → alert)  │          │  - audit.log (rule webshell)│
└─────────────────────────────┘          │ auditd (rule siem-webshell) │
                                          │ (Nginx/ứng dụng web thật)   │
                                          └─────────────────────────────┘
```

## 1. Điều kiện trước khi cài

- Máy này (Máy B) phải **kết nối mạng TCP được tới Máy A** ở đúng cổng Kafka EXTERNAL
  (`KAFKA_EXTERNAL_PORT`, mặc định `9094`). Nếu 2 máy ở 2 mạng khác nhau, mở firewall/
  security group tương ứng.
- SIEM box (Máy A) đã chạy `bash setup.sh` xong (Kafka, Elasticsearch, Kibana đã lên).
- Hệ điều hành: Ubuntu/Debian (script `install.sh` dùng `apt`). Nếu dùng RHEL/CentOS,
  đọc phần "Distro khác" bên dưới.

## 2. Cài đặt

```bash
# Trên Máy B (máy chủ web):
cp .env.example .env
# Sửa .env: điền SIEM_EXTERNAL_HOST = đúng IP của Máy A (giống hệt giá trị
# SIEM_EXTERNAL_HOST trong siem-box/.env), và KAFKA_EXTERNAL_PORT nếu bạn đã đổi.

sudo bash install.sh
```

`install.sh` sẽ:
1. Kiểm tra kết nối mạng tới Kafka trên Máy A.
2. Cài `auditd` (nếu chưa có) và nạp rule `audit-rules/siem-webshell.rules` — rule này
   ghi lại mọi `execve` chạy dưới quyền `www-data` (uid 33), dấu hiệu chính của web shell.
3. Cài Filebeat (nhánh 8.x, từ kho APT chính thức của Elastic) nếu chưa có.
4. Sinh `/etc/filebeat/filebeat.yml` từ `filebeat/filebeat.yml` (thay `${SIEM_EXTERNAL_HOST}`
   và `${KAFKA_EXTERNAL_PORT}` bằng giá trị thật trong `.env`).
5. Chạy `filebeat test output` để xác nhận kết nối Kafka thành công trước khi bật service.
6. Bật `filebeat` và `auditd` bằng `systemctl enable --now`.

## 3. Nếu máy này đã có ứng dụng web thật (không phải demo)

- Sửa đường dẫn log trong `filebeat/filebeat.yml` (mục `nginx-access`) trỏ đúng vào access
  log thật của bạn (Apache, hay nginx ở path khác) rồi chạy lại `sudo bash install.sh`.
- Nếu web server chạy dưới user khác `www-data` (uid 33) — ví dụ `nginx` (RHEL, thường
  uid 993) — sửa `euid=33` trong `audit-rules/siem-webshell.rules` thành uid thật (kiểm
  tra bằng `id -u <user>`), rồi chạy lại `install.sh`.

## 4. Demo kịch bản tấn công (xem thêm README của siem-box, mục "Demo kịch bản tấn công")

Chạy ngay trên Máy B này:

```bash
# SSH brute-force / dò tài khoản không tồn tại
for i in $(seq 1 6); do ssh khongtontai$i@localhost -p 22 || true; done

# Giả lập webshell — bất kỳ tiến trình nào chạy dưới www-data đều bị auditd bắt
sudo -u www-data bash -c "id"
```

Rồi kiểm tra alert bên Máy A (SIEM box):

```bash
curl -sk -u elastic:<mật khẩu trong siem-box/.env> \
  "https://<IP Máy A>:9200/siem-alerts-default/_search?pretty"
```

## 5. Distro khác (không dùng apt)

`install.sh` hiện chỉ hỗ trợ Ubuntu/Debian. Trên RHEL/CentOS/Alma:
- Thay bước cài `auditd`/`audispd-plugins` bằng `yum install -y audit`.
- Thêm kho Elastic RPM thay vì APT — xem hướng dẫn chính thức của Elastic cho Filebeat
  trên RPM-based distro (kho `https://artifacts.elastic.co/packages/8.x/yum`).
- auth log trên các distro này thường ở `/var/log/secure` — file `filebeat/filebeat.yml`
  mẫu ở đây đã khai cả 2 path (`auth.log` và `secure`), Filebeat tự bỏ qua path không tồn tại.

## 6. Gỡ cài đặt

```bash
sudo systemctl disable --now filebeat auditd
sudo rm -f /etc/audit/rules.d/siem-webshell.rules
sudo augenrules --load 2>/dev/null || true
sudo mv /etc/filebeat/filebeat.yml.orig /etc/filebeat/filebeat.yml 2>/dev/null || true
```
