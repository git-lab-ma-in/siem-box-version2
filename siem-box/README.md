# SIEM Box — Kafka + Logstash + Elasticsearch + Kibana (TLS tự động)

## Kiến trúc: 2 máy riêng biệt

Đây là điểm khác biệt quan trọng nhất so với bản trước: **SIEM box và máy chủ Web là 2
máy/VM khác nhau**, nói chuyện với nhau qua mạng (Kafka), giống đúng mô hình SIEM thật
(collector chạy trên endpoint cần giám sát, gửi log về trung tâm xử lý) — không co-locate
Filebeat/auditd chung với Elasticsearch/Kibana như trước.

```
Máy A — SIEM box (thư mục này, chạy docker compose)
┌───────────────────────────────────────────────────────┐
│ Kafka (nội bộ 9092, EXTERNAL 9094 publish ra ngoài)    │
│ Logstash (3 pipeline: nginx, linux-auth, linux-auditd) │
│ Elasticsearch (TLS)                                    │
│ Kibana (TLS)                                           │
│ rule-engine (Sigma → Lucene → poll ES → sinh alert)    │
└───────────────────────────────────────────────────────┘
                        ▲  mạng (TCP :9094)
                        │
Máy B — Web server (thư mục web-server-agent/, KHÔNG chạy trong docker-compose này)
┌───────────────────────────────────────────────────────┐
│ Nginx/ứng dụng web thật                                │
│ Filebeat (đọc access.log, auth.log, audit.log)         │
│ auditd + rule siem-webshell.rules (bắt execve www-data)│
└───────────────────────────────────────────────────────┘
```

Máy A và Máy B có thể là 2 VM trên cùng 1 host vật lý (mạng nội bộ của hypervisor) hoặc 2
máy vật lý khác hẳn — miễn là Máy B kết nối TCP được tới cổng Kafka EXTERNAL của Máy A.

## Cây thư mục

```
siem-box/                          ← chạy trên Máy A (SIEM box)
├── .env.example
├── docker-compose.yml
├── setup.sh
├── README.md                      ← file này
├── config/
│   ├── kibana.yml
│   └── logstash/
│       ├── logstash.yml
│       ├── pipelines.yml
│       └── pipeline/
│           ├── nginx.conf
│           ├── linux-auth.conf
│           └── linux-auditd.conf
├── rules/
│   └── sigma/
│       ├── ssh-invalid-user.yml
│       └── webshell-exec.yml
├── rule-engine/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── engine.py
└── utils/
    ├── setup-certs.sh
    ├── create-data-views.sh
    └── create-dashboard.sh

web-server-agent/                  ← copy sang và chạy trên Máy B (web server), xem README riêng
├── README.md
├── .env.example
├── install.sh
├── filebeat/
│   └── filebeat.yml
└── audit-rules/
    └── siem-webshell.rules
```

## Những gì mới thêm (so với bản trước) và nằm ở đâu

| Yêu cầu | File giải quyết |
|---|---|
| Tách đúng kiến trúc: SIEM box và web server là 2 máy riêng | `web-server-agent/` (chạy trên Máy B, không phải Docker) + Kafka listener `EXTERNAL` đã publish sẵn từ trước |
| Collector thật trên máy web (không phải gõ tay) | `web-server-agent/filebeat/filebeat.yml` + `web-server-agent/install.sh` |
| 2 nguồn dữ liệu còn thiếu (SSH auth, auditd) | `config/logstash/pipeline/linux-auth.conf`, `linux-auditd.conf` (phía SIEM box) |
| Rule auditd bắt hành vi webshell trên máy web | `web-server-agent/audit-rules/siem-webshell.rules` |
| Rule phát hiện tấn công (Sigma) | `rules/sigma/ssh-invalid-user.yml`, `webshell-exec.yml` |
| Cơ chế chạy rule + sinh alert | `rule-engine/engine.py` — Sigma → Lucene (`pysigma-backend-elasticsearch`), poll Elasticsearch, ghi alert vào `siem-alerts-default` |
| Dashboard | `utils/create-dashboard.sh` (tạo dashboard "SIEM Overview" qua Kibana API) |

Lấy cảm hứng từ mẫu stack bạn cung cấp (cert-gen tự động, wiring TLS vào từng service), nhưng
lược bớt Fleet Server để giữ stack **nhỏ gọn**, đồng thời sửa các lỗi đã phát hiện ở bản mẫu
(sai tên `pipelines.yml`, Kafka advertised listener trỏ `localhost`, index/Data View lệch tên).

## 1. Chạy nhanh

**Trên Máy A (SIEM box):**
```bash
cd siem-box
bash setup.sh
```

Script sẽ tự động:
1. Tạo `.env` từ `.env.example` nếu chưa có.
2. Phát hiện/yêu cầu bạn xác nhận `SIEM_EXTERNAL_HOST` (IP thật của Máy A).
3. **Tự sinh mật khẩu `elastic`, `kibana_system`, và encryption key** nếu bạn để trống trong `.env`
   — không cần tự nghĩ hay hardcode mật khẩu yếu như bản mẫu (`elastic`/`kibana`).
4. Kiểm tra `vm.max_map_count`.
5. Dựng stack (bao gồm build image `rule-engine`), chờ health check.
6. Tạo Kibana Data View tương ứng (`bash utils/create-data-views.sh`).
7. Export chứng chỉ CA ra `config/certs/ca.crt` để bạn import vào trình duyệt.

Sau đó (tuỳ chọn, nhưng nên chạy để có dashboard sẵn khi demo):
```bash
bash utils/create-dashboard.sh
```

**Trên Máy B (web server):**
```bash
cd web-server-agent
cp .env.example .env   # điền SIEM_EXTERNAL_HOST = IP của Máy A
sudo bash install.sh
```
Xem chi tiết trong `web-server-agent/README.md`.

## 2. Vì sao cần điền `SIEM_EXTERNAL_HOST` trước

Đây là biến quan trọng nhất, dùng lại ở **3 chỗ** (trước là 2, nay thêm 1 vì kiến trúc tách máy):

- SAN (Subject Alternative Name) của chứng chỉ TLS cho `es01` và `kibana` (Máy A)
- Giá trị Kafka `advertised.listeners` cho listener `EXTERNAL` (Máy A)
- Đích kết nối Kafka trong `web-server-agent/.env` trên Máy B — **phải điền cùng giá trị**
  với `SIEM_EXTERNAL_HOST` trong `siem-box/.env`, nếu không Filebeat trên Máy B sẽ không
  gửi được log về, và trình duyệt mở Kibana từ máy khác sẽ báo lỗi TLS SAN không khớp.

## 3. Cấu hình tài nguyên

| Thành phần | RAM tối thiểu | Ghi chú |
|---|---|---|
| Elasticsearch | 2GB | TLS thêm ~5-10% CPU overhead so với bản không mã hoá, không đáng kể |
| Kibana | 1GB | |
| Kafka | 1.5GB | |
| Logstash | 1.5GB | |
| rule-engine | 256MB | Python nhẹ, chạy poll định kỳ, không giữ dữ liệu lớn trong RAM |
| Kafka UI | 512MB | Xoá service này trong `docker-compose.yml` nếu muốn tối giản hơn nữa |
| setup (tạm thời) | 1GB | Container tự thoát sau khi xong, không tốn RAM lâu dài |

**Tổng tối thiểu Máy A: ~8-9GB RAM**, khuyến nghị **12GB+** nếu chạy song song với công cụ khác.
**Máy B (web server)**: Filebeat + auditd tốn không đáng kể (dưới 200MB RAM cộng thêm), có thể
dùng cấu hình VM nhỏ hơn nhiều, tuỳ vào ứng dụng web thật chạy trên đó.

## 4. Hệ điều hành

**Máy A**: Ubuntu Server 24.04 LTS, 4 vCPU, 12GB RAM, 40GB disk SSD. `elasticsearch-certutil`
(chạy trong container `setup`) và OpenSSL đều là công cụ native Linux — Docker Desktop
(Windows/macOS) đôi khi có khác biệt nhỏ về cách container resolve DNS nội bộ (`es01`, `kibana`)
có thể ảnh hưởng tới bước cert SAN nếu bạn tự thêm hostname tuỳ biến sau này.

**Máy B**: `web-server-agent/install.sh` hiện chỉ hỗ trợ Ubuntu/Debian (dùng `apt`); xem
`web-server-agent/README.md` mục "Distro khác" nếu dùng RHEL/CentOS.

## 5. Chạy trực tiếp trên Docker máy vật lý hay trong VM? (Máy A)

Lý do chọn VM cho demo chính thức: cô lập, snapshot, tránh mô phỏng tấn công chạm vào máy
thật. Với bản có TLS này có thêm một lý do cụ thể:

**Chứng chỉ TLS được "đóng băng" tại thời điểm chạy `setup.sh` lần đầu**, gắn chặt với
`SIEM_EXTERNAL_HOST` bạn khai lúc đó. Nếu bạn phát triển trên laptop cá nhân (IP riêng) rồi
demo trên máy phòng hội đồng (IP khác hẳn) → chứng chỉ cũ sẽ **không còn khớp SAN**, trình
duyệt báo lỗi TLS ngay khi mở Kibana trước hội đồng.

**Khuyến nghị**: dùng **VM cố định** cho Máy A (không đổi máy chạy VM giữa các buổi tập demo
và buổi báo cáo chính thức) — VM copy được giữa các máy vật lý mà giữ nguyên IP nội bộ (NAT/
host-only network), nên chứng chỉ vẫn khớp dù bạn đổi laptop trình chiếu vào phút chót. Máy B
(web server) không giữ chứng chỉ nào nên linh hoạt hơn — chỉ cần đổi `SIEM_EXTERNAL_HOST` trong
`web-server-agent/.env` và chạy lại `install.sh` nếu đổi mạng.

Nếu bắt buộc chạy Máy A trực tiếp trên máy vật lý (không dùng VM): chốt `SIEM_EXTERNAL_HOST`
bằng IP LAN cố định và luôn demo trên đúng máy đó, tại đúng phòng có mạng đó.

## 6. Nếu buộc phải đổi `SIEM_EXTERNAL_HOST`

Trên Máy A:
```bash
docker compose down -v      # xoá volume certs cũ
# sửa SIEM_EXTERNAL_HOST trong .env
bash setup.sh                # sinh lại chứng chỉ + toàn bộ dữ liệu từ đầu
```
Trên Máy B, sửa `SIEM_EXTERNAL_HOST` trong `web-server-agent/.env` cho khớp, rồi:
```bash
sudo bash install.sh
```
Không có cách "vá" chứng chỉ đang chạy — đây là đánh đổi hợp lý giữa bảo mật (SAN chặt) và tiện
lợi, chấp nhận được vì bạn chỉ chốt IP 1 lần trước demo.

## 7. Mở rộng thêm nguồn log

1. **Phía Máy B (thu thập)**: thêm 1 input mới trong `web-server-agent/filebeat/filebeat.yml`,
   đặt `fields.topic` theo đúng quy ước `logs-<source>-default`, rồi chạy lại
   `sudo bash install.sh` trên Máy B.
2. **Phía Máy A (xử lý)**: copy `config/logstash/pipeline/nginx.conf` → `<source>.conf`, sửa lại
   `topics` và filter cho phù hợp, **giữ đúng quy ước**: `index` trong output phải trùng chữ với
   Kafka `topics` ở input (vd nguồn `<source>` → topic `logs-<source>-default` → index cùng tên).
3. Thêm 1 block trong `config/logstash/pipelines.yml`.
4. Thêm tên nguồn vào mảng `SOURCES` trong `utils/create-data-views.sh`.
5. `docker compose restart logstash && bash utils/create-data-views.sh`.
6. Nếu muốn có rule phát hiện cho nguồn mới: thêm file `.yml` vào `rules/sigma/`, khai
   `logsource.service` đúng tên nguồn, và thêm mapping tương ứng vào `SERVICE_INDEX_MAP`
   trong `rule-engine/engine.py`. `rule-engine` nạp lại rule mỗi vòng poll — không cần
   restart container để rule mới có hiệu lực.

## 8. Mức độ đã kiểm thử của từng phần — nói thật, không tô hồng

Tôi không có sẵn một cluster Docker/Kibana thật + 2 máy vật lý để chạy toàn bộ end-to-end
trong lúc viết code này. Mức độ tin cậy từng phần:

- **Đã chạy thử thật, xác nhận đúng**: việc chuyển Sigma rule → Lucene query bằng `pysigma`
  (`rule-engine/engine.py`) — đã cài `pysigma`/`pysigma-backend-elasticsearch` thật và test
  đúng 2 rule hiện có (`ssh-invalid-user.yml`, `webshell-exec.yml`), output đúng như mong đợi:
  `auth.message:*Invalid\ user*` và `key:webshell_exec OR user.effective.id:33` (bao gồm cả
  escape khoảng trắng và logic OR). Cũng đã `python3 -m py_compile` toàn bộ `engine.py`.
- **Đúng cú pháp, đúng logic, nhưng CHƯA chạy trên cluster thật**: 2 pipeline Logstash mới
  (`linux-auth.conf`, `linux-auditd.conf`), phần gọi Elasticsearch REST API trong
  `engine.py` (poll + ghi alert), toàn bộ `web-server-agent/` (Filebeat, rule auditd,
  `install.sh`) — đây là các API/cấu hình chuẩn, ổn định, rủi ro thấp, nhưng bạn nên chạy thử
  và xem log (`docker logs -f siem-rule-engine`, `docker logs -f siem-logstash`,
  `tail -f /var/log/filebeat/filebeat.log` trên Máy B) ngay sau khi dựng để bắt lỗi sớm.
- **Rủi ro cao nhất, cần bạn kiểm tra kỹ**: `utils/create-dashboard.sh` — dùng schema "classic
  visualization" của Kibana Saved Objects API. JSON đã được kiểm tra hợp lệ về cú pháp (test
  bằng Python, xem đúng field cần có), nhưng tôi không thể xác nhận Kibana 8.19.7 chấp nhận
  đúng 100% mà không lỗi hiển thị vì không có cluster thật để chạy `curl` lên đó. Nếu dashboard
  không hiện đúng: mở từng panel trong Kibana > Visualize, bấm "Edit" — Kibana sẽ tự sửa/báo
  lỗi field cụ thể, hoặc bạn tạo lại thủ công theo đúng field đã liệt kê trong script.

## 9. Demo kịch bản tấn công để tạo alert thật

Chạy các lệnh này **trên Máy B (web server)** — xem thêm `web-server-agent/README.md` mục 4:

**SSH brute-force / scan tài khoản không tồn tại**:
```bash
for i in $(seq 1 6); do ssh khongtontai$i@localhost -p 22 || true; done
```

**Web shell giả lập** (cần đã cài + bật auditd trên Máy B, `install.sh` làm việc này tự động):
```bash
sudo -u www-data bash -c "id"
```
User `www-data` (uid 33) có sẵn trên Ubuntu/Debian dù chưa cài web server nào — auditd sẽ ghi
lại execve của `bash` với euid=33 (theo rule `audit-rules/siem-webshell.rules`), Filebeat đọc
`/var/log/audit/audit.log` và đẩy vào pipeline `linux-auditd`.

Chờ tối đa 60s (chu kỳ poll của rule-engine) rồi kiểm tra **trên Máy A**:
```bash
curl -sk -u elastic:<mật khẩu> "https://localhost:9200/siem-alerts-default/_search?pretty"
```
hoặc mở dashboard "SIEM Overview" trong Kibana (nếu đã chạy `utils/create-dashboard.sh`).

## 10. Vì sao Kafka trong bản này KHÔNG có TLS

Để giữ stack "nhỏ, dễ dùng", tôi ưu tiên TLS cho Elasticsearch/Kibana (nơi lưu dữ liệu và nơi
hiển thị — bề mặt quan trọng nhất) và chấp nhận Kafka chạy PLAINTEXT. **Lưu ý quan trọng sau
khi tách máy**: vì Máy B nay kết nối tới Kafka **qua mạng thật** (không còn cùng mạng Docker cô
lập như bản co-locate trước), log thô (bao gồm nội dung auth.log, audit.log) đi qua mạng ở dạng
không mã hoá giữa Máy B và Máy A. Với phạm vi đồ án/demo trong 1 mạng LAN tin cậy, đây là đánh
đổi chấp nhận được và nên nêu rõ là "known trade-off" trong báo cáo — nếu triển khai thật, bước
tiếp theo là bật `KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP` sang `SASL_SSL` cho listener
`EXTERNAL` và cấu hình TLS phía client Filebeat tương ứng, việc này tăng đáng kể độ phức tạp cấu
hình nên tôi để ngoài phạm vi bản này.
