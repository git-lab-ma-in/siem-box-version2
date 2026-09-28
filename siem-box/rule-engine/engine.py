#!/usr/bin/env python3
"""
SIEM rule-engine
=================
- Đọc toàn bộ rule Sigma trong RULES_DIR (mặc định /rules/sigma).
- Convert Sigma -> Lucene query bằng pySigma (backend Elasticsearch, LuceneBackend).
- Mỗi POLL_INTERVAL giây: với mỗi rule, chạy query lên đúng index tương ứng
  (theo logsource.service, xem SERVICE_INDEX_MAP) trong khoảng thời gian mới
  kể từ lần poll trước.
- Với mỗi document khớp, ghi 1 alert vào ALERTS_INDEX. Việc ghi dùng _create
  với _id xác định (hash của rule + doc gốc) nên idempotent: chạy lại không
  tạo alert trùng cho cùng 1 sự kiện gốc.
- State (thời điểm poll gần nhất của từng rule) được lưu ở STATE_FILE để
  container restart không bỏ sót / không quét lại từ đầu toàn bộ dữ liệu.

Rule mới muốn được engine này chạy phải khai báo logsource.service là một
trong các key của SERVICE_INDEX_MAP bên dưới (khớp với pipeline.id trong
config/logstash/pipelines.yml).
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [rule-engine] %(levelname)s %(message)s",
)
log = logging.getLogger("rule-engine")

ES_HOST = os.environ.get("ES_HOST", "https://es01:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASSWORD = os.environ["ES_PASSWORD"]
ES_CA_CERT = os.environ.get("ES_CA_CERT", "/certs/ca/ca.crt")
POLL_INTERVAL = int(os.environ.get("POLL_INTERVAL", "60"))
ALERTS_INDEX = os.environ.get("ALERTS_INDEX", "siem-alerts-default")
RULES_DIR = Path(os.environ.get("RULES_DIR", "/rules/sigma"))
STATE_FILE = Path(os.environ.get("STATE_FILE", "/data/state.json"))
INITIAL_LOOKBACK_MINUTES = int(os.environ.get("INITIAL_LOOKBACK_MINUTES", "15"))

# logsource.service (khai báo trong file Sigma) -> index Elasticsearch tương ứng.
# Quy ước đặt tên index xem trong config/logstash/pipelines.yml.
SERVICE_INDEX_MAP = {
    "auth": "logs-linux-auth-default",
    "auditd": "logs-linux-auditd-default",
    "nginx": "logs-nginx-default",
}

SESSION = requests.Session()
SESSION.auth = (ES_USER, ES_PASSWORD)
SESSION.verify = ES_CA_CERT

BACKEND = LuceneBackend()


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            log.warning("Không đọc được state file %s, bắt đầu lại từ đầu.", STATE_FILE)
    return {}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state))
    tmp.replace(STATE_FILE)


def load_rules() -> list:
    """Đọc từng file .yml trong RULES_DIR, convert sang Lucene query.

    Trả về list[dict]: {id, title, level, description, file, index, query}
    """
    rules = []
    if not RULES_DIR.exists():
        log.warning("Thư mục rule %s không tồn tại.", RULES_DIR)
        return rules

    for path in sorted(RULES_DIR.glob("*.yml")):
        try:
            raw = path.read_text(encoding="utf-8")
            collection = SigmaCollection.from_yaml(raw)
            queries = BACKEND.convert(collection)
        except Exception as exc:
            log.error("Bỏ qua rule lỗi cú pháp/convert %s: %s", path.name, exc)
            continue

        for sigma_rule, query in zip(collection.rules, queries):
            service = str(sigma_rule.logsource.service) if sigma_rule.logsource and sigma_rule.logsource.service else None
            index = SERVICE_INDEX_MAP.get(service)
            if not index:
                log.warning(
                    "Rule '%s' (file %s) có logsource.service='%s' — không có trong "
                    "SERVICE_INDEX_MAP, bỏ qua. Thêm mapping trong engine.py nếu đây là nguồn mới.",
                    sigma_rule.title, path.name, service,
                )
                continue

            rules.append({
                "id": str(sigma_rule.id) if sigma_rule.id else path.stem,
                "title": sigma_rule.title,
                "level": str(sigma_rule.level) if sigma_rule.level else "medium",
                "description": (sigma_rule.description or "").strip(),
                "file": path.name,
                "index": index,
                "query": query,
            })

    return rules


def run_rule(rule: dict, since_iso: str, now_iso: str) -> list:
    """Chạy 1 rule lên đúng index, trong khoảng thời gian (since_iso, now_iso]."""
    body = {
        "size": 200,
        "query": {
            "bool": {
                "must": [
                    {"query_string": {"query": rule["query"], "default_operator": "AND"}},
                ],
                "filter": [
                    {"range": {"@timestamp": {"gt": since_iso, "lte": now_iso}}},
                ],
            }
        },
        "sort": [{"@timestamp": "asc"}],
    }
    url = f"{ES_HOST}/{rule['index']}/_search"
    try:
        resp = SESSION.post(url, json=body, timeout=20)
        if resp.status_code == 404:
            # Index chưa tồn tại (chưa có log nào từ nguồn này chảy vào) — bỏ qua êm.
            return []
        resp.raise_for_status()
        return resp.json().get("hits", {}).get("hits", [])
    except requests.RequestException as exc:
        log.error("Lỗi khi chạy rule '%s' trên index %s: %s", rule["title"], rule["index"], exc)
        return []


def alert_doc_id(rule_id: str, hit: dict) -> str:
    """_id xác định (idempotent) — tránh ghi trùng alert cho cùng 1 sự kiện gốc
    nếu 1 khoảng thời gian bị quét lại (vd sau khi container restart)."""
    raw = f"{rule_id}:{hit['_index']}:{hit['_id']}"
    return hashlib.sha256(raw.encode()).hexdigest()


def _get(d: dict, path: str):
    cur = d
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def index_alert(rule: dict, hit: dict) -> None:
    source = hit.get("_source", {})
    doc = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "rule.id": rule["id"],
        "rule.title": rule["title"],
        "rule.level": rule["level"],
        "rule.description": rule["description"],
        "rule.file": rule["file"],
        "event.original_index": hit["_index"],
        "event.original_id": hit["_id"],
        "event.original_timestamp": source.get("@timestamp"),
        "source.ip": _get(source, "source.ip"),
        "user.name": _get(source, "user.name"),
        "message": source.get("message") or _get(source, "auth.message"),
    }
    doc_id = alert_doc_id(rule["id"], hit)
    url = f"{ES_HOST}/{ALERTS_INDEX}/_create/{doc_id}"
    try:
        resp = SESSION.put(url, json=doc, timeout=20)
    except requests.RequestException as exc:
        log.error("Không gửi được alert lên ES: %s", exc)
        return

    if resp.status_code == 201:
        log.info("ALERT [%s] %s  (nguồn: %s/%s)", rule["level"].upper(), rule["title"], hit["_index"], hit["_id"])
    elif resp.status_code == 409:
        pass  # alert cho sự kiện này đã tồn tại — bỏ qua, không phải lỗi
    else:
        log.error("Ghi alert thất bại (HTTP %s): %s", resp.status_code, resp.text[:300])


def main() -> None:
    log.info("Rule-engine khởi động — poll mỗi %ss, đọc rule từ %s, ghi alert vào %s",
              POLL_INTERVAL, RULES_DIR, ALERTS_INDEX)
    state = load_state()

    while True:
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()
        default_since_iso = (now - timedelta(minutes=INITIAL_LOOKBACK_MINUTES)).isoformat()

        # Nạp lại rule mỗi vòng: cho phép thêm/sửa rule trong rules/sigma/ mà
        # không cần restart container siem-rule-engine.
        rules = load_rules()
        if not rules:
            log.warning("Không nạp được rule nào hợp lệ — kiểm tra log lỗi phía trên.")

        for rule in rules:
            since_iso = state.get(rule["id"], default_since_iso)
            hits = run_rule(rule, since_iso, now_iso)
            for hit in hits:
                index_alert(rule, hit)
            state[rule["id"]] = now_iso

        save_state(state)
        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    main()
