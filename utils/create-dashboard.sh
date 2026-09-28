#!/bin/bash
# create-dashboard.sh
# Tạo dashboard "SIEM Overview" trong Kibana qua Saved Objects API (_bulk_create),
# gồm 3 panel dạng "classic visualization" (visState) + 1 dashboard gộp cả 3.
#
# LƯU Ý (xem README mục 8 - "mức độ đã kiểm thử"): đây là phần rủi ro cao nhất
# trong toàn bộ dự án. JSON đã được kiểm tra hợp lệ về cú pháp và đúng theo
# schema Saved Objects của Kibana 8.x, nhưng CHƯA được xác nhận chạy đúng 100%
# trên một cluster Kibana 8.19.7 thật. Nếu panel không hiển thị đúng sau khi
# chạy script này: vào Kibana > Analytics > Visualize library, mở panel bị lỗi,
# bấm "Edit" — Kibana sẽ tự báo lỗi field cụ thể (thường do field chưa tồn tại
# vì chưa có log nào chảy vào index tương ứng). Cách chắc ăn hơn nếu debug JSON
# quá mất thời gian: tạo lại thủ công 3 visualization theo đúng field liệt kê
# trong script, rồi kéo vào 1 dashboard mới.

set -euo pipefail

: "${KIBANA_PORT:?Thiếu biến KIBANA_PORT — chạy script này qua setup.sh hoặc export KIBANA_PORT trước}"
: "${ELASTIC_PASSWORD:?Thiếu biến ELASTIC_PASSWORD}"

KIBANA_URL="https://localhost:${KIBANA_PORT}"
AUTH=(-k -u "elastic:${ELASTIC_PASSWORD}")

echo "=========================================="
echo "[DASHBOARD] Tạo dashboard 'SIEM Overview'"
echo "=========================================="

get_data_view_id() {
  local TITLE_PATTERN="$1"
  curl -s "${AUTH[@]}" -H "kbn-xsrf: true" \
    "${KIBANA_URL}/api/data_views" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
target = '${TITLE_PATTERN}'
for dv in data.get('data_view', []):
    if dv.get('title') == target:
        print(dv['id'])
        break
"
}

echo "[DASHBOARD] Tra ID của các Data View (phải chạy create-data-views.sh trước)..."
DV_ALERTS=$(get_data_view_id "siem-alerts-default*")
DV_AUTH=$(get_data_view_id "logs-linux-auth-default*")

if [ -z "$DV_ALERTS" ] || [ -z "$DV_AUTH" ]; then
  echo "[DASHBOARD] LỖI: chưa tìm thấy Data View cần thiết."
  echo "  siem-alerts-default* -> '${DV_ALERTS}'"
  echo "  logs-linux-auth-default* -> '${DV_AUTH}'"
  echo "Chạy: bash utils/create-data-views.sh   rồi thử lại."
  exit 1
fi
echo "[DASHBOARD]   Data View siem-alerts-default*     -> ${DV_ALERTS}"
echo "[DASHBOARD]   Data View logs-linux-auth-default*  -> ${DV_AUTH}"

BULK_BODY=$(python3 - "$DV_ALERTS" "$DV_AUTH" <<'PYEOF'
import json
import sys

dv_alerts, dv_auth = sys.argv[1], sys.argv[2]


def vis_object(obj_id, title, vis_state, dv_ref_id):
    return {
        "type": "visualization",
        "id": obj_id,
        "attributes": {
            "title": title,
            "visState": json.dumps(vis_state),
            "uiStateJSON": "{}",
            "kibanaSavedObjectMeta": {
                "searchSourceJSON": json.dumps({
                    "query": {"query": "", "language": "kuery"},
                    "filter": [],
                    "indexRefName": "kibanaSavedObjectMeta.searchSourceJSON.index",
                })
            },
        },
        "references": [
            {
                "name": "kibanaSavedObjectMeta.searchSourceJSON.index",
                "type": "index-pattern",
                "id": dv_ref_id,
            }
        ],
    }


# Panel 1: alert theo thời gian, chia màu theo mức độ (rule.level.keyword)
alerts_over_time = vis_object(
    "siem-alerts-over-time",
    "SIEM - Alerts theo thời gian",
    {
        "title": "SIEM - Alerts theo thời gian",
        "type": "histogram",
        "params": {
            "type": "histogram",
            "grid": {"categoryLines": False},
            "categoryAxes": [{"id": "CategoryAxis-1", "type": "category", "position": "bottom", "show": True}],
            "valueAxes": [{"id": "ValueAxis-1", "name": "LeftAxis-1", "type": "value", "position": "left", "show": True}],
            "seriesParams": [{
                "show": True, "type": "histogram", "mode": "stacked",
                "data": {"label": "Count", "id": "1"}, "valueAxis": "ValueAxis-1",
            }],
            "addTooltip": True, "addLegend": True, "legendPosition": "right",
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "date_histogram", "schema": "segment",
             "params": {"field": "@timestamp", "interval": "auto"}},
            {"id": "3", "enabled": True, "type": "terms", "schema": "group",
             "params": {"field": "rule.level.keyword", "size": 5, "order": "desc", "orderBy": "1"}},
        ],
    },
    dv_alerts,
)

# Panel 2: top rule bị kích hoạt (pie)
alerts_by_rule = vis_object(
    "siem-alerts-by-rule",
    "SIEM - Alerts theo rule",
    {
        "title": "SIEM - Alerts theo rule",
        "type": "pie",
        "params": {"type": "pie", "addTooltip": True, "addLegend": True, "legendPosition": "right", "isDonut": True},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "segment",
             "params": {"field": "rule.title.keyword", "size": 10, "order": "desc", "orderBy": "1"}},
        ],
    },
    dv_alerts,
)

# Panel 3: bảng đăng nhập SSH thất bại theo IP nguồn
failed_ssh_by_ip = vis_object(
    "siem-failed-ssh-by-ip",
    "SIEM - SSH thất bại theo IP nguồn",
    {
        "title": "SIEM - SSH thất bại theo IP nguồn",
        "type": "table",
        "params": {"perPage": 10, "showPartialRows": False, "showMetricsAtAllLevels": False, "showTotal": False},
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {"id": "2", "enabled": True, "type": "terms", "schema": "bucket",
             "params": {"field": "source.ip", "size": 20, "order": "desc", "orderBy": "1"}},
        ],
    },
    dv_auth,
)

panels = [
    {"obj": alerts_over_time, "panel_ref": "panel_0", "x": 0, "y": 0, "w": 24, "h": 15},
    {"obj": alerts_by_rule, "panel_ref": "panel_1", "x": 24, "y": 0, "w": 24, "h": 15},
    {"obj": failed_ssh_by_ip, "panel_ref": "panel_2", "x": 0, "y": 15, "w": 48, "h": 15},
]

panels_json = []
dashboard_references = []
for p in panels:
    panels_json.append({
        "version": "8.19.7",
        "type": "visualization",
        "gridData": {"x": p["x"], "y": p["y"], "w": p["w"], "h": p["h"], "i": p["panel_ref"]},
        "panelIndex": p["panel_ref"],
        "embeddableConfig": {},
        "panelRefName": p["panel_ref"],
    })
    dashboard_references.append({
        "name": p["panel_ref"],
        "type": "visualization",
        "id": p["obj"]["id"],
    })

dashboard = {
    "type": "dashboard",
    "id": "siem-overview",
    "attributes": {
        "title": "SIEM Overview",
        "description": "Tong quan alert va dang nhap SSH that bai - sinh tu dong boi utils/create-dashboard.sh",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "hidePanelTitles": False}),
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        },
    },
    "references": dashboard_references,
}

bulk = [alerts_over_time, alerts_by_rule, failed_ssh_by_ip, dashboard]
print(json.dumps(bulk))
PYEOF
)

echo "[DASHBOARD] Đang gửi 3 visualization + 1 dashboard lên Kibana (overwrite nếu đã tồn tại)..."
RESPONSE=$(curl -s -w "\n%{http_code}" -X POST \
  "${AUTH[@]}" \
  -H "Content-Type: application/json" \
  -H "kbn-xsrf: true" \
  "${KIBANA_URL}/api/saved_objects/_bulk_create?overwrite=true" \
  -d "${BULK_BODY}")

HTTP_CODE=$(echo "$RESPONSE" | tail -n1)
BODY=$(echo "$RESPONSE" | sed '$d')

if [ "$HTTP_CODE" == "200" ]; then
  echo "[DASHBOARD]   OK — mở Kibana > Analytics > Dashboard > 'SIEM Overview'"
else
  echo "[DASHBOARD]   Thất bại (HTTP $HTTP_CODE):"
  echo "$BODY"
  echo "[DASHBOARD]   Xem ghi chú rủi ro ở đầu file này để tạo lại thủ công nếu cần."
  exit 1
fi

echo "[DASHBOARD] Hoàn tất."
