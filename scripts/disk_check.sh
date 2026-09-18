#!/bin/bash
ES_PASS="${ES_PASSWORD:?ES_PASSWORD environment variable not set}"
# Norrsken — ELK Storage Monitor
# Run manually or via cron to check storage status

echo "========================================"
echo "  NORRSKEN ELK STORAGE MONITOR"
echo "  $(date '+%Y-%m-%d %H:%M:%S CAT')"
echo "========================================"

echo ""
echo "--- DISK USAGE ---"
df -h / | awk 'NR==2 {printf "Used: %s / %s (%s)\nFree: %s\n", $3, $2, $5, $4}'

echo ""
echo "--- ELASTICSEARCH INDEX ---"
curl -sk -u "elastic:${ES_PASS}" \
  "https://192.168.1.5:9200/_cat/indices?v&h=index,docs.count,store.size&s=store.size:desc" \
  | grep fortinet | awk '{printf "Documents: %s\nSize:      %s\n", $2, $3}'

echo ""
echo "--- ALL INDICES BY SIZE ---"
curl -sk -u "elastic:${ES_PASS}" \
  "https://192.168.1.5:9200/_cat/indices?v&h=index,store.size&s=store.size:desc" \
  | head -6

echo ""
echo "--- ELASTICSEARCH DATA DIRECTORY ---"
sudo du -sh /var/lib/elasticsearch/ 2>/dev/null
sudo du -sh /var/lib/elasticsearch-snapshots/ 2>/dev/null

echo ""
echo "--- VICTORIAMETRICS ---"
du -sh /opt/norrsken-monitor/data/victoriametrics/

echo ""
echo "--- GROWTH RATE (approx) ---"
DOCS=$(curl -sk -u "elastic:${ES_PASS}" \
  "https://192.168.1.5:9200/_cat/indices?h=docs.count" | grep -v "^0$" | head -1)
echo "Current FortiGate documents: $DOCS"
echo "Approx growth: ~11.2M docs/day, ~3.35GB/day"

FREE=$(df / | awk 'NR==2 {print $4}')
FREE_GB=$((FREE / 1024 / 1024))
echo "Days until disk full (approx): ~$((FREE_GB / 4)) days"

echo ""
echo "========================================"
