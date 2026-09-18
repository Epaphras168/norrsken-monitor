#!/bin/bash
ARCHIVE_HOST="100.74.77.76"
ARCHIVE_USER="zuba"
ARCHIVE_BASE="/archive/norrsken"
LOG="/opt/norrsken-monitor/archive.log"
DATE=$(date +%Y-%m-%d)
ES_URL="https://192.168.1.5:9200"
ES_PASS="${ES_PASSWORD:?ES_PASSWORD environment variable not set}"
LOCKFILE="/tmp/norrsken_archive.lock"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

if [ -e "$LOCKFILE" ]; then
    OLD_PID=$(cat "$LOCKFILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && kill -0 "$OLD_PID" 2>/dev/null; then
        log "ABORT: another archive.sh instance (PID ${OLD_PID}) is still running. Exiting without starting a second run."
        exit 1
    else
        log "Stale lock file found (PID ${OLD_PID} no longer running) — removing and proceeding."
        rm -f "$LOCKFILE"
    fi
fi
echo $$ > "$LOCKFILE"
trap 'rm -f "$LOCKFILE"' EXIT

log "=== Archive run started: ${DATE} (PID $$) ==="

log "Archiving VictoriaMetrics..."
tar -czf /tmp/vm-${DATE}.tar.gz \
    /opt/norrsken-monitor/data/victoriametrics/ 2>/dev/null
rsync -avz /tmp/vm-${DATE}.tar.gz \
    ${ARCHIVE_USER}@${ARCHIVE_HOST}:${ARCHIVE_BASE}/victoriametrics/exports/
rm -f /tmp/vm-${DATE}.tar.gz
log "VictoriaMetrics done"

log "Archiving Grafana..."
tar -czf /tmp/grafana-${DATE}.tar.gz \
    /opt/norrsken-monitor/data/grafana/ 2>/dev/null
rsync -avz /tmp/grafana-${DATE}.tar.gz \
    ${ARCHIVE_USER}@${ARCHIVE_HOST}:${ARCHIVE_BASE}/grafana/
rm -f /tmp/grafana-${DATE}.tar.gz
log "Grafana done"

log "Archiving configs and scripts..."
rsync -avz \
    /opt/norrsken-monitor/docker-compose.yml \
    /opt/norrsken-monitor/prometheus/ \
    /opt/norrsken-monitor/blackbox/ \
    /opt/norrsken-monitor/grafana/provisioning/ \
    /opt/norrsken-monitor/collectors/ \
    /opt/norrsken-monitor/events.log \
    /opt/norrsken-monitor/dscp_verification_procedure.md \
    ${ARCHIVE_USER}@${ARCHIVE_HOST}:${ARCHIVE_BASE}/configs/
log "Configs done"

SNAPSHOT_NAME="snapshot-${DATE}-$(date +%H%M)"
log "Taking Elasticsearch snapshot: ${SNAPSHOT_NAME}..."
SNAP_RESULT=$(curl -sk -u "elastic:${ES_PASS}" \
    -X PUT "${ES_URL}/_snapshot/norrsken_archive/${SNAPSHOT_NAME}?wait_for_completion=true" \
    -H 'Content-Type: application/json' \
    -d '{
        "indices": "logs-fortinet_fortigate.log-*",
        "ignore_unavailable": true,
        "include_global_state": false
    }')

SNAP_STATE=$(echo "$SNAP_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin)['snapshot']['state'])" 2>/dev/null)
log "Snapshot state: ${SNAP_STATE}"

if [ "$SNAP_STATE" = "SUCCESS" ]; then
    log "Syncing ES snapshot to archive VM..."
    rsync -avz /var/lib/elasticsearch-snapshots/ \
        ${ARCHIVE_USER}@${ARCHIVE_HOST}:${ARCHIVE_BASE}/elasticsearch/snapshots/
    RSYNC_EXIT=$?

    if [ $RSYNC_EXIT -eq 0 ]; then
        log "ES snapshot synced successfully (rsync exit 0)"
        log "Performing file-by-file verification before deleting anything locally..."

        find /var/lib/elasticsearch-snapshots/ -type f -printf '%P\n' | LC_ALL=C sort > /tmp/archive_local_files.txt
        ssh ${ARCHIVE_USER}@${ARCHIVE_HOST} \
            "find ${ARCHIVE_BASE}/elasticsearch/snapshots/ -type f -printf '%P\n' | LC_ALL=C sort" \
            > /tmp/archive_remote_files.txt

        LOCAL_COUNT=$(wc -l < /tmp/archive_local_files.txt)
        REMOTE_COUNT=$(wc -l < /tmp/archive_remote_files.txt)
        log "Local file count: ${LOCAL_COUNT} | Remote file count: ${REMOTE_COUNT}"

        MISSING_FILES=$(comm -23 /tmp/archive_local_files.txt /tmp/archive_remote_files.txt)
        MISSING_COUNT=$(echo -n "$MISSING_FILES" | grep -c . || true)

        if [ -z "$MISSING_FILES" ]; then
            log "VERIFIED: all ${LOCAL_COUNT} local files confirmed present on remote. Safe to delete."

            ALL_SNAPSHOTS=$(curl -sk -u "elastic:${ES_PASS}" \
                "${ES_URL}/_snapshot/norrsken_archive/_all" | \
                python3 -c "import sys,json; [print(s['snapshot']) for s in json.load(sys.stdin).get('snapshots',[])]")

            for SNAP in $ALL_SNAPSHOTS; do
                log "  Deleting local snapshot: ${SNAP}"
                curl -sk -u "elastic:${ES_PASS}" \
                    -X DELETE "${ES_URL}/_snapshot/norrsken_archive/${SNAP}" > /dev/null
            done

            log "Local snapshot cleanup complete — zero snapshots retained locally by design."
        else
            log "WARNING: ${MISSING_COUNT} local file(s) NOT found on remote — skipping local deletion this run."
            log "First few missing files:"
            echo "$MISSING_FILES" | head -5 | while read -r line; do log "  MISSING: $line"; done
        fi
    else
        log "WARNING: rsync exited with code ${RSYNC_EXIT} — skipping local deletion, will retry next time."
    fi
else
    log "ERROR: ES snapshot failed — skipping sync and cleanup"
fi

log "Local snapshot directory size after cleanup:"
du -sh /var/lib/elasticsearch-snapshots/ 2>/dev/null

log "Remote archive size:"
ssh ${ARCHIVE_USER}@${ARCHIVE_HOST} "du -sh ${ARCHIVE_BASE}/*"

log "=== Archive run complete ==="
