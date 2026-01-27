#!/bin/bash
# =====================================================
# Auditd-based Ransomware Guard (Daemon)
# Detects rapid file write activity
# =====================================================

AUDIT_LOG="/var/log/audit/audit.log"
KEY="ransomware_detect"

THRESHOLD=20
WINDOW=10

LOCKFILE="/tmp/.network_isolated"
LOGFILE="/var/log/ransomware_guard.log"

count=0
start_time=0

log() {
    echo "$(date '+%F %T') : $1" >> "$LOGFILE"
}

isolate() {
    [ -f "$LOCKFILE" ] && return

    log "THRESHOLD HIT — isolating network"

    iptables -P INPUT DROP
    iptables -P OUTPUT DROP
    iptables -P FORWARD DROP

    touch "$LOCKFILE"
    log "Network isolation complete"
}

log "Ransomware audit daemon started"

tail -F "$AUDIT_LOG" | while read line; do
    echo "$line" | grep -q "$KEY" || continue

    now=$(date +%s)

    if (( start_time == 0 || now - start_time > WINDOW )); then
        start_time=$now
        count=0
    fi

    ((count++))

    if (( count >= THRESHOLD )); then
        isolate
        exit 0
    fi
done
