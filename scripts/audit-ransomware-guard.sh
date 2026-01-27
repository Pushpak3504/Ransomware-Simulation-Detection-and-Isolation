#!/bin/sh
### BEGIN INIT INFO
# Provides:          audit-ransomware-guard
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Auditd ransomware protection daemon
### END INIT INFO

DAEMON="/opt/defense/audit_guard_daemon.sh"
PIDFILE="/var/run/audit_guard.pid"

start() {
    echo "[+] Starting audit ransomware guard"
    start-stop-daemon --start --background \
        --make-pidfile --pidfile "$PIDFILE" \
        --exec "$DAEMON"
}

stop() {
    echo "[-] Stopping audit ransomware guard"
    start-stop-daemon --stop --pidfile "$PIDFILE"
}

case "$1" in
    start) start ;;
    stop) stop ;;
    restart) stop; start ;;
    status)
        [ -f "$PIDFILE" ] && echo "Running" || echo "Stopped"
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|status}"
        exit 1
        ;;
esac

exit 0
