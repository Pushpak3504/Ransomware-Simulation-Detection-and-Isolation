#!/bin/bash
set -e

ISSUE_FILE="/etc/issue"
MOTD_FILE="/etc/motd"

# Root check
if [[ "$EUID" -ne 0 ]]; then
  echo "Run as root"
  exit 1
fi

cat << 'EOF' > /tmp/handsomeware_banner.txt

 ██╗  ██╗ █████╗ ███╗   ██╗██████╗ ███████╗ ██████╗ ███╗   ███╗███████╗
 ██║  ██║██╔══██╗████╗  ██║██╔══██╗██╔════╝██╔═══██╗████╗ ████║██╔════╝
 ███████║███████║██╔██╗ ██║██║  ██║███████╗██║   ██║██╔████╔██║█████╗  
 ██╔══██║██╔══██║██║╚██╗██║██║  ██║╚════██║██║   ██║██║╚██╔╝██║██╔══╝  
 ██║  ██║██║  ██║██║ ╚████║██████╔╝███████║╚██████╔╝██║ ╚═╝ ██║███████╗
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝

──────────────────────────────────────────────────────────────────────
                H A N D S O M E W A R E   A T T A C K
──────────────────────────────────────────────────────────────────────

   Hello, friend.
   Your files are encrypted.
   Control is an illusion.

   Host : $(hostname)
   Time : $(date)

──────────────────────────────────────────────────────────────────────

EOF

# Apply banner
cp /tmp/handsomeware_banner.txt "$ISSUE_FILE"
cp /tmp/handsomeware_banner.txt "$MOTD_FILE"
rm -f /tmp/handsomeware_banner.txt
