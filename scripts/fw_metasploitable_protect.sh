#!/bin/bash
# ==================================================
# Firewall + Apache Port Forwarding for Metasploitable
# ==================================================

# -------------------------------
# VARIABLES
# -------------------------------
FW_EXT_IP="192.168.80.100"     # Firewall external IP
FW_INT_IP="192.168.40.100"     # Firewall internal IP
TARGET_IP="192.168.40.10"      # Metasploitable IP
LAN_NET="192.168.80.0/24"

echo "[+] Enabling IP forwarding"
echo 1 > /proc/sys/net/ipv4/ip_forward

# -------------------------------
# FLUSH OLD RULES
# -------------------------------
echo "[+] Flushing old rules"
iptables -F
iptables -t nat -F
iptables -X

# -------------------------------
# DEFAULT POLICIES (ZERO TRUST)
# -------------------------------
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# -------------------------------
# BASIC ALLOW RULES
# -------------------------------

# Loopback
iptables -A INPUT -i lo -j ACCEPT

# Established / Related
iptables -A INPUT   -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH to firewall (management)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# -------------------------------
# 🔥 APACHE PORT FORWARDING (DNAT)
# -------------------------------

# Forward HTTP from firewall external IP → metasploitable
iptables -t nat -A PREROUTING -p tcp -d $FW_EXT_IP --dport 80 \
-j DNAT --to-destination $TARGET_IP:80

# Allow forwarded HTTP traffic
iptables -A FORWARD -p tcp -d $TARGET_IP --dport 80 \
-m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Allow return traffic from metasploitable
iptables -A FORWARD -p tcp -s $TARGET_IP --sport 80 \
-m state --state ESTABLISHED,RELATED -j ACCEPT

# -------------------------------
# SSH ACCESS TO METASPLOITABLE
# (ONLY VIA FIREWALL)
# -------------------------------

iptables -A FORWARD -p tcp -s $FW_INT_IP -d $TARGET_IP --dport 22 -j ACCEPT

# SSH brute-force protection
iptables -A FORWARD -p tcp -d $TARGET_IP --dport 22 \
-m state --state NEW -m recent --set --name SSH

iptables -A FORWARD -p tcp -d $TARGET_IP --dport 22 \
-m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP

# -------------------------------
# BLOCK NMAP SCANS (TARGET ONLY)
# -------------------------------

iptables -A FORWARD -p tcp -d $TARGET_IP --tcp-flags ALL NONE -j DROP
iptables -A FORWARD -p tcp -d $TARGET_IP --tcp-flags ALL FIN -j DROP
iptables -A FORWARD -p tcp -d $TARGET_IP --tcp-flags ALL FIN,PSH,URG -j DROP

# -------------------------------
# ICMP RATE LIMITING
# -------------------------------

iptables -A FORWARD -p icmp -d $TARGET_IP --icmp-type echo-request \
-m limit --limit 1/s --limit-burst 2 -j ACCEPT

iptables -A FORWARD -p icmp -d $TARGET_IP -j DROP

# -------------------------------
# DROP INVALID PACKETS
# -------------------------------

iptables -A FORWARD -m state --state INVALID -j DROP

# -------------------------------
# LOG DROPPED PACKETS
# -------------------------------

iptables -A FORWARD -m limit --limit 5/min -j LOG \
--log-prefix "FW-DROP: " --log-level 4

# -------------------------------
# SAVE RULES (PERSISTENT)
# -------------------------------

iptables-save > /etc/iptables.rules

cat <<EOF > /etc/network/if-pre-up.d/iptables
#!/bin/sh
iptables-restore < /etc/iptables.rules
EOF

chmod +x /etc/network/if-pre-up.d/iptables

echo "[+] Firewall deployed successfully"
