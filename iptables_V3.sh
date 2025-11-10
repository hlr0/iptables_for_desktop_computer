#!/bin/bash

#================================================================
# LETS GET FANCY - COLOR CODE
#================================================================
RES=$(echo -e "\e[0m") # Reset
BLD=$(echo -e "\e[0;34m") # Blue
BLL=$(echo -e "\e[1;34m") # Blue Light
CYD=$(echo -e "\e[0;36m") # Cyan
CYL=$(echo -e "\e[1;36m") # Cyan Light
GRD=$(echo -e "\e[0;32m") # Green 
GRL=$(echo -e "\e[1;32m") # Green Light
PUD=$(echo -e "\e[0;35m") # Purple
PUL=$(echo -e "\e[1;35m") # Purple Light
RED=$(echo -e "\e[0;31m") # Red
REL=$(echo -e "\e[1;31m") # Red Light
YED=$(echo -e "\e[0;33m") # Yellow
YEL=$(echo -e "\e[1;33m") # Yellow Light

#================================================================
# BANNER
#================================================================
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n ${RED} ========/// DESKTOP IPTABLES FIREWALL RULES ${RES}"   
printf "\n ${BLD} ========/// Basic Script to Setup Iptables rules for your Desktop (Everyday Box) ${RES}"   
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n ${YED} ======================================================================================================================= \n ${RES}"

##### SETTINGS OF THE SYSTEM
# Setting the default iptables super bin file at the very top
IPT="/sbin/iptables"
IP6T="/sbin/ip6tables"
# Default network interface
NETIF="eth0"

# Trusted IPs that can ping this machine (array for easy expansion)
TRUSTED_PING_IPS=("192.168.1.100")

#================================================================
# FUNCTIONS
#================================================================

show_help() {
    echo "Iptables Script for Desktop Computer Setup"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help      Show this help message and exit"
    echo "  -c, --clean     Revert all changes and flush the iptables rules"
    echo "  -n, --network   Specify network interface (e.g., eth0, eno2, wlan0)"
    echo "  -l, --list      Display current iptables rules"
    echo "  -b, --backup    Backup current iptables rules"
    echo ""
    echo "Examples:"
    echo "  $0 -n eno2      Run with eno2 as network interface"
    echo "  $0 --clean      Flush all iptables rules"
    echo "  $0 --list       Display current rules"
    echo "  $0 --backup     Backup current rules to file"
    echo ""
    echo "Note: This script must be run with root privileges"
    exit 0
}

backup_iptables() {
    echo -e "\n\n"
    printf "\n ${YED} ======================================================================================================================= ${RES}"
    printf "\n ${RED} ========/// BACKING UP CURRENT IPTABLES RULES ${RES}" 
    printf "\n ${YED} ======================================================================================================================= ${RES}\n"
    
    BACKUP_FILE="/tmp/iptables-backup-$(date +%F-%T).rules"
    iptables-save > "$BACKUP_FILE"
    
    printf "\n ${GRD} ========/// Backup saved to: $BACKUP_FILE ${RES}\n"
    exit 0
}

list_iptables() {
    echo -e "\n\n"
    printf "\n ${YED} ======================================================================================================================= ${RES}"
    printf "\n ${RED} ========/// CURRENT IPTABLES RULES ${RES}" 
    printf "\n ${YED} ======================================================================================================================= ${RES}\n"
    
    echo -e "\n${BLD}=== FILTER TABLE ===${RES}"
    $IPT -nvL --line-numbers
    
    echo -e "\n${BLD}=== NAT TABLE ===${RES}"
    $IPT -t nat -nvL --line-numbers
    
    echo -e "\n${BLD}=== MANGLE TABLE ===${RES}"
    $IPT -t mangle -nvL --line-numbers
    
    exit 0
}

clean_iptables() {
    echo -e "\n\n"
    printf "\n ${YED} ======================================================================================================================= ${RES}"
    printf "\n ${YED} ======================================================================================================================= ${RES}"
    printf "\n ${YED} ======================================================================================================================= ${RES}"
    printf "\n ${RED} ========/// CLEAN SLATE PROTOCOL START ${RES}" 
    printf "\n ${YED} ======================================================================================================================= ${RES}"
    printf "\n ${YED} ======================================================================================================================= ${RES}"
    printf "\n ${YED} =======================================================================================================================  \n ${RES}"

    # Flush all rules (IPv4)
    $IPT -F
    $IPT -X
    $IPT -t nat -F
    $IPT -t nat -X
    $IPT -t mangle -F
    $IPT -t mangle -X
    $IPT -t raw -F
    $IPT -t raw -X
    $IPT -t security -F
    $IPT -t security -X
    
    # Flush all rules (IPv6)
    $IP6T -F
    $IP6T -X
    $IP6T -t nat -F
    $IP6T -t nat -X
    $IP6T -t mangle -F
    $IP6T -t mangle -X
    $IP6T -t raw -F
    $IP6T -t raw -X
    $IP6T -t security -F
    $IP6T -t security -X
    
    # Set default policies
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
    
    $IP6T -P INPUT ACCEPT
    $IP6T -P OUTPUT ACCEPT
    $IP6T -P FORWARD ACCEPT
    
    # List current rules
    $IPT -nvL 

    echo -e "\n------------------------------------------------- Finished Clean Slate Protocol-------------------------------------------------"
    exit 0
}

#================================================================
# PARSE COMMAND LINE ARGUMENTS
#================================================================
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            ;;
        -c|--clean)
            clean_iptables
            ;;
        -n|--network)
            NETIF="$2"
            shift
            ;;
        -l|--list)
            list_iptables
            ;;
        -b|--backup)
            backup_iptables
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
    shift
done

#================================================================
# MAIN SCRIPT - ROOT CHECK
#================================================================
if [ "$EUID" -ne 0 ]; then 
    printf "\n ${RED} ========/// ERROR: This script must be run as root ${RES}\n"
    exit 1
fi

#================================================================
# BACKUP CURRENT RULES BEFORE PROCEEDING
#================================================================
echo -e "----------------------------------------\n  Creating automatic backup \n----------------------------------------\n "
BACKUP_FILE="/tmp/iptables-backup-$(date +%F-%T).rules"
iptables-save > "$BACKUP_FILE" 2>/dev/null
printf "\n ${GRD} ========/// Backup saved to: $BACKUP_FILE ${RES}\n"

#================================================================
# LOAD REQUIRED KERNEL MODULES
#================================================================
echo -e "----------------------------------------\n  Loading Required Kernel Modules \n----------------------------------------\n "
modprobe ip_conntrack 2>/dev/null || modprobe nf_conntrack
modprobe ip_conntrack_ftp 2>/dev/null || modprobe nf_conntrack_ftp
modprobe ip_nat_ftp 2>/dev/null || modprobe nf_nat_ftp

echo -e "----------------------------------------\n  Using Network Interface: $NETIF \n----------------------------------------\n "

# Check if network interface exists
if ! ip link show $NETIF >/dev/null 2>&1; then
    printf "\n ${RED} ========/// ERROR: Network interface $NETIF does not exist! ${RES}"
    printf "\n ${YED} ========/// Available interfaces: ${RES}"
    ip link show | awk -F: '$0 !~ "lo|vir|^[^0-9]"{print $2;getline}'
    exit 1
fi

# Detect VPN interfaces
echo -e "----------------------------------------\n  Detecting VPN Interfaces \n----------------------------------------\n "
VPN_INTERFACES=$(ip link show 2>/dev/null | grep -E 'tun|wg|ppp|vpn' | cut -d: -f2 | tr -d ' ' | grep -v '^$')
if [ -n "$VPN_INTERFACES" ]; then
    for vpn_if in $VPN_INTERFACES; do
        printf "\n ${GRL} ========/// Found VPN interface: $vpn_if ${RES}"
    done
    echo ""
else
    printf "\n ${YED} ========/// No VPN interfaces detected ${RES}\n"
fi

# Get Docker bridge interface (docker0)
DOCKER_IF="docker0"
if ! ip link show $DOCKER_IF >/dev/null 2>&1; then
    printf "\n ${YED} ========/// NOTE: Docker bridge interface not found, skipping Docker rules ${RES}\n"
    DOCKER_IF=""
fi

echo -e "----------------------------------------\n  Setting your DNS servers \n----------------------------------------\n "
DNS_SERVER="9.9.9.9 8.8.8.8 1.1.1.1"

echo -e "----------------------------------------\n  Getting Server IP \n----------------------------------------\n "
SERVER_IP="$(ip -4 addr show $NETIF | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
echo -e "$NETIF exists with IP: $SERVER_IP"
printf "\n ${YED} ========/// OK: $NETIF exists with IP: $SERVER_IP... ${RES}\n"

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// KERNEL HARDENING
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
echo -e "----------------------------------------\n  Setting Kernel Parameters for Security \n----------------------------------------\n "

##DROP ICMP echo-requests sent to broadcast/multi-cast addresses.
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

##DROP source routed packets
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
echo 0 > /proc/sys/net/ipv4/conf/default/accept_source_route

##Enable TCP SYN cookies
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

##Do not ACCEPT ICMP redirect
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/default/accept_redirects
echo 0 > /proc/sys/net/ipv4/conf/all/secure_redirects
echo 0 > /proc/sys/net/ipv4/conf/default/secure_redirects

##Don't send ICMP redirect 
echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects
echo 0 > /proc/sys/net/ipv4/conf/default/send_redirects

##Enable source spoofing protection
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
echo 1 > /proc/sys/net/ipv4/conf/default/rp_filter

##Log impossible (martian) packets
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians

# Enable IP forwarding for Docker
echo 1 > /proc/sys/net/ipv4/ip_forward

# Disable IPv6 completely
echo -e "----------------------------------------\n  Disabling IPv6 \n----------------------------------------\n "
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/default/disable_ipv6
echo 1 > /proc/sys/net/ipv6/conf/lo/disable_ipv6

# Ignore ICMP pings
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_all

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// START IPTABLES RULES
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
echo -e "----------------------------------------\n  Flush all existing tables \n----------------------------------------\n "
$IPT -F
$IPT -X
$IPT -t filter -F
$IPT -t filter -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -t raw -F
$IPT -t raw -X
$IPT -t security -F
$IPT -t security -X

# Also flush IPv6 rules
$IP6T -F
$IP6T -X
$IP6T -t filter -F
$IP6T -t filter -X
$IP6T -t nat -F
$IP6T -t nat -X
$IP6T -t mangle -F
$IP6T -t mangle -X
$IP6T -t raw -F
$IP6T -t raw -X
$IP6T -t security -F
$IP6T -t security -X

######---------------------------
echo -e "----------------------------------------\n  Creating default policies \n----------------------------------------\n "
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

# Drop all IPv6 traffic
$IP6T -P INPUT DROP
$IP6T -P OUTPUT DROP
$IP6T -P FORWARD DROP

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES LOOPBACK
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
echo -e "----------------------------------------\n  Allow traffic on loopback \n----------------------------------------\n "
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A INPUT -i lo -j ACCEPT

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// ALLOW ESTABLISHED/RELATED FIRST (CRITICAL)
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
echo -e "----------------------------------------\n  Allow Established Related Connections (EARLY) \n----------------------------------------\n "
# THIS MUST BE EARLY IN THE CHAIN - allows return traffic for all outbound connections
$IPT -A INPUT -i $NETIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Allow established/related connections for VPN interfaces
if [ -n "$VPN_INTERFACES" ]; then
    for vpn_if in $VPN_INTERFACES; do
        $IPT -A INPUT -i $vpn_if -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
        $IPT -A OUTPUT -o $vpn_if -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    done
fi

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// SECURITY RULES SECTION
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
echo -e "----------------------------------------\n  Security Rules - Anti-Scanning Protection \n----------------------------------------\n "

# Create a logging chain for suspicious activity
$IPT -N SCAN_ATTEMPTS
$IPT -A SCAN_ATTEMPTS -m limit --limit 5/min -j LOG --log-prefix "IPTABLES SCAN ATTEMPT: " --log-level 4
$IPT -A SCAN_ATTEMPTS -j DROP

# Block NULL packets (used in Nmap NULL scan)
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j SCAN_ATTEMPTS

# Block XMAS packets (used in Nmap XMAS scan)
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j SCAN_ATTEMPTS

# Block FIN packets without ACK (used in Nmap FIN scan)
$IPT -A INPUT -p tcp --tcp-flags ALL FIN -j SCAN_ATTEMPTS

# Block SYN-FIN packets (another scanning technique)
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j SCAN_ATTEMPTS

# Block SYN-RST packets
$IPT -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j SCAN_ATTEMPTS

# Block FIN-RST packets
$IPT -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j SCAN_ATTEMPTS

# FIXED: Only limit INCOMING new connections, not OUTGOING (relaxed from 1/s to 10/s for normal browsing)
$IPT -A INPUT -p tcp --syn -m limit --limit 10/s --limit-burst 20 -j ACCEPT
$IPT -A INPUT -p tcp --syn -j DROP

# Force SYN packets check - ONLY for INPUT chain
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Packets with incoming fragments drop them
$IPT -A INPUT -f -j DROP

# Drop invalid packets
$IPT -A INPUT -m state --state INVALID -j DROP
$IPT -A OUTPUT -m state --state INVALID -j DROP

# Block broadcast and multicast traffic (except for specific services)
$IPT -A INPUT -m addrtype --dst-type BROADCAST -j DROP
$IPT -A INPUT -m addrtype --dst-type MULTICAST -j DROP
$IPT -A INPUT -m addrtype --dst-type ANYCAST -j DROP

######---------------------------
echo -e "----------------------------------------\n  Granular ICMP Control Rules \n----------------------------------------\n "

# Allow exceptions for trusted IPs to ping this machine
for trusted_ip in "${TRUSTED_PING_IPS[@]}"; do
    echo "Allowing ping from trusted IP: $trusted_ip"
    $IPT -A INPUT -p icmp --icmp-type echo-request -s $trusted_ip -j ACCEPT
done

# Allow essential ICMP types (required for proper network operation)
$IPT -A INPUT  -p icmp --icmp-type destination-unreachable -j ACCEPT   # Needed for Path MTU discovery
$IPT -A OUTPUT -p icmp --icmp-type destination-unreachable -j ACCEPT

$IPT -A INPUT  -p icmp --icmp-type time-exceeded -j ACCEPT             # Needed for Traceroute
$IPT -A OUTPUT -p icmp --icmp-type time-exceeded -j ACCEPT

$IPT -A INPUT  -p icmp --icmp-type parameter-problem -j ACCEPT         # Needed for packet error reporting
$IPT -A OUTPUT -p icmp --icmp-type parameter-problem -j ACCEPT

# Allow outgoing ping (when you initiate it)
$IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A INPUT  -p icmp --icmp-type echo-reply -j ACCEPT

# Block all other incoming pings (kernel setting already blocks, but for logging)
$IPT -A INPUT  -p icmp --icmp-type echo-request -j SCAN_ATTEMPTS

# Rate limit remaining ICMP to prevent flooding
$IPT -A INPUT -p icmp -m limit --limit 1/sec --limit-burst 5 -j ACCEPT
$IPT -A INPUT -p icmp -j DROP

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES DNS
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
echo -e "----------------------------------------\n  Allow DNS Requests \n----------------------------------------\n "

# Allow DNS to any server (for resolving all domains) - consolidated single rule
$IPT -A OUTPUT -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// VPN SUPPORT
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

echo -e "----------------------------------------\n  Allow VPN Connections \n----------------------------------------\n"

# OpenVPN
$IPT -A OUTPUT -o $NETIF -p udp --dport 1194 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p tcp --dport 1194 -m state --state NEW,ESTABLISHED -j ACCEPT

# WireGuard
$IPT -A OUTPUT -o $NETIF -p udp --dport 51820 -m state --state NEW,ESTABLISHED -j ACCEPT

# Custom FortiGate VPN port
$IPT -A OUTPUT -o $NETIF -p tcp --dport 10443 -m state --state NEW,ESTABLISHED -j ACCEPT

# IPSec/IKEv2 (common for corporate VPNs)
$IPT -A OUTPUT -o $NETIF -p udp --dport 500 -m state --state NEW,ESTABLISHED -j ACCEPT   # IKE
$IPT -A OUTPUT -o $NETIF -p udp --dport 4500 -m state --state NEW,ESTABLISHED -j ACCEPT  # IPSec NAT-T
$IPT -A OUTPUT -o $NETIF -p esp -j ACCEPT  # ESP protocol

# PPTP VPN
$IPT -A OUTPUT -o $NETIF -p tcp --dport 1723 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p gre -j ACCEPT

# Allow all traffic through VPN interfaces (when connected)
if [ -n "$VPN_INTERFACES" ]; then
    for vpn_if in $VPN_INTERFACES; do
        echo "Configuring firewall rules for VPN interface: $vpn_if"
        $IPT -A INPUT -i $vpn_if -j ACCEPT
        $IPT -A OUTPUT -o $vpn_if -j ACCEPT
    done
fi

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// DOCKER NETWORKING RULES
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
if [ -n "$DOCKER_IF" ]; then
    echo -e "----------------------------------------\n  Setting up Docker Networking Rules \n----------------------------------------\n "
    
    # Allow Docker containers to communicate with host (more restrictive)
    $IPT -A INPUT -i $DOCKER_IF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT -A OUTPUT -o $DOCKER_IF -j ACCEPT
    
    # Allow Docker containers to communicate with external world
    $IPT -A FORWARD -i $DOCKER_IF -o $NETIF -j ACCEPT
    $IPT -A FORWARD -i $NETIF -o $DOCKER_IF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # Allow Docker containers to communicate with each other
    $IPT -A FORWARD -i $DOCKER_IF -o $DOCKER_IF -j ACCEPT
    
    # NAT for Docker containers
    $IPT -t nat -A POSTROUTING -s 172.17.0.0/16 ! -o $DOCKER_IF -j MASQUERADE
    
    printf "\n ${GRD} ========/// Docker networking rules configured for interface $DOCKER_IF ${RES}\n"
fi

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES LOGGING
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
echo -e "----------------------------------------\n  Logging and Dropping Unwanted Traffic \n----------------------------------------\n "
$IPT -N LOGNDROP
$IPT -A LOGNDROP -m limit --limit 5/min -j LOG --log-prefix "IPTABLES DROP: " --log-level 4
$IPT -A LOGNDROP -j DROP

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES VARIOUS SERVICES (CONSOLIDATED - NO DUPLICATES)
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

echo -e "----------------------------------------\n  Allow DHCP \n----------------------------------------\n "
$IPT -A OUTPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT
$IPT -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow Outbound Services \n----------------------------------------\n "

# FTP (port 21)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT

# SSH (port 22)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT

# SMTP (port 25)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT

# HTTP (port 80)
$IPT -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT

# HTTPS (port 443)
$IPT -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

# IMAP (port 143)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT

# SMTPS (port 465)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 465 -m state --state NEW,ESTABLISHED -j ACCEPT

# Submission (port 587) - for sending emails with authentication
$IPT -A OUTPUT -o $NETIF -p tcp --dport 587 -m state --state NEW,ESTABLISHED -j ACCEPT

# IMAPS (port 993)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 993 -m state --state NEW,ESTABLISHED -j ACCEPT

# POP3 (port 110)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 110 -m state --state NEW,ESTABLISHED -j ACCEPT

# POP3S (port 995)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 995 -m state --state NEW,ESTABLISHED -j ACCEPT

# MySQL (port 3306)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 3306 -m state --state NEW,ESTABLISHED -j ACCEPT

# RDP (port 3389)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 3389 -m state --state NEW,ESTABLISHED -j ACCEPT

# NTP (Network Time Protocol - port 123)
$IPT -A OUTPUT -o $NETIF -p udp --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT

# mDNS/Avahi (port 5353) - for local network service discovery
$IPT -A OUTPUT -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT
$IPT -A INPUT -p udp --sport 5353 -j ACCEPT

# CUPS Printing (port 631)
$IPT -A OUTPUT -p tcp --dport 631 -j ACCEPT
$IPT -A OUTPUT -p udp --dport 631 -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow Non-Standard Web Ports \n----------------------------------------\n "
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8080 -j ACCEPT   # Alternative HTTP
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8443 -j ACCEPT   # Alternative HTTPS
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8096 -j ACCEPT   # Jellyfin server

######---------------------------
echo -e "----------------------------------------\n  Allow Specialized Services \n----------------------------------------\n "

# Proxmox (port 8006)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8006 -m state --state NEW,ESTABLISHED -j ACCEPT

# cPanel/WHM ports
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2087 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2083 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2096 -m state --state NEW,ESTABLISHED -j ACCEPT

# VNC OpenNebula (port 7952)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 7952 -m state --state NEW,ESTABLISHED -j ACCEPT

# Dremio (port 9047)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 9047 -m state --state NEW,ESTABLISHED -j ACCEPT

# TOR Relay Network (port 9050)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 9050 -m state --state NEW,ESTABLISHED -j ACCEPT

# Webuzo (ports 2004-2005)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2004 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2005 -m state --state NEW,ESTABLISHED -j ACCEPT

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES BLOCK IPADDR SECTION
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
echo -e "----------------------------------------\n  Blocking specific IPADDRS \n----------------------------------------\n "
#BLOCK_THESE_IPS="192.168.0.243"
#for blockip in $BLOCK_THESE_IPS; do
#    $IPT -A INPUT -s $blockip -j DROP
#done

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// FINAL LOGGING RULES
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

echo -e "----------------------------------------\n  Enabling Final Logging Rules \n----------------------------------------\n "
# Log remaining dropped INPUT packets
$IPT -A INPUT -m limit --limit 3/min -j LOG --log-prefix "IPTABLES INPUT DROP: " --log-level 4
$IPT -A INPUT -j DROP

# Log remaining dropped OUTPUT packets
$IPT -A OUTPUT -m limit --limit 3/min -j LOG --log-prefix "IPTABLES OUTPUT DROP: " --log-level 4
$IPT -A OUTPUT -j DROP

####################################################################################################
####################################################################################################
#####-----/// END IPTABLES SCRIPT
####################################################################################################
####################################################################################################
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n ${RED} ========/// DONT FORGET TO SAVE YOUR RULES FOR THE REBOOT ${RES}" 
printf "\n ========/// EOF SCRIPT ${RES}" 
printf "\n ========/// ------------------------------------------------------------------------------------"
printf "\n ========/// apt-get install iptables-persistent"
printf "\n ========/// ------------------------------------------------------------------------------------"
printf "\n ========/// #Save current rules:"
printf "\n ========/// iptables-save > /etc/iptables/rules.v4"
printf "\n ========/// ip6tables-save > /etc/iptables/rules.v6"
printf "\n ========/// ------------------------------------------------------------------------------------"
printf "\n ========/// #if you want to load at reboot or make sure crontab -- is set or run with iptables-save or netfilter persistent"
printf "\n ========/// #every 30 minutes"
printf "\n ========/// */30 * * * * /sbin/iptables-restore < /etc/iptables/rules.v4 2>&1 | logger -t iptables-restore"
printf "\n ========/// */30 * * * * /usr/sbin/netfilter-persistent reload 2>&1 | logger -t netfilter-persistent"
printf "\n ========/// @reboot /sbin/iptables-restore < /etc/iptables/rules.v4 2>&1 | logger -t iptables-restore"
printf "\n ========/// @reboot /usr/sbin/netfilter-persistent reload 2>&1 | logger -t netfilter-persistent"
printf "\n ========/// ------------------------------------------------------------------------------------"
printf "\n ${YED} iptables -L -n  # Verify rules loaded ${RES}"
printf "\n ${YED} grep -E 'iptables|netfilter' /var/log/syslog  # Check for errors ${RES}"
printf "\n ${YED} systemctl enable netfilter-persistent  # Ensures it loads at boot ${RES}"
printf "\n ${YED} systemctl start netfilter-persistent  # Loads it now ${RES}"
printf "\n ========/// ------------------------------------------------------------------------------------"
printf "\n ${GRL} ========/// ACTIVE VPN INTERFACES: ${VPN_INTERFACES:-None detected} ${RES}"
printf "\n ${GRL} ========/// BACKUP SAVED TO: $BACKUP_FILE ${RES}"
printf "\n ========/// ------------------------------------------------------------------------------------"
printf "\n ${YED} ======================================================================================================================= ${RES}\n"
