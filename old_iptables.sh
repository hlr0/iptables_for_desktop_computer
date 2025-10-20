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
    echo ""
    echo "Examples:"
    echo "  $0 -n eno2      Run with eno2 as network interface"
    echo "  $0 --clean      Flush all iptables rules"
    echo "  $0 --help       Display this help message"
    echo ""
    echo "Note: This script must be run with root privileges"
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

    # Flush all rules
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
    
    # Set default policies
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
    
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
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
    shift
done

#================================================================
# MAIN SCRIPT
#================================================================
echo -e "----------------------------------------\n  Using Network Interface: $NETIF \n----------------------------------------\n "

# Check if network interface exists
if ! ip link show $NETIF >/dev/null 2>&1; then
    printf "\n ${RED} ========/// ERROR: Network interface $NETIF does not exist! ${RES}"
    printf "\n ${YED} ========/// Available interfaces: ${RES}"
    ip link show | awk -F: '$0 !~ "lo|vir|^[^0-9]"{print $2;getline}'
    exit 1
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
#Setting up default kernel tunings here (don't worry too much about these right now, they are acceptable defaults) 
echo -e "----------------------------------------\n  Setting Kernel Parameters for Security \n----------------------------------------\n "
##DROP ICMP echo-requests sent to broadcast/multi-cast addresses.
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
##DROP source routed packets
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
##Enable TCP SYN cookies
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
##Do not ACCEPT ICMP redirect
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
##Don't send ICMP redirect 
echo 0 >/proc/sys/net/ipv4/conf/all/send_redirects
##Enable source spoofing protection
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
##Log impossible (martian) packets
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians

# Enable IP forwarding for Docker
echo 1 > /proc/sys/net/ipv4/ip_forward

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

######---------------------------
echo -e "----------------------------------------\n  Creating default policies \n----------------------------------------\n "
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP

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

# Block FIN packets (used in Nmap FIN scan)
$IPT -A INPUT -p tcp --tcp-flags ALL FIN -j SCAN_ATTEMPTS

# Block SYN-FIN packets (another scanning technique)
$IPT -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j SCAN_ATTEMPTS

# Limit new connections to prevent scanning
$IPT -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
$IPT -A INPUT -p tcp --syn -j DROP

# Force SYN packets check
$IPT -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

# Packets with incoming fragments drop them
$IPT -A INPUT -f -j DROP

# Limit DDOS Attacks
$IPT -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 5 -j ACCEPT
$IPT -A INPUT -p tcp --syn -j DROP

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

# Explicitly block echo requests (ping) but allow replies
$IPT -A INPUT  -p icmp --icmp-type echo-request -j SCAN_ATTEMPTS       # Block incoming pings and log
$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT                # Allow ping replies if we initiate

# Allow outgoing ping if needed (uncomment if you want to ping others)
$IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT

# Rate limit remaining ICMP to prevent flooding
$IPT -A INPUT -p icmp -m limit --limit 1/sec --limit-burst 5 -j ACCEPT
$IPT -A INPUT -p icmp -j DROP

# Block all other ICMP types not explicitly allowed
$IPT -A OUTPUT -p icmp -j DROP

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES DNS
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
echo -e "----------------------------------------\n  Allow DNS Requests \n----------------------------------------\n "

for dnsip in $DNS_SERVER; do
    $IPT -A OUTPUT -p udp -o $NETIF -d $dnsip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p udp -i $NETIF -s $dnsip --sport 53 -m state --state ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp -o $NETIF -d $dnsip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p tcp -i $NETIF -s $dnsip --sport 53 -m state --state ESTABLISHED -j ACCEPT
done

# Allow DNS to any server (for resolving all domains)
$IPT -A OUTPUT -p udp -o $NETIF --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p udp -i $NETIF --sport 53 -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -o $NETIF --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp -i $NETIF --sport 53 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow Established Related Connections \n----------------------------------------\n "
$IPT -A OUTPUT -o $NETIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i $NETIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// DOCKER NETWORKING RULES
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
if [ -n "$DOCKER_IF" ]; then
    echo -e "----------------------------------------\n  Setting up Docker Networking Rules \n----------------------------------------\n "
    
    # Allow Docker containers to communicate with host
    $IPT -A INPUT -i $DOCKER_IF -j ACCEPT
    $IPT -A OUTPUT -o $DOCKER_IF -j ACCEPT
    
    # Allow Docker containers to communicate with external world
    $IPT -A FORWARD -i $DOCKER_IF -o $NETIF -j ACCEPT
    $IPT -A FORWARD -i $NETIF -o $DOCKER_IF -j ACCEPT
    
    # Allow established/related connections
    $IPT -A FORWARD -i $DOCKER_IF -o $NETIF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    $IPT -A FORWARD -i $NETIF -o $DOCKER_IF -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    
    # NAT for Docker containers
    $IPT -t nat -A POSTROUTING -o $NETIF -j MASQUERADE
    
    # Allow Docker containers to communicate with each other
    $IPT -A FORWARD -i $DOCKER_IF -o $DOCKER_IF -j ACCEPT
    
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

# Uncomment the following line to send all remaining unmatched traffic to logging
# $IPT -A INPUT -j LOGNDROP
# $IPT -A OUTPUT -j LOGNDROP

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES VARIOUS SERVICES
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

echo -e "----------------------------------------\n  Allow DHCP \n----------------------------------------\n "
$IPT -A OUTPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT
$IPT -A INPUT -p udp --dport 67:68 --sport 67:68 -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow outgoing SSH \n----------------------------------------\n "
$IPT -A OUTPUT -o $NETIF -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow outgoing HTTP and HTTPS \n----------------------------------------\n "
$IPT -A OUTPUT -p tcp -o $NETIF --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp -i $NETIF --sport 80 -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -o $NETIF --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp -i $NETIF --sport 443 -m state --state ESTABLISHED -j ACCEPT

# Allow HTTP/HTTPS to any destination (not just specific ports)
$IPT -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow outgoing RDP Connections \n----------------------------------------\n "
$IPT -A OUTPUT -o $NETIF -p tcp --dport 3389 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 3389 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow Proxmox PORT \n----------------------------------------\n"
# Allow outbound Proxmox (TCP 8006)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8006 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -i $NETIF -p tcp --sport 8006 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow Email Client Protocols (POP3/IMAP) \n----------------------------------------\n "
# POP3 (port 110)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 110 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 110 -m state --state ESTABLISHED -j ACCEPT

# POP3S (port 995)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 995 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 995 -m state --state ESTABLISHED -j ACCEPT

# IMAP (port 143)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 143 -m state --state ESTABLISHED -j ACCEPT

# IMAPS (port 993)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 993 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 993 -m state --state ESTABLISHED -j ACCEPT

# SMTP (port 25) - for sending emails
$IPT -A OUTPUT -o $NETIF -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

# Submission (port 587) - for sending emails with authentication
$IPT -A OUTPUT -o $NETIF -p tcp --dport 587 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 587 -m state --state ESTABLISHED -j ACCEPT

# SMTPS (port 465) - Secure SMTP
$IPT -A OUTPUT -o $NETIF -p tcp --dport 465 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 465 -m state --state ESTABLISHED -j ACCEPT

# SMTPS (port 2087 and 2083 and 2096) - Secure CPANEL WHM Systems
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2087 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2083 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2096 -m state --state NEW,ESTABLISHED -j ACCEPT

# NON-STANDARD PORT FOR WEBSERVERS
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8080 -j ACCEPT 
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8443 -j ACCEPT #non-privelege port for secure https
$IPT -A OUTPUT -o $NETIF -p tcp --dport 8096 -j ACCEPT #8096 is jellyfin server

# VNC (port 7952) - OPENNEBULA
$IPT -A OUTPUT -o $NETIF -p tcp --dport 7952 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 7952 -m state --state ESTABLISHED -j ACCEPT

# DREMIO (port 9047) - DREMIO
$IPT -A OUTPUT -o $NETIF -p tcp --dport 9047 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 9047 -m state --state ESTABLISHED -j ACCEPT

#NTP (Network Time Protocol)
$IPT -A OUTPUT -o $NETIF -p udp --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p udp --sport 123 -m state --state ESTABLISHED -j ACCEPT

#TOR RELAY NETWORK
$IPT -A OUTPUT -o $NETIF -p tcp --dport 9050 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 9050 -m state --state ESTABLISHED -j ACCEPT

#WABUZO
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2004 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 2004 -m state --state ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $NETIF -p tcp --dport 2005 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 2005 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Allow Basic Services Ports \n----------------------------------------\n "
# FTP (port 21)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 21 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 21 -m state --state ESTABLISHED -j ACCEPT

# SSH (port 22)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# SMTP (port 25)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 25 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 25 -m state --state ESTABLISHED -j ACCEPT

# DNS (port 53) - UDP
$IPT -A OUTPUT -o $NETIF -p udp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p udp --sport 53 -m state --state ESTABLISHED -j ACCEPT
# DNS (port 53) - TCP
$IPT -A OUTPUT -o $NETIF -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT

# HTTP (port 80)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

# HTTPS (port 443)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

# IMAP (port 143)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 143 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 143 -m state --state ESTABLISHED -j ACCEPT

# SMTPS (port 465)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 465 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 465 -m state --state ESTABLISHED -j ACCEPT

# IMAPS (port 993)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 993 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 993 -m state --state ESTABLISHED -j ACCEPT

# MySQL (port 3306)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 3306 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 3306 -m state --state ESTABLISHED -j ACCEPT

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// IPTABLES VPN PORTS
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

echo -e "----------------------------------------\n  Allow OPENVPN PORT \n----------------------------------------\n"
# Allow outbound VPN connection (UDP 1194)
$IPT -A OUTPUT -o $NETIF -p udp --dport 1194 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -i $NETIF -p udp --sport 1194 -m state --state ESTABLISHED -j ACCEPT
# Allow fallback TCP/443 (if OpenVPN uses TCP mode or for TLS)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -i $NETIF -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

echo -e "----------------------------------------\n  Allow CUSTOM FORTIGATE PORT \n----------------------------------------\n"
# Allow fallback TCP/443 (if OpenVPN uses TCP mode or for TLS)
$IPT -A OUTPUT -o $NETIF -p tcp --dport 10443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -i $NETIF -p tcp --sport 10443 -m state --state ESTABLISHED -j ACCEPT

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
printf "\n ${YED} Check logs for any scan attempts -- grep 'IPTABLES SCAN ATTEMPT' /var/log/syslog ${RES}"
printf "\n ========/// ------------------------------------------------------------------------------------"
printf "\n ${YED} ======================================================================================================================= ${RES}"
printf "\n"
