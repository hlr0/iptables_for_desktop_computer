#!/bin/bash
#================================================================
# HEADER
#================================================================
#% SYNOPSIS
#+    ${iptables.sh}
#%
#% DESCRIPTION
#%    This is a Iptables Script for setup of Desktop Computer - Everyday
#%    Ping, dns, dhcp, ssh, http, https, working and will set establish and new connection
#%    Adjust the script to add your own dns servers and network cards
#%
#% OPTIONS
#%    -c, --clean                   Will Revert all changes and flush
#%                                  the iptables rules, chains, tables allowing
#%                                  to start from a clean slate or to
#%                                  revert any changes made to the system
#%
#% EXAMPLES
#%    ${iptables.sh} [--clean]
#%
#================================================================
#- IMPLEMENTATION
#-    version         ${iptables.sh} 0.0.4
#-    author          Some Dude that thinks iptables is cool
#-    copyright       Copyright (c) Free For All
#-    license         GNU General Public License
#-    script_id       12345
#-
#================================================================
#  HISTORY
#     2025/02/25 : Me : Script creation
#     2025/02/26 : Me : Added kernel hardening 
#     2025/02/27 : Me : Added header and settings
#     2025/02/27 : Me : Added various iptables rules 
#     2025/02/27 : Me : Added block ipaddr iptables rules 
#     2025/02/27 : Me : Added revert changes
#
#================================================================
#  LOGS LOCATION
#    LOGS IPTABLES: Ubuntu / Kali / Debian:  grep "IPTABLES DROP:" /var/log/syslog
#    LOGS IPTABLES: Centos / AlmaLinux / RedHat:  grep "IPTABLES DROP:" /var/log/messages
#
#================================================================
#  DEBUG OPTION
#    set -n  # Uncomment to check your syntax, without execution.
#    set -x  # Uncomment to debug this shell script
#
#================================================================
#- OS SAVE OR RESTORE RULES
#- Use these commands to save or restore iptables rules before reboot.
#- You can specify IPv4 or IPv6 rules as needed.
#- 
#- 
#- RED HAT:
#- Save:    iptables-save > /etc/sysconfig/iptables
#- Restore: iptables-restore < /etc/sysconfig/iptables
#- 
#-
#-UBUNTU (24.04) OR KALI (2024.3):
#- Save:    
#- iptables-save > /etc/iptables/rules.v4
#- ip6tables-save > /etc/iptables/rules.v6
#-
#- Restore: 
#- iptables-restore < /etc/iptables/rules.v4
#- ip6tables-restore < /etc/iptables/rules.v6
#-
#================================================================
# END_OF_HEADER
#================================================================
####################################################################################################
####################################################################################################
#####-----/// START IPTABLES SCRIPT
####################################################################################################
####################################################################################################
#Setting the default iptables super bin file
IPT="/sbin/iptables"


######---------------------------------------------------------------------------------
######-----/// SETTINGS
######---------------------------------------------------------------------------------
echo -e "------------\n Setting Network Cards \n------------\n"
NETIF_0="eth0"  # Update to use your first network card
NETIF_1="eth1"  # Update to use your second network card

######---------------------------
echo -e "------------\n Setting your DNS servers \n------------\n"
DNS_SERVER="9.9.9.9 8.8.8.8 1.1.1.1"

######---------------------------
echo -e "------------\n Getting Server IP and Check Network Cards \n------------\n"
if ip link show $NETIF_0 >/dev/null 2>&1; then
    SERVER_IP_0="$(ip -4 addr show $NETIF_0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
    echo -e "$NETIF_0 exists with IP: $SERVER_IP_0"
else
    echo -e "$NETIF_0 does not exist"
    SERVER_IP_0=""
fi

if ip link show $NETIF_1 >/dev/null 2>&1; then
    SERVER_IP_1="$(ip -4 addr show $NETIF_1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
    echo -e "$NETIF_1 exists with IP: $SERVER_IP_1"
else
    echo -e "$NETIF_1 does not exist"
    SERVER_IP_1=""
fi

######---------------------------------------------------------------------------------
######-----/// FUNCTIONS
######---------------------------------------------------------------------------------
######---------------------------
if [[ "$1" == "--clean" || "$1" == "-c" ]]; then
    echo -e "---------------------\n CLEAN SLATE PROTOCOL START \n----------------------------\n"
    $IPT -F
    $IPT -X
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
    exit 0
fi


######---------------------------------------------------------------------------------
######-----/// KERNEL HARDENING
######---------------------------------------------------------------------------------
#Setting up default kernel tunings here (don't worry too much about these right now, they are acceptable defaults) 
echo -e "------------\n Setting Kernel Parameters for Security \n------------\n"
#DROP ICMP echo-requests sent to broadcast/multi-cast addresses.
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts
#DROP source routed packets
echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route
#Enable TCP SYN cookies
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
#Do not ACCEPT ICMP redirect
echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects
#Don't send ICMP redirect 
echo 0 >/proc/sys/net/ipv4/conf/all/send_redirects
#Enable source spoofing protection
echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter
#Log impossible (martian) packets
echo 1 > /proc/sys/net/ipv4/conf/all/log_martians

######---------------------------------------------------------------------------------
######-----/// START IPTABLES RULES
######---------------------------------------------------------------------------------

######---------------------------
echo -e "------------\n Flush all existing tables \n------------\n"
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
echo -e "------------\n Creating default policies \n------------\n"
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP
$IPT -P PREROUTING DROP
$IPT -P POSTROUTING DROP

######---------------------------
echo -e "------------\n Allow traffic on loopback \n------------\n"
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

######---------------------------
echo -e "------------\n Ping ICMP from inside to outside \n------------\n"
$IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

echo -e "------------\n Ping ICMP from outside to inside \n------------\n"
$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT

######---------------------------
echo -e "------------\n Allow DNS Requests \n------------\n"
for dnsip in $DNS_SERVER; do
    $IPT -A OUTPUT -p udp -d $dnsip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p udp -s $dnsip --sport 53 -m state --state ESTABLISHED -j ACCEPT
    $IPT -A OUTPUT -p tcp -d $dnsip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p tcp -s $dnsip --sport 53 -m state --state ESTABLISHED -j ACCEPT
done

######---------------------------
echo -e "------------\n Allow Established Connections \n------------\n"
$IPT -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

######---------------------------
echo -e "------------\n Allow outgoing SSH \n------------\n"
$IPT -A OUTPUT -o $NETIF_0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF_0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "------------\n Allow HTTP and HTTPS \n------------\n"
$IPT -A OUTPUT -p tcp -o $NETIF_0 --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -o $NETIF_0 --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT

######---------------------------
echo -e "------------\n Prevent DoS attack \n------------\n"
$IPT -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 5 -j ACCEPT
$IPT -A INPUT -p tcp --syn -j DROP

######---------------------------
echo -e "------------\n Logging and Dropping Unwanted Traffic \n------------\n"
$IPT -N LOGNDROP
$IPT -A LOGNDROP -m limit --limit 5/min -j LOG --log-prefix "IPTABLES DROP: " --log-level 4
$IPT -A LOGNDROP -j DROP

$IPT -A INPUT -j LOGNDROP
$IPT -A OUTPUT -j LOGNDROP


####################################################################################################
#####-----/// BLOCK IPADDR SECTION
######---------------------------
#echo "Blocking specific IPADDRS"
#BLOCK_THESE_IPS="x.x.x.x x.x.x.x x.x.x.x"
#for blockip in $BLOCK_THESE_IPS
    #$IPT -A INPUT -s $blockip -j DROP
#do

####################################################################################################
####################################################################################################
#####-----/// END IPTABLES SCRIPT
####################################################################################################
####################################################################################################
echo -e "######---------------------------------------------------------------------------------\n"
echo -e "######-----/// DONT FORGET TO SAVE YOUR RULES FOR THE REBOOT\n"
echo -e "######-----/// EOF SCRIPT\n"
echo -e "######---------------------------------------------------------------------------------\n"
exit 0
