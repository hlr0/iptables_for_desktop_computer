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
# 
#================================================================
#  DEBUG OPTION
#    set -n  # Uncomment to check your syntax, without execution.
#    set -x  # Uncomment to debug this shell script
#
#================================================================
#  REVERT OPTION - if you cannot access the internet anymore
#    iptables -F
#    iptables -X
#    iptables -P INPUT ACCEPT
#    iptables -P OUTPUT ACCEPT
#    iptables -P FORWARD ACCEPT
#
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
######-----/// SETTINGS
######---------------------------------------------------------------------------------
echo -e "------------\n Setting Network Cards \n------------\n"
NETIF_0="eth0"  # Update to use your first network card
NETIF_1="eth1"  # Update to use your second network card



######---------------------------
echo -e "------------\n Setting your DNS servers \n------------\n"
DNS_SERVER="9.9.9.9 8.8.8.8 1.1.1.1"



######---------------------------
echo -e "------------\n Getting Server IP \n------------\n"
SERVER_IP_0="$(ip -4 addr show $NETIF_0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
SERVER_IP_1="$(ip -4 addr show $NETIF_1 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"

######---------------------------------------------------------------------------------
######-----/// START IPTABLES RULES
######---------------------------------------------------------------------------------
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
####################################################################################################
#####-----/// END IPTABLES SCRIPT
####################################################################################################
####################################################################################################
echo -e "######---------------------------------------------------------------------------------\n"
echo -e "######-----/// DONT FORGET TO SAVE YOUR RULES FOR THE REBOOT\n"
echo -e "######-----/// EOF SCRIPT\n"
echo -e "######---------------------------------------------------------------------------------\n"
exit 0
