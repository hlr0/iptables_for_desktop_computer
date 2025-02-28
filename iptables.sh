#!/bin/bash
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo "
    dMP dMMMMb dMMMMMMP .aMMMb  dMMMMb  dMP     dMMMMMP .dMMMb  
   amr dMP.dMP   dMP   dMP"dMP dMP"dMP dMP     dMP     dMP" VP  
  dMP dMMMMP"   dMP   dMMMMMP dMMMMK" dMP     dMMMP    VMMMb    
 dMP dMP       dMP   dMP dMP dMP.aMF dMP     dMP     dP .dMP    
dMP dMP       dMP   dMP dMP dMMMMP" dMMMMMP dMMMMMP  VMMMP"     
                                                                
    dMMMMMP dMP dMMMMb  dMMMMMP dMP dMP dMP .aMMMb  dMP     dMP 
   dMP     amr dMP.dMP dMP     dMP dMP dMP dMP"dMP dMP     dMP  
  dMMMP   dMP dMMMMK" dMMMP   dMP dMP dMP dMMMMMP dMP     dMP   
 dMP     dMP dMP"AMF dMP     dMP.dMP.dMP dMP dMP dMP     dMP    
dMP     dMP dMP dMP dMMMMMP  VMMMPVMMP" dMP dMP dMMMMMP dMMMMMP 
"    
echo -e "######-----/// Basic Script to Setup Iptables rules for your Desktop (Everyday Box)"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"

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
#%    -h, --help                    Display this help message
#%    -c, --clean                   Will Revert all changes and flush
#%                                  the iptables rules, chains, tables allowing
#%                                  to start from a clean slate or to
#%                                  revert any changes made to the system
#%
#% EXAMPLES
#%    ${iptables.sh} [--help|--clean]
#%
#================================================================
#- IMPLEMENTATION
#-    version         ${iptables.sh} 0.0.6
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
#     2025/02/27 : Me : Added help function
#     2025/02/27 : Me : Added POP3/IMAP rules for email clients
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
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// FUNCTIONS
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------

######---------------------------
# Help function
show_help() {
    echo "Iptables Script for Desktop Computer Setup"
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -h, --help     Show this help message and exit"
    echo "  -c, --clean    Revert all changes and flush the iptables rules,"
    echo "                 chains, and tables allowing to start from a clean"
    echo "                 slate or to revert any changes made to the system"
    echo ""
    echo "Examples:"
    echo "  $0             Run the script with default firewall rules"
    echo "  $0 --clean     Flush all iptables rules and set default policies to ACCEPT"
    echo "  $0 --help      Display this help message"
    echo ""
    echo "Note: This script must be run with root privileges"
    exit 0
}

######---------------------------
# Clean function
clean_iptables() {
    echo -e "\n\n"
    echo -e "######--------------------------------------------------------------------------------------------------"
    echo -e "######--------------------------------------------------------------------------------------------------"
    echo -e "######--------------------------------------------------------------------------------------------------"
    echo -e "######-----/// CLEAN SLATE PROTOCOL START"
    echo -e "######--------------------------------------------------------------------------------------------------"
    echo -e "######--------------------------------------------------------------------------------------------------"
    echo -e "######--------------------------------------------------------------------------------------------------"
    $IPT -F
    $IPT -X
    $IPT -P INPUT ACCEPT
    $IPT -P OUTPUT ACCEPT
    $IPT -P FORWARD ACCEPT
    $IPT -nvL
    echo -e "\n------------------------------------------------- Finished Clean Slate Protocol-------------------------------------------------"
    exit 0
}

######---------------------------
# Parse command line arguments
case "$1" in
    --help|-h)
        show_help
        ;;
    --clean|-c)
        clean_iptables
        ;;
esac

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// SETTINGS
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
echo -e "----------------------------------------\n  Setting Network Cards \n----------------------------------------\n "
NETIF="eth0"  # Update to use your first network card

######---------------------------
echo -e "----------------------------------------\n  Setting your DNS servers \n----------------------------------------\n "
DNS_SERVER="9.9.9.9 8.8.8.8 1.1.1.1"

######---------------------------
echo -e "----------------------------------------\n  Getting Server IP and Check Network Cards \n----------------------------------------\n "
if ip link show $NETIF >/dev/null 2>&1; then
    SERVER_IP="$(ip -4 addr show $NETIF | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
    echo -e "$NETIF exists with IP: $SERVER_IP"
else
    echo -e "$NETIF does not exist"
    echo -e "Please set up network card then try again."
    exit 0
fi
echo -e "\n"

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// KERNEL HARDENING
######---------------------------------------------------------------------------------
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

######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######---------------------------------------------------------------------------------
######-----/// START IPTABLES RULES
######---------------------------------------------------------------------------------
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

######---------------------------
echo -e "----------------------------------------\n  Allow traffic on loopback \n----------------------------------------\n "
$IPT -A OUTPUT -o lo -j ACCEPT
$IPT -A INPUT -i lo -j ACCEPT

######---------------------------
echo -e "----------------------------------------\n  Ping ICMP from inside to outside \n----------------------------------------\n "
$IPT -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-reply -j ACCEPT

echo -e "----------------------------------------\n  Ping ICMP from outside to inside \n----------------------------------------\n "
$IPT -A OUTPUT -p icmp --icmp-type echo-reply -j ACCEPT
$IPT -A INPUT -p icmp --icmp-type echo-request -j ACCEPT

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

# Add DHCP section after DNS section
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

######---------------------------
echo -e "----------------------------------------\n  Allow outgoing RDP Connections \n----------------------------------------\n "
$IPT -A OUTPUT -o $NETIF -p tcp --dport 3389 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF -p tcp --sport 3389 -m state --state ESTABLISHED -j ACCEPT

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

######---------------------------
echo -e "----------------------------------------\n  Prevent DoS attack \n----------------------------------------\n "
$IPT -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 5 -j ACCEPT
$IPT -A INPUT -p tcp --syn -j DROP

######---------------------------
echo -e "----------------------------------------\n  Logging and Dropping Unwanted Traffic \n----------------------------------------\n "
$IPT -N LOGNDROP
$IPT -A LOGNDROP -m limit --limit 5/min -j LOG --log-prefix "IPTABLES DROP: " --log-level 4
$IPT -A LOGNDROP -j DROP

# Uncomment the following line to send all remaining unmatched traffic to logging
# $IPT -A INPUT -j LOGNDROP
# $IPT -A OUTPUT -j LOGNDROP

####################################################################################################
#####-----/// BLOCK IPADDR SECTION
######---------------------------
echo -e "----------------------------------------\n  Blocking specific IPADDRS \n----------------------------------------\n "
#BLOCK_THESE_IPS="192.168.0.243"
#for blockip in $BLOCK_THESE_IPS
#   $IPT -A INPUT -s $blockip -j DROP
#do

####################################################################################################
####################################################################################################
#####-----/// END IPTABLES SCRIPT
####################################################################################################
####################################################################################################
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-----/// DONT FORGET TO SAVE YOUR RULES FOR THE REBOOT"
echo -e "######-----/// EOF SCRIPT"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"
echo -e "######-------------------------------------------------------------------------------------------------------------"
exit 0
