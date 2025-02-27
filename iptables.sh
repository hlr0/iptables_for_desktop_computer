#!/bin/bash
IPT="/sbin/iptables"

# Server IP
SERVER_IP="$(ip addr show enp1s0 | grep 'inet ' | cut -f2 | awk '{ print $2}')"

# Your DNS servers you use: cat /etc/resolv.conf
DNS_SERVER="9.9.9.9 8.8.8.8 1.1.1.1"

# Allow connections to this package servers
PACKAGE_SERVER="ftp.us.debian.org security.debian.org"

echo "flush iptable rules"
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

echo "Set default policy to 'DROP'"
$IPT -P INPUT DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT DROP
$IPT -P PREROUTING DROP
$IPT -P POSTROUTING DROP

## This should be one of the first rules.
## so dns lookups are already allowed for your other rules
for ip in $DNS_SERVER
do
	echo "Allowing DNS lookups (tcp, udp port 53) to server '$ip'"
	$IPT -A OUTPUT -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p udp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
	$IPT -A OUTPUT -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
done

echo "allow all and everything on localhost"
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

for ip in $PACKAGE_SERVER
do
	echo "Allow connection to '$ip' on port 21"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 21  -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 21  -m state --state ESTABLISHED     -j ACCEPT

	echo "Allow connection to '$ip' on port 80"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 80  -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 80  -m state --state ESTABLISHED     -j ACCEPT

	echo "Allow connection to '$ip' on port 443"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 443 -m state --state ESTABLISHED     -j ACCEPT
done


#######################################################################################################
## Global iptable rules. Not IP specific

echo "Allowing new and established incoming connections to port 22, 80, 443"
$IPT -A INPUT  -p tcp -m multiport --dports 22,80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -m multiport --sports 22,80,443 -m state --state ESTABLISHED     -j ACCEPT

echo "Allow all outgoing connections to port 22"
$IPT -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -p tcp --sport 22 -m state --state ESTABLISHED     -j ACCEPT

echo "Allow outgoing icmp connections (pings,...)"
$IPT -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT  -p icmp -m state --state ESTABLISHED,RELATED     -j ACCEPT

echo "Allow outgoing connections to port 123 (ntp syncs)"
$IPT -A OUTPUT -p udp --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -p udp --sport 123 -m state --state ESTABLISHED     -j ACCEPT

# Log before dropping
$IPT -A INPUT  -j LOG  -m limit --limit 12/min --log-level 4 --log-prefix 'IP INPUT drop: '
$IPT -A INPUT  -j DROP

$IPT -A OUTPUT -j LOG  -m limit --limit 12/min --log-level 4 --log-prefix 'IP OUTPUT drop: '
$IPT -A OUTPUT -j DROP

exit 0









































#Setting up default kernel tunings here (don't worry too much about these right now, they are acceptable defaults) #DROP ICMP echo-requests sent to broadcast/multi-cast addresses.
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


####################################################################################################
####################################################################################################
####################################################################################################
####################################################################################################
####################################################################################################

#!/bin/bash
IPT="/sbin/iptables"
######---------------------------------------------------------------------------------
######-----/// SETTINGS OF SYSTEM
######---------------------------------------------------------------------------------
echo -e "------------\n Setting Network Cards \n------------\n"
NETIF_0="eth0"  	# Update to use your first network card
NETIF_1="eth1"  	# Update to use your second network card

######---------------------------
echo -e "------------\n Setting your DNS servers can use cat /etc/resolv.conf \n------------\n"
DNS_SERVER="9.9.9.9 8.8.8.8 1.1.1.1"

######---------------------------
echo -e "------------\n Getting Server IP \n------------\n"
SERVER_IP_0="$(ip addr show $NETIF_0 | grep 'inet ' | cut -f2 | awk '{ print $2}')"
SERVER_IP_1="$(ip addr show $NETIF_1 | grep 'inet ' | cut -f2 | awk '{ print $2}')"

######---------------------------------------------------------------------------------
######-----/// START OF SCRIPT FOR IPTABLES
######---------------------------------------------------------------------------------
echo -e "------------\n Flush all existing tables \n------------\n"
$IPT -F
$IPT -X
$IPT -t filter -F
$IPT -t filter -X
$IPT -t mangle -F
$IPT -t mangle -X
$IPT -t nat -F
$IPT -t nat -X
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
echo -e "------------\n Ping from inside to outside \n------------\n"
$IPT -A OUTPUT -p icmp -i $NETIF_0 --icmp-type echo-request -j ACCEPT
$IPT -A INPUT -p icmp -o $NETIF_0 --icmp-type echo-reply -j ACCEPT

######---------------------------
echo -e "------------\n Ping from outside to inside \n------------\n"
$IPT -A INPUT -p icmp -i $NETIF_0 --icmp-type echo-request -j ACCEPT
$IPT -A OUTPUT -p icmp -o $NETIF_0 --icmp-type echo-reply -j ACCEPT

######---------------------------
#echo -e "------------\n Allow outbound DNS \n------------\n"
#$IPT -A OUTPUT -p udp -o $NETIF_0 --dport 53 -j ACCEPT
#$IPT -A INPUT -p udp -i $NETIF_0 --sport 53 -j ACCEPT

######---------------------------
echo -e "------------\n Allow DNS IPADDR \n------------\n"
for dnsip in $DNS_SERVER
do
    echo -e "------------\n Allowing DNS lookups (tcp, udp port 53) to server '$dnsip' \n------------\n"
    $IPT -A OUTPUT -p udp -o $NETIF_0 -d $dnsip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p udp -i $NETIF_0 -s $dnsip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
    $IPT -A OUTPUT -p tcp -o $NETIF_0 -d $dnsip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p tcp -i $NETIF_0 -s $dnsip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
done

######---------------------------
echo -e "------------\n Allow previously established connections to continue uninterupted \n------------\n"
$IPT -A INPUT -o $NETIF_0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
$IPT -A OUTPUT -i $NETIF_0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

######---------------------------
echo -e "------------\n Allow outgoing SSH \n------------\n"
$IPT -A OUTPUT -o $NETIF_0 -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $NETIF_0 -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

######---------------------------
echo -e "------------\n Allow outbound connections on the ports specific ports. \n------------\n"
$IPT -A OUTPUT -p tcp -o $NETIF_0 --dport 53 -j ACCEPT #DNS
$IPT -A OUTPUT -p udp -o $NETIF_0 --dport 53 -j ACCEPT #DNS
$IPT -A OUTPUT -p tcp -o $NETIF_0 --dport 80 -j ACCEPT #HTTP
$IPT -A OUTPUT -p tcp -o $NETIF_0 --dport 443 -j ACCEPT #HTTPS
$IPT -A OUTPUT -p UDP -o $NETIF_0 --dport 67:68 -j ACCEPT #DHCP

######---------------------------
echo -e "------------\n Prevent DoS attack \n------------\n"
# Implementing SYN flood protection
$IPT -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 5 -j ACCEPT
$IPT -A INPUT -p tcp --syn -j DROP # Drop excess SYN packets to prevent DoS attacks

######---------------------------
echo -e "------------\n Set up logging for incoming and outgoing traffic. \n------------\n"
# Create a custom chain for logging and dropping
$IPT -N LOGNDROP
# Add rules to log incoming traffic before dropping it
$IPT -A INPUT -j LOGNDROP
$IPT -A LOGNDROP -m limit --limit 5/min -j LOG
$IPT -A LOGNDROP -j DROP
# Log incoming traffic before dropping
$IPT -A INPUT -j LOG -m limit --limit 12/min --log-level 4 --log-prefix 'IP INPUT drop: '
$IPT -A INPUT -j DROP
# Log outgoing traffic before dropping
$IPT -A OUTPUT -j LOG -m limit --limit 12/min --log-level 4 --log-prefix 'IP OUTPUT drop: '
$IPT -A OUTPUT -j DROP

######---------------------------
#echo -e "------------\n Blocking specific IPADDRS \n------------\n"
#BLOCK_THESE_IPS="x.x.x.x x.x.x.x x.x.x.x"
#for blockip in $BLOCK_THESE_IPS
#do
#    echo -e "------------\n Blocking the IPADDR '$blockip' \n------------\n"
#    $IPT -A INPUT -s "$blockip" -j DROP
#done

echo -e "######---------------------------\n"
echo -e "######-----/// EOF SCRIPT\n"
echo -e "######---------------------------\n"
exit 0
