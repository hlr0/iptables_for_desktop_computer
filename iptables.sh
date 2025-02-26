#!/bin/bash
IPT="/sbin/iptables"

# Server IP
SERVER_IP="$(ip addr show enp1s0 | grep 'inet ' | cut -f2 | awk '{ print $2}')"

# Your DNS servers you use: cat /etc/resolv.conf
DNS_SERVER="9.9.9.9 8.8.8.8 1.1.1.1"

# Allow connections to this package servers (Ubuntu 24.04 package servers)
PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"

echo "flush iptable rules"
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

echo "Set default policy to 'DROP'"
$IPT -P INPUT   DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT  DROP

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

# Resolve the domain names to IP addresses for package servers
for domain in $PACKAGE_SERVER
do
    IP=$(dig +short $domain | head -n 1)  # Get the first IP address for the domain

    if [ -z "$IP" ]; then
        echo "Unable to resolve domain: $domain"
        continue
    fi

    echo "Allow connection to '$domain' ($IP) on port 80"
    $IPT -A OUTPUT -p tcp -d "$IP" --dport 80  -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p tcp -s "$IP" --sport 80  -m state --state ESTABLISHED     -j ACCEPT

    echo "Allow connection to '$domain' ($IP) on port 443"
    $IPT -A OUTPUT -p tcp -d "$IP" --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
    $IPT -A INPUT  -p tcp -s "$IP" --sport 443 -m state --state ESTABLISHED     -j ACCEPT
done

# Allow HTTP and HTTPS for browsing
echo "Allow outgoing HTTP (port 80) for browsing"
$IPT -A OUTPUT -p tcp --dport 80 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -p tcp --sport 80 -m state --state ESTABLISHED -j ACCEPT

echo "Allow outgoing HTTPS (port 443) for browsing"
$IPT -A OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT

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
