Iptables Script for Desktop Computer Setup

Usage: $0 [OPTIONS]

Options:
  -h, --help      Show this help message and exit
  -c, --clean     Revert all changes and flush the iptables rules
  -n, --network   Specify network interface (e.g., eth0, eno2, wlan0)

Examples:
  $0 -n eno2      Run with eno2 as network interface
  $0 --clean      Flush all iptables rules
  $0 --help       Display this help message

Note: This script must be run with root privileges

##### setup procedure
 ------------------------------------------------------------------------------------
 apt-get install iptables-persistent
 ------------------------------------------------------------------------------------
 #if you want to load at reboot or make sure crontab -- is set or run with iptables-save or netfilter persistent
 #every 30 minutes
 */30 * * * * /sbin/iptables-restore < /etc/iptables/rules.v4 2>&1 | logger -t iptables-restore
 */30 * * * * /usr/sbin/netfilter-persistent reload 2>&1 | logger -t netfilter-persistent
 @reboot /sbin/iptables-restore < /etc/iptables/rules.v4 2>&1 | logger -t iptables-restore
 @reboot /usr/sbin/netfilter-persistent reload 2>&1 | logger -t netfilter-persistent
 ------------------------------------------------------------------------------------

################### BASIC USAGE 

#### Check if rules are loaded
iptables -L -n

#### Test ping blocking (should fail from untrusted IPs)
ping 192.168.0.43

#### Check logs for any scan attempts
grep "IPTABLES SCAN ATTEMPT" /var/log/syslog

#### Save the rules permanently
apt-get install iptables-persistent
#### or
iptables-save > /etc/iptables/rules.v4
