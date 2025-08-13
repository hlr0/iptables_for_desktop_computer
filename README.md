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
