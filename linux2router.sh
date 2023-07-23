#!/bin/bash

if (( $EUID != 0 )); then
    echo "Please run as root"
    exit
fi

# Function to display the help page
display_help() {
    echo "Usage: $0 [OPTIONS] <inbound_interface> <outbound_interface> <ip_range>"
    echo
    echo "Configure IP forwarding and iptables rules for network forwarding and NAT."
    echo "This script can be used to relay Hack The Box VPN traffic from Kali Linux to Windows."

    echo
    echo "Arguments:"
    echo "  <inbound_interface>   The interface name for inbound traffic."
    echo "  <outbound_interface>  The interface name for outbound traffic."
    echo "  <ip_range>            The IP range for NAT (Network Address Translation)."
    echo
    echo "Options:"
    echo "  --enable              Enable IP forwarding and configure iptables rules (default)."
    echo "  --disable             Disable IP forwarding and remove iptables rules."
    echo "  --help, -h            Display this help page."
    echo
    echo "Example:"
    echo "  $0 --enable eth0 tun0 192.168.1.0/24"
    echo
}

# Function to enable IP forwarding and configure iptables rules
enable_forwarding() {
    # Enable IP forwarding
    echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    sysctl -p

    # Configure iptables
    iptables -A FORWARD -i "$1" -o "$2" -j ACCEPT
    iptables -A FORWARD -i "$2" -o "$1" -j ACCEPT

    # When using VPN
    iptables -A FORWARD -i "$2" -o "$1" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$1" -o "$2" -j ACCEPT

    # Change outgoing packets for the reply packets (NAT)
    iptables -t nat -A POSTROUTING -o "$2" -s "$3" -j MASQUERADE

    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4

    # Save iptables rules with persistence
    apt-get install iptables-persistent -y
    service netfilter-persistent save
    service netfilter-persistent restart
    
    echo
    echo "IP forwarding and iptables rules have been configured."
    echo "Add the route by -"
    echo "cmd> route ADD <destination> MASK <mask> <gateway> METRIC <metric> IF <Interface>"

}

# Function to disable IP forwarding and remove iptables rules
disable_forwarding() {
    # Disable IP forwarding
    sed -i '/net.ipv4.ip_forward = 1/d' /etc/sysctl.conf
    sysctl -p

    # Remove iptables rules
    iptables -D FORWARD -i "$1" -o "$2" -j ACCEPT
    iptables -D FORWARD -i "$2" -o "$1" -j ACCEPT
    iptables -D FORWARD -i "$2" -o "$1" -m state --state RELATED,ESTABLISHED -j ACCEPT
    iptables -D FORWARD -i "$1" -o "$2" -j ACCEPT
    iptables -t nat -D POSTROUTING -o "$2" -s "$3" -j MASQUERADE

    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4
    
    # Remove iptables-persistent package
    #apt-get remove --purge iptables-persistent -y
    service netfilter-persistent restart

    echo
    echo "IP forwarding and iptables rules have been disabled."

    
}

# Check if help option is provided
if [[ $1 == "--help" || $1 == "-h" ]]; then
    display_help
    exit 0
fi

# Check if disable option is provided
if [[ $1 == "--disable" ]]; then
    disable_forwarding "$2" "$3" "$4"
    exit 0
fi

# Check if all arguments are provided
if [[ $# -ne 4 ]]; then
    echo "Error: Invalid number of arguments."
    echo
    display_help
    exit 1
fi

# Enable IP forwarding and configure iptables rules
enable_forwarding "$2" "$3" "$4"
