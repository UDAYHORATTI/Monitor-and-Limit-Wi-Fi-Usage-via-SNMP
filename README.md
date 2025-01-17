# Monitor-and-Limit-Wi-Fi-Usage-via-SNMP
Python and SNMP (Simple Network Management Protocol). This approach is ideal for managing a network where you have access to the router or switch and can monitor traffic per device (IP or MAC address) directly from the network hardware.

from pysnmp.hlapi import *
import time
import subprocess

# Configuration
ROUTER_IP = "192.168.1.1"  # Replace with your router's IP
COMMUNITY_STRING = "public"  # Replace with your SNMP community string
USAGE_LIMIT_MB = 500  # Limit in MB
CHECK_INTERVAL = 60  # Check interval in seconds
DEVICE_IPS = ["192.168.1.101", "192.168.1.102"]  # Devices to monitor
IP_TO_INTERFACE = {"192.168.1.101": "2", "192.168.1.102": "3"}  # Map IP to interface index

# Function to get SNMP data
def get_snmp_data(ip, community, oid):
    try:
        iterator = getCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid)),
        )
        error_indication, error_status, error_index, var_binds = next(iterator)

        if error_indication:
            print(f"SNMP Error: {error_indication}")
            return None
        elif error_status:
            print(f"SNMP Error: {error_status.prettyPrint()}")
            return None
        else:
            for var_bind in var_binds:
                return int(var_bind[1])
    except Exception as e:
        print(f"Error fetching SNMP data: {e}")
        return None

# Function to block IP
def block_ip(ip_address):
    try:
        subprocess.run(["iptables", "-A", "OUTPUT", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"Blocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error blocking IP {ip_address}: {e}")

# Function to unblock IP
def unblock_ip(ip_address):
    try:
        subprocess.run(["iptables", "-D", "OUTPUT", "-s", ip_address, "-j", "DROP"], check=True)
        subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        print(f"Unblocked IP: {ip_address}")
    except subprocess.CalledProcessError as e:
        print(f"Error unblocking IP {ip_address}: {e}")

# Monitoring and limiting function
def monitor_and_limit():
    initial_usage = {ip: 0 for ip in DEVICE_IPS}
    blocked_ips = set()

    while True:
        time.sleep(CHECK_INTERVAL)
        for ip, interface in IP_TO_INTERFACE.items():
            # Get bytes sent and received
            oid_in = f"1.3.6.1.2.1.2.2.1.10.{interface}"  # OID for incoming bytes
            oid_out = f"1.3.6.1.2.1.2.2.1.16.{interface}"  # OID for outgoing bytes
            in_bytes = get_snmp_data(ROUTER_IP, COMMUNITY_STRING, oid_in)
            out_bytes = get_snmp_data(ROUTER_IP, COMMUNITY_STRING, oid_out)

            if in_bytes is None or out_bytes is None:
                print(f"Could not fetch data for IP: {ip}")
                continue

            # Calculate total usage
            total_bytes = in_bytes + out_bytes
            usage_mb = (total_bytes - initial_usage[ip]) / (1024 * 1024)  # Convert to MB
            initial_usage[ip] = total_bytes

            print(f"IP: {ip}, Usage: {usage_mb:.2f} MB")

            # Block if limit exceeded
            if usage_mb > USAGE_LIMIT_MB and ip not in blocked_ips:
                block_ip(ip)
                blocked_ips.add(ip)

# Main function
if __name__ == "__main__":
    monitor_and_limit()
