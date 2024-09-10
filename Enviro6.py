import argparse
import os
import subprocess
import random
import time
import sys
from scapy.all import *
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_banner():
    banner = f"""
{Fore.CYAN} _______   ________   ___      ___ ___  ________  ________  ________     
{Fore.CYAN}|\  ___ \ |\   ___  \|\  \    /  /|\  \|\   __  \|\   __  \|\   ____\    
{Fore.CYAN}\ \   __/|\ \  \\ \  \ \  \  /  / | \  \ \  \|\  \ \  \|\  \ \  \___|    
{Fore.CYAN} \ \  \_|/_\ \  \\ \  \ \  \/  / / \ \  \ \   _  _\ \  \\\  \ \  \____   
{Fore.CYAN}  \ \  \_|\ \ \  \\ \  \ \    / /   \ \  \ \  \\  \\ \  \\\  \ \  ___  \ 
{Fore.CYAN}   \ \_______\ \__\\ \__\ \__/ /     \ \__\ \__\\ _\\ \_______\ \_______\\
{Fore.CYAN}    \|_______|\|__| \|__|\|__|/       \|__|\|__|\|__|\|_______|\|_______|
{Fore.GREEN}By @ShakudW
{Fore.GREEN}https://github.com/ShkudW/Enviro6
"""
    print(banner)

def generate_ula_address():
    prefix = "fd{:02x}:{:02x}{:02x}:{:02x}{:02x}".format(
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255),
        random.randint(0, 255)
    )
    return f"{prefix}::"

def check_service_installed(service_name):
    status = subprocess.run(["dpkg", "-s", service_name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if status.returncode == 0:
        print(f"{Fore.GREEN}{service_name} is installed: OK")
        return True
    else:
        print(f"{Fore.RED}{service_name} is not installed: FAIL")
        return False

def check_port_open(port):
    result = subprocess.run(["sudo", "lsof", "-i", f":{port}"], stdout=subprocess.PIPE)
    if result.stdout:
        print(f"{Fore.GREEN}Port {port} is open: OK")
        return True
    else:
        print(f"{Fore.RED}Port {port} is not open: FAIL")
        return False

def update_netplan(ula_address, iface):
    netplan_file = "/etc/netplan/01-netcfg.yaml"
    backup_file = "/etc/netplan/01-netcfg.yaml.backup"
    if not os.path.exists(backup_file):
        os.system(f"sudo cp {netplan_file} {backup_file}")
    new_netplan = f"""
network:
  version: 2
  renderer: networkd
  ethernets:
    {iface}:
      dhcp4: yes
      dhcp6: no
      addresses:
        - {ula_address}1/64
      nameservers:
        addresses:
          - {ula_address}1
      routes:
        - to: default
          via: {ula_address}1
    """
    with open(netplan_file, 'w') as f:
        f.write(new_netplan)
    os.system("sudo chmod 600 /etc/netplan/01-netcfg.yaml")
    os.system("sudo netplan apply")
    print(f"{Fore.GREEN}Updated {netplan_file} with ULA address {ula_address}1 and secured file permissions.")

def update_dhcpd6_conf(ula_address):
    dhcpd6_conf = "/etc/dhcp/dhcpd6.conf"
    backup_file = "/etc/dhcp/dhcpd6.conf.backup"
    if not os.path.exists(backup_file):
        os.system(f"sudo cp {dhcpd6_conf} {backup_file}")
    start_range = f"{ula_address}10"
    end_range = f"{ula_address}100"
    new_dhcpd6_conf = f"""
subnet6 {ula_address}/64 {{
    range6 {start_range} {end_range};
    option dhcp6.name-servers {ula_address}1;
    option dhcp6.domain-search "example.local";
}}
    """
    with open(dhcpd6_conf, 'w') as f:
        f.write(new_dhcpd6_conf)
    print(f"{Fore.GREEN}Updated {dhcpd6_conf} with ULA range {start_range} to {end_range}.")

def configure_dhcp_interface():
    dhcp_default_file = "/etc/default/isc-dhcp-server"
    backup_file = "/etc/default/isc-dhcp-server.backup"
    if not os.path.exists(backup_file):
        os.system(f"sudo cp {dhcp_default_file} {backup_file}")
    needs_update = False
    with open(dhcp_default_file, 'r') as f:
        lines = f.readlines()
    if 'INTERFACESv4=""\n' not in lines:
        needs_update = True
    if 'INTERFACESv6="eth0"\n' not in lines:
        needs_update = True
    if needs_update:
        new_conf = [
            'INTERFACESv4=""',
            'INTERFACESv6="eth0"',
        ]
        with open(dhcp_default_file, 'w') as f:
            f.write("\n".join(new_conf) + "\n")
        os.system("sudo systemctl restart isc-dhcp-server")
        print(f"{Fore.GREEN}Updated {dhcp_default_file} to use only DHCPv6 on eth0.")
        print(f"{Fore.GREEN}Restarted isc-dhcp-server service.")

def check_and_update_dhcpd6_conf():
    dhcpd6_conf = "/etc/dhcp/dhcpd6.conf"
    with open(dhcpd6_conf, 'r') as f:
        content = f.read()
    if 'subnet6' not in content:
        print(f"{Fore.RED}Error: No subnet6 statement found in dhcpd6.conf.")
    else:
        print(f"{Fore.GREEN}subnet6 statement found in dhcpd6.conf: OK")

def update_dnsmasq_conf(ula_address, domains):
    dnsmasq_conf = "/etc/dnsmasq.conf"
    backup_file = "/etc/dnsmasq.conf.backup"
    if not os.path.exists(backup_file):
        os.system(f"sudo cp {dnsmasq_conf} {backup_file}")
    
    ipv4_addresses = os.popen('hostname -I').read().strip().split()
    ipv4_address = ipv4_addresses[0] if ipv4_addresses else '127.0.0.1'
    
    new_conf = [
        "domain-needed",
        "bogus-priv",
        f"interface=eth0",
        f"listen-address={ula_address}1",
        f"listen-address=127.0.0.1",
        f"listen-address={ipv4_address}",
    ]
    for domain in domains:
        new_conf.append(f"address=/{domain}/{ula_address}1")
        new_conf.append(f"address=/{domain}/{ipv4_address}")
    
    with open(dnsmasq_conf, 'w') as f:
        f.write("\n".join(new_conf) + "\n")
    
    os.system("sudo systemctl restart dnsmasq")
    print(f"{Fore.GREEN}Updated {dnsmasq_conf} with the following configuration:")
    print("\n".join(new_conf))

def update_resolv_conf(ula_address):
    resolv_file = "/etc/resolv.conf"
    backup_resolv = "/etc/resolv.conf.backup"
    if not os.path.exists(backup_resolv):
        os.system(f"sudo cp {resolv_file} {backup_resolv}")
    resolv_conf = [
        f"nameserver {ula_address}1",
        "nameserver 127.0.0.1"
    ]
    with open(resolv_file, 'w') as f:
        f.write("\n".join(resolv_conf) + "\n")
    print(f"{Fore.GREEN}Updated {resolv_file} with the following nameservers:")
    print("\n".join(resolv_conf))

def restore_previous_conf(iface):
    files_to_restore = [
        ("/etc/netplan/01-netcfg.yaml", "/etc/netplan/01-netcfg.yaml.backup"),
        ("/etc/dhcp/dhcpd6.conf", "/etc/dhcp/dhcpd6.conf.backup"),
        ("/etc/dnsmasq.conf", "/etc/dnsmasq.conf.backup"),
        ("/etc/resolv.conf", "/etc/resolv.conf.backup"),
        ("/etc/default/isc-dhcp-server", "/etc/default/isc-dhcp-server.backup"),
        ("/etc/radvd.conf", "/etc/radvd.conf.backup"),
    ]
    for file, backup in files_to_restore:
        if os.path.exists(backup):
            os.system(f"sudo cp {backup} {file}")
            print(f"{Fore.GREEN}Restored {file} from {backup}.")
        else:
            print(f"{Fore.YELLOW}Backup {backup} not found. No changes made to {file}.")
    
    # Disable IP forwarding as part of the restore process
    with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
        f.write('0')
    print(f"{Fore.GREEN}IP Forwarding disabled.")
    
    # Flush IPv6 addresses from the interface
    os.system(f"sudo ip -6 addr flush dev {iface}")
    print(f"{Fore.GREEN}Flushed IPv6 addresses from {iface}.")
    
    # Reset iptables rules
    os.system("sudo ip6tables --flush")
    os.system("sudo ip6tables --table nat --flush")
    os.system("sudo ip6tables --delete-chain")
    os.system("sudo ip6tables --table nat --delete-chain")
    print(f"{Fore.GREEN}Reset ip6tables rules to defaults.")
    
    os.system("sudo systemctl stop isc-dhcp-server")
    os.system("sudo systemctl stop dnsmasq")
    os.system("sudo systemctl stop radvd")
    os.system("sudo netplan apply")

def enable_ip_forwarding():
    print(f"{Fore.CYAN}Enabling IP Forwarding...")
    with open('/proc/sys/net/ipv6/conf/all/forwarding', 'w') as f:
        f.write('1')
    print(f"{Fore.GREEN}IP Forwarding enabled.")

def setup_iptables(ula_address, external_interface):
    print(f"{Fore.CYAN}Setting up iptables to allow all traffic for ULA and Link-local addresses...")
    os.system("sudo ip6tables --flush")
    os.system("sudo ip6tables --table nat --flush")
    os.system("sudo ip6tables --delete-chain")
    os.system("sudo ip6tables --table nat --delete-chain")

    # Allow all traffic to and from ULA and Link-local addresses
    os.system(f"sudo ip6tables -A INPUT -s {ula_address}/64 -j ACCEPT")
    os.system(f"sudo ip6tables -A OUTPUT -d {ula_address}/64 -j ACCEPT")
    os.system("sudo ip6tables -A INPUT -s fe80::/10 -j ACCEPT")
    os.system("sudo ip6tables -A OUTPUT -d fe80::/10 -j ACCEPT")

    # Masquerading for the ULA range
    os.system(f"sudo ip6tables -t nat -A POSTROUTING -s {ula_address}/64 -o {external_interface} -j MASQUERADE")

    print(f"{Fore.GREEN}iptables rules for IPv6 configured to allow full traffic for ULA and Link-local addresses.")

def start_dhcp_server():
    print(f"{Fore.CYAN}Attempting to start DHCP server...")
    result = subprocess.run(["sudo", "systemctl", "start", "isc-dhcp-server"], stdout=subprocess.PIPE)
    if result.returncode == 0:
        print(f"{Fore.GREEN}DHCP server started successfully.")
    else:
        print(f"{Fore.RED}Failed to start DHCP server. Please check the service status manually.")

def check_dhcp_server_status():
    print(f"{Fore.CYAN}Checking DHCP server status...")
    result = subprocess.run(["sudo", "systemctl", "status", "isc-dhcp-server"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if "active (running)" in result.stdout.decode():
        print(f"{Fore.GREEN}DHCP server is running: OK")
    else:
        print(f"{Fore.RED}DHCP server is not running: FAIL")

def configure_radvd(ula_address, iface):
    radvd_conf = "/etc/radvd.conf"
    backup_file = "/etc/radvd.conf.backup"
    if not os.path.exists(backup_file):
        os.system(f"sudo cp {radvd_conf} {backup_file}")
    
    new_radvd_conf = f"""
interface {iface}
{{
    AdvSendAdvert on;
    MinRtrAdvInterval 30;
    MaxRtrAdvInterval 100;
    prefix {ula_address}1/64
    {{
        AdvOnLink on;
        AdvAutonomous on;
        AdvRouterAddr off;
    }};
    RDNSS {ula_address}1
    {{
        AdvRDNSSLifetime 300;
    }};
}};
    """
    with open(radvd_conf, 'w') as f:
        f.write(new_radvd_conf)
    os.system("sudo systemctl restart radvd")
    print(f"{Fore.GREEN}Router Advertisement Daemon (radvd) started with ULA prefix {ula_address}1/64.")

def show_connected_devices():
    seen_devices = set()
    print(f"{Fore.CYAN}{Style.BRIGHT}Showing connected devices with IPv6 addresses...")
    while True:
        output = subprocess.run(["ip", "-6", "neighbor", "show"], stdout=subprocess.PIPE).stdout.decode()
        lines = output.strip().split('\n')
        for line in lines:
            parts = line.split()
            if len(parts) >= 5:
                ipv6_address = parts[0]
                mac_address = parts[4]
                if mac_address not in seen_devices:
                    seen_devices.add(mac_address)
                    print(f"{Fore.YELLOW}Device {mac_address} with IPv6 {ipv6_address} connected.")
        time.sleep(5)

def sniff_ndp_packets(iface):
    print(f"{Fore.CYAN}Starting NDP sniffing on interface {iface}...")
    seen_addresses = set()

    def handle_packet(pkt):
        if ICMPv6ND_NS in pkt or ICMPv6ND_NA in pkt:
            src_ip = pkt[IPv6].src
            src_mac = pkt[Ether].src
            if (src_ip, src_mac) not in seen_addresses:
                seen_addresses.add((src_ip, src_mac))
                print(f"{Fore.YELLOW}Neighbor Solicitation/Advertisement: {src_ip} is at {src_mac}")

    sniff(iface=iface, prn=handle_packet, filter="icmp6")

def main():
    print_banner()  # Print the banner when the script starts

    parser = argparse.ArgumentParser(description="Configure DHCPv6 and DNSv6 with autogenerated ULA address and domains")
    parser.add_argument("-iface", "--iface", help="Network interface to apply the ULA address")
    parser.add_argument("-dns", "--dns", action="store_true", help="Configure the machine as a DNSv6 server")
    parser.add_argument("-domain", "--domains", nargs='+', help="Domains to map to the IPv6 and IPv4 addresses (requires --dns)")
    parser.add_argument("-restore", "--restore", action="store_true", help="Restore the previous configuration")
    parser.add_argument("-sniff", "--sniff", action="store_true", help="Sniff for Neighbor Discovery Protocol (NDP) packets")

    args = parser.parse_args()

    if args.restore:
        restore_previous_conf(args.iface)
        return

    if not args.iface:
        print(f"{Fore.RED}Error: The -iface argument is required unless running with -restore.")
        sys.exit(1)

    if args.sniff:
        sniff_ndp_packets(args.iface)
    else:
        ula_address = generate_ula_address()
        external_interface = args.iface  # Adjust to the correct external interface
        print(f"{Fore.CYAN}Generated ULA address: {ula_address}1")

        enable_ip_forwarding()
        setup_iptables(f"{ula_address}1", external_interface)

        dhcp_installed = check_service_installed("isc-dhcp-server")
        dns_installed = check_service_installed("dnsmasq") if args.dns else True
        radvd_installed = check_service_installed("radvd")

        if not dhcp_installed or (args.dns and not dns_installed) or not radvd_installed:
            print(f"{Fore.RED}One or more services are not installed. Please install them and run the script again.")
            return

        configure_dhcp_interface()
        check_and_update_dhcpd6_conf()
        update_netplan(ula_address, args.iface)
        update_dhcpd6_conf(ula_address)
        configure_radvd(ula_address, args.iface)

        if args.dns:
            if not args.domains:
                print(f"{Fore.RED}Error: You must provide domains using the --domains flag when using --dns.")
                return

            update_dnsmasq_conf(ula_address, args.domains)
            update_resolv_conf(ula_address)

        start_dhcp_server()
        check_dhcp_server_status()

        # Start showing connected devices
        show_connected_devices()

if __name__ == "__main__":
    main()

