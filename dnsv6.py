import argparse
import os

def update_dnsmasq_conf(ipv6_address, domains):
    conf_file = "/etc/dnsmasq.conf"
    backup_file = "/etc/dnsmasq.conf.backup"

    # Backup existing config
    if not os.path.exists(backup_file):
        os.system(f"sudo cp {conf_file} {backup_file}")

    # Prepare the new config content
    new_conf = []
    new_conf.append(f"interface=eth0")
    new_conf.append(f"listen-address={ipv6_address}")
    new_conf.append(f"listen-address=127.0.0.1")  # For local testing
    new_conf.append(f"listen-address={os.popen('hostname -I').read().strip()}")  # Get the IPv4 address

    for domain in domains:
        new_conf.append(f"address=/{domain}/{ipv6_address}")
        new_conf.append(f"address=/{domain}/{os.popen('hostname -I').read().strip()}")  # IPv4 mapping

    # Write to the config file
    with open(conf_file, 'w') as f:
        f.write("\n".join(new_conf) + "\n")

    print(f"Updated {conf_file} with the following configuration:")
    print("\n".join(new_conf))

    # Restart dnsmasq service to apply changes
    os.system("sudo systemctl restart dnsmasq")

def update_resolv_conf(ipv6_address):
    resolv_file = "/etc/resolv.conf"
    backup_resolv = "/etc/resolv.conf.backup"

    # Backup existing resolv.conf
    if not os.path.exists(backup_resolv):
        os.system(f"sudo cp {resolv_file} {backup_resolv}")

    # Prepare new resolv.conf content
    resolv_conf = [
        f"nameserver {ipv6_address}",
        "nameserver 127.0.0.1"
    ]

    # Write to the resolv.conf file
    with open(resolv_file, 'w') as f:
        f.write("\n".join(resolv_conf) + "\n")

    print(f"Updated {resolv_file} with the following nameservers:")
    print("\n".join(resolv_conf))

def restore_previous_conf():
    conf_file = "/etc/dnsmasq.conf"
    backup_file = "/etc/dnsmasq.conf.backup"
    resolv_file = "/etc/resolv.conf"
    backup_resolv = "/etc/resolv.conf.backup"

    # Restore dnsmasq.conf
    if os.path.exists(backup_file):
        os.system(f"sudo cp {backup_file} {conf_file}")
        print(f"Restored {conf_file} from {backup_file}.")
    else:
        print(f"Backup {backup_file} not found. No changes made to {conf_file}.")

    # Restore resolv.conf
    if os.path.exists(backup_resolv):
        os.system(f"sudo cp {backup_resolv} {resolv_file}")
        print(f"Restored {resolv_file} from {backup_resolv}.")
    else:
        print(f"Backup {backup_resolv} not found. No changes made to {resolv_file}.")

    # Restart dnsmasq service to apply changes
    os.system("sudo systemctl restart dnsmasq")

def main():
    parser = argparse.ArgumentParser(description="Configure dnsmasq with custom IPv6 and domains")
    parser.add_argument("-ipv6", "--ipv6_address", help="IPv6 address of the Kali machine")
    parser.add_argument("-domain", "--domains", nargs='+', help="Domains to map to the IPv6 and IPv4 addresses")
    parser.add_argument("-restore", "--restore", action="store_true", help="Restore the previous DNS configuration")

    args = parser.parse_args()

    if args.restore:
        restore_previous_conf()
    else:
        if not args.ipv6_address or not args.domains:
            print("Error: You must provide both IPv6 address and domains unless using --restore.")
            return

        # Update dnsmasq configuration
        update_dnsmasq_conf(args.ipv6_address, args.domains)

        # Update resolv.conf to use the custom DNS server
        update_resolv_conf(args.ipv6_address)

if __name__ == "__main__":
    main()

