import nmap
import sys

def main():
    # Initializes a PortScanner Object
    nm = nmap.PortScanner()
    
    # Defining target host and port range
    target = '127.0.0.1'
    port_range = '1-10'

    try:
        print(f"Scanning {target} on ports {port_range}...")

        # TCP Connect Scan
        nm.scan(target, port_range, '-sT')

        # Handles case where host is unreachable
        if not nm.all_hosts():
            print("Error: Target host is unreachable.")
            return

        # No open ports found
        for host in nm.all_hosts():
            print(f"\nHost Found: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")

            if not nm[host].all_protocols():
                print(f"No open ports found on {host} in range {port_range}.")
                continue

            for proto in nm[host].all_protocols():
                print(f"Protocol: {proto}")

                # Displays open ports and states
                ports = nm[host][proto].keys()
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    # Print port states and the detected services
                    print(f"Port: {port}\tState: {state}\tService: {service}")

    # Nmap not installed or inaccessible, Privilege and Permission issues and Unexpected Error
    except nmap.PortScannerError:
        print("Error: Nmap is not installed or inaccessible.")
    except PermissionError:
        print("Error: Privilege and or Permission issues encountered.")
    except Exception as e:
        print(f"Unexpected Error/Problem: {e}")

if __name__ == "__main__":
    main()
