import pydnsmgr
import argparse
import os
from dotenv import load_dotenv
from pathlib import Path

DEBUG_MODE = False

# Debug print function
def debug_print(message: str):
    if DEBUG_MODE:
        print(f"DEBUG: {message}")

def main():
    global DEBUG_MODE
    global status
    dotenv_path = Path(__file__).parent / '.env'
    load_dotenv(dotenv_path=dotenv_path)

    username = os.getenv("DNS_ADMIN")
    password = os.getenv("DNS_PASSWORD")

    parser = argparse.ArgumentParser(description="Create and update DNS Records")
    parser.add_argument("-t", "--type", type=str, required=True, help="Type of DNS record (A, AAAA, CNAME, etc.)")
    parser.add_argument("-n", "--hostname", type=str, required=True, help="Hostname for the DNS record")
    parser.add_argument("-i", "--ip", type=str, required=True, help="IP address for the DNS record (e.g. 10.1.1.3 for A records, last octet for PTR records)")
    parser.add_argument("-z", "--zone", type=str, required=True, help="Zone to update (e.g. bodiddely.internal, 10.168.192.in-addr.arpa)")
    parser.add_argument("-s", "--server", type=str, required=True, help="IP Address of the DNS server to update")
    parser.add_argument("-d", "--debug", action="store_true", help="Enable debug output")
    args = parser.parse_args()

    if args.debug:
        DEBUG_MODE = True

    try:
        #verify environment variables for username and password
        if username is None or password is None:
            raise ValueError("DNS_ADMIN or DNS_PASSWORD environment variables are not set.")

        debug_print(f"Connecting to DNS server {args.server} with user {username}")
        dns_session = pydnsmgr.DNSManager(args.server, username, password)
        status = None
        match args.type.upper():
            case "A":
                status = dns_session.add_a_record(args.zone, args.hostname, args.ip)
            case "CNAME":
                status = dns_session.add_cname_record(args.zone, args.hostname, args.ip)
            case _:
                print(f"Unsupported DNS record type: {args.type.upper()}")
        if status is not None:
            if status == 0:
                print("SUCCESS")
            else:
                print("FAILED")

    except argparse.ArgumentError as e:
        print(parser.print_help())

    except Exception as e:
        print(f"Failed to create WinRM session: {e}")

if __name__ == "__main__":
    main()