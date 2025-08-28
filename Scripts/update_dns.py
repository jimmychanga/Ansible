import winrm
import argparse
import os
from dotenv import load_dotenv
from pathlib import Path

DEBUG_MODE = False

# Debug print function
def debug_print(message: str):
    if DEBUG_MODE:
        print(f"DEBUG: {message}")

#Function connects to DNS server and creates a record
def createRecord(session, args):
    dns_command_add = f"dnscmd.exe {args.server} /RecordAdd {args.zone} {args.hostname}  /CreatePTR {args.type} {args.ip}"
    debug_print(f"Executing: {dns_command_add}")
    result_add = session.run_ps(dns_command_add)
    if result_add.status_code == 0:
        print(f"SUCCESS: {args.hostname}.{args.zone} -> {args.ip} record created")
    else:
        debug_print(f"Failed to add DNS record. Return Code: {result_add.status_code}")
        print(f"FAILED: {args.hostname}.{args.zone} -> {args.ip} record creation failed")

def main():
    global DEBUG_MODE
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

        #create winrm session for connecting to DNS server
        session = winrm.Session(
            f"https://{args.server}:5986/wsman",
            transport='basic',
            auth=(username, password),
            server_cert_validation='ignore'
        )

        #call createRecord funtion to create record on DNS server
        createRecord(session, args)

    except argparse.ArgumentError as e:
        print(parser.print_help())

    except Exception as e:
        print(f"Failed to create WinRM session: {e}")

if __name__ == "__main__":
    main()