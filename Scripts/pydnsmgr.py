import winrm

# DNS Manager class for managing DNS records on Windows Server
# Future enhancements could include support for additional record types and improved error handling

global result
class DNSManager:
    def __init__(self, dns_server, username, password):
        self.host = dns_server
        self.username = username
        self.password = password
        self.session = winrm.Session(f"https://{self.host}:5986/wsman", transport="basic", auth=(self.username, self.password), server_cert_validation="ignore")

    def add_a_record(self, zone, host, ip_address):
        dns_command = f"dnscmd.exe {self.host} /RecordAdd {zone} {host} /CreatePTR A {ip_address}"
        return self.__execute_dns_command(dns_command)

    def add_cname_record(self, zone, a_record, cname_record):
        dns_command = f"dnscmd.exe {self.host} /RecordAdd {zone} {a_record} CNAME {cname_record}"
        self.__execute_dns_command(dns_command)

    def remove_dns_record(self, zone, record_type, name):
        dns_command = f"dnscmd.exe {self.host} /RecordDelete {zone} {name} {record_type}"
        return self.__execute_dns_command(dns_command)

    def __execute_dns_command(self, command):
        try:
            result = self.session.run_ps(command)
            return result.status_code
        except Exception as e:
            return 1