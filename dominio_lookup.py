import dns.resolver
import socket
import concurrent.futures
from ipwhois import IPWhois
import whois
import ssl
import http.client
from datetime import datetime

def header(text):
    print(f"\n{'-'*10} {text.upper()} {'-'*10}")

def get_dns_records(domain):
    header("DNS RECORDS")
    record_types = [
        'A', 'AAAA', 'AFSDB', 'APL', 'CAA', 'CDNSKEY', 'CDS', 'CERT', 'CNAME',
        'DHCID', 'DLV', 'DNAME', 'DNSKEY', 'DS', 'EUI48', 'EUI64', 'HINFO',
        'HIP', 'IPSECKEY', 'KEY', 'KX', 'LOC', 'MB', 'MD', 'MF', 'MG', 'MINFO',
        'MR', 'MX', 'NAPTR', 'NS', 'NSEC', 'NSEC3', 'NSEC3PARAM', 'OPENPGPKEY',
        'PTR', 'RRSIG', 'RP', 'SIG', 'SMIMEA', 'SOA', 'SPF', 'SRV', 'SSHFP',
        'SVCB', 'TA', 'TKEY', 'TLSA', 'TSIG', 'TXT', 'URI', 'ZONEMD', 
        'SMIMEA', 'RP', 'SIG', 'SSHFP', 'SVCB', 'TA', 'TKEY', 'TLSA'
    ]
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(domain, record, raise_on_no_answer=False, lifetime=5)
            if answers:
                for r in answers:
                    print(f"[{record}] {r.to_text()}")
        except dns.resolver.NoAnswer:
            pass
        except dns.exception.DNSException:
            print(f"[{record}] Error resolviendo este tipo de registro.")
            continue

def get_ip_info(domain):
    header("IP & PTR & WHOIS IP")
    try:
        ip = socket.gethostbyname(domain)
        print(f"IP: {ip}")
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_answers = dns.resolver.resolve(rev_name, "PTR", lifetime=5)
            for ptr in ptr_answers:
                print(f"PTR: {ptr.to_text()}")
        except dns.exception.DNSException:
            pass
        try:
            obj = IPWhois(ip)
            res = obj.lookup_rdap()
            asn = res.get('asn')
            org = res.get('network', {}).get('name')
            country = res.get('network', {}).get('country')
            cidr = res.get('network', {}).get('cidr')
            if asn: print(f"ASN: {asn}")
            if org: print(f"ORG: {org}")
            if country: print(f"COUNTRY: {country}")
            if cidr: print(f"CIDR: {cidr}")
        except:
            pass
        return ip
    except (socket.gaierror, dns.exception.DNSException):
        print(f"No se pudo resolver la IP para {domain}.")
        return None

def subdomain_scan(domain):
    header("SUBDOMAINS")
    subdomains = ['www', 'mail', 'ftp', 'webmail', 'remote', 'ns1', 'ns2', 'smtp', 'blog', 'dev', 'api', 'test', 'vpn', 'cpanel', 'whm', 'admin', 'gateway', 'server', 'portal']
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(resolve_subdomain, f"{sub}.{domain}"): sub for sub in subdomains}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                print(result)

def resolve_subdomain(sub):
    try:
        ip = socket.gethostbyname(sub)
        return f"{sub} -> {ip}"
    except socket.gaierror:
        return None

def scan_ports(ip):
    header("PORT SCAN")
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 465, 587, 993, 995, 3306, 8080, 8443]
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"Port {port}: OPEN")
            sock.close()
        except:
            pass

def get_http_headers(domain):
    header("HTTP HEADERS")
    try:
        conn = http.client.HTTPSConnection(domain, timeout=2, context=ssl._create_unverified_context())
        conn.request("HEAD", "/")
        res = conn.getresponse()
        print(f"HTTP {res.status} {res.reason}")
        for k, v in res.getheaders():
            print(f"{k}: {v}")
        conn.close()
    except (http.client.HTTPException, ssl.SSLError, socket.timeout):
        print(f"No se pudo obtener el encabezado HTTP de {domain}.")

def get_whois_domain(domain):
    header("WHOIS DOMAIN")
    try:
        data = whois.whois(domain)
        for key in ['domain_name', 'registrar', 'creation_date', 'expiration_date', 'name_servers', 'emails']:
            val = data.get(key)
            if val:
                print(f"{key.upper()}: {val}")
    except:
        print(f"No se pudo obtener la información WHOIS de {domain}.")

if __name__ == "__main__":
    print(f"\nstarted at {datetime.now().strftime('%H:%M:%S')}")
    domain = input("domain: ").strip()
    get_dns_records(domain)
    ip = get_ip_info(domain)
    subdomain_scan(domain)
    if ip:
        scan_ports(ip)
        get_http_headers(domain)
    get_whois_domain(domain)
    print(f"\nfinished at {datetime.now().strftime('%H:%M:%S')}")
    print("\nmade by undefined_name")