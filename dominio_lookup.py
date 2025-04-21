import dns.resolver
import socket
import concurrent.futures
from ipwhois import IPWhois
import whois
import ssl
import http.client
from datetime import datetime
import subprocess
import json
import requests
from bs4 import BeautifulSoup
import urllib3
from urllib.parse import urljoin

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

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

def ultra_tech_scan(domain):
    header("ULTRA TECHNOLOGY FINGERPRINTING")

    try:
        result = subprocess.run(
            ["wappalyzer", f"https://{domain}", "-d", "10", "-f", "json"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=20,
            text=True
        )
        data = json.loads(result.stdout)
        technologies = data.get("technologies", [])
        for tech in technologies:
            name = tech.get("name")
            version = tech.get("version", "N/A")
            categories = [c['name'] for c in tech.get("categories", [])]
            print(f"{name} - Version: {version} - Categories: {', '.join(categories)}")
    except:
        print("Error al ejecutar Wappalyzer o no está instalado correctamente.")

    try:
        r = requests.get(f"https://{domain}", timeout=10, verify=False)
        print("\nCOOKIES DETECTADAS:")
        for cookie in r.cookies:
            print(f"{cookie.name}: {cookie.value}")
        print("\nHEADERS ADICIONALES:")
        for h, v in r.headers.items():
            print(f"{h}: {v}")
    except:
        print("No se pudo analizar las cookies o headers adicionales.")

    print("\nRUTAS COMUNES:")
    paths = [
        "/admin", "/administrator", "/wp-admin", "/wp-login.php", "/login", "/user/login", 
        "/cpanel", "/config", "/setup", "/.env", "/.git/config", "/server-status", "/robots.txt"
    ]
    for path in paths:
        try:
            res = requests.get(f"https://{domain}{path}", timeout=5, verify=False)
            if res.status_code in [200, 301, 302]:
                print(f"{path} -> {res.status_code}")
        except:
            pass

    try:
        print("\nARCHIVOS JS Y LIBRERÍAS EXTERNAS:")
        soup = BeautifulSoup(r.text, "html.parser")
        scripts = soup.find_all("script", src=True)
        for s in scripts:
            src = s['src']
            print(f"JS: {src}")
            if "jquery" in src.lower():
                print("→ Posible uso de jQuery")
            if "wp-" in src.lower():
                print("→ WordPress detectado en JS")
            if "react" in src.lower():
                print("→ Posible uso de React.js")
            if "vue" in src.lower():
                print("→ Posible uso de Vue.js")
            if "angular" in src.lower():
                print("→ Posible uso de Angular")
    except:
        print("No se pudo analizar los scripts JS.")

    try:
        cname = dns.resolver.resolve(domain, 'CNAME', lifetime=5)
        for c in cname:
            ctext = c.to_text()
            if "cloudflare" in ctext:
                print("→ Usa Cloudflare")
            elif "akamai" in ctext:
                print("→ Usa Akamai CDN")
            elif "aws" in ctext or "amazon" in ctext:
                print("→ Usa AWS")
    except:
        pass

def discover_files(domain):
    header("ARCHIVOS Y CARPETAS DETECTADAS")
    try:
        r = requests.get(f"https://{domain}", timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        links = soup.find_all("a", href=True)
        for link in links:
            href = link.get('href')
            if href:
                print(f"Archivo/Carpeta encontrado: {href}")
    except Exception as e:
        print(f"No se pudo descubrir archivos: {e}")

def brute_common_paths(domain):
    header("ESCANEANDO RUTAS COMUNES")
    common_paths = [
        "/index.php", "/about", "/contact", "/admin", "/dashboard", "/login", 
        "/user", "/images", "/static", "/uploads", "/js", "/css"
    ]
    for path in common_paths:
        try:
            full_url = urljoin(f"https://{domain}", path)
            res = requests.get(full_url, timeout=5, verify=False)
            if res.status_code == 200:
                print(f"{full_url} -> STATUS: {res.status_code}")
        except:
            pass

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
    ultra_tech_scan(domain)
    
    discover_files(domain)
    brute_common_paths(domain)
    print(f"\nfinished at {datetime.now().strftime('%H:%M:%S')}")
    print("\nmade by undefined_name")
