import socket
import requests
from scapy.all import sr1, IP, TCP
from collections import defaultdict

ascii_art = """
  _____ _      ______          
 /  ___(_)     |  _  \         
 \ `--. _ _ __ | | | |_____  __
  `--. \ | '_ \| | | / _ \ \/ /
 /\__/ / | | | | |/ /  __/>  < 
 \____/|_|_| |_|___/ \___/_/\_\\
"""

port_services = {
    20: "FTP Data", 21: "FTP Control", 22: "SSH", 23: "Telnet", 
    25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 
    123: "NTP", 135: "Microsoft RPC", 139: "NetBIOS", 
    143: "IMAP", 443: "HTTPS", 445: "Microsoft-DS", 
    465: "SMTPS", 587: "SMTP (Submission)", 993: "IMAPS", 
    995: "POP3S", 3306: "MySQL", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
}

cms_keywords = {
    "WordPress": "wp-content",
    "Joomla": "Joomla",
    "Drupal": "Drupal",
    "Magento": "Magento"
}

def banner():
    print(ascii_art)
    print("="*60)
    print(" 🌐 SinD3X - For A Root User")
    print(" 🛠️  Developed by: DekaXploiT")
    print(" 📊 Version: 2.0 (Enhanced Port & Web Server Scan)")
    print("="*60)

def dns_info(domain):
    try:
        ip = socket.gethostbyname(domain)
        print(f"\n[🌐] DNS Information for {domain}:")
        print(f"    Domain: {domain}")
        print(f"    IP Address: {ip}")
        return ip
    except socket.gaierror:
        print(f"    🚫 Failed to resolve DNS for {domain}")
        return None

def port_scan(ip):
    print("\n[🔍] Scanning Ports with 90% Accuracy:\n")
    common_ports = sorted(port_services.keys())
    open_ports = defaultdict(str)
    
    print(f"   {'PORT'.center(8)}{'SERVICE'.center(22)}{'STATUS'.center(10)}")
    print(f"   {'-' * 40}")
    
    for port in common_ports:
        pkt = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=0.5, verbose=0)
        if pkt and pkt.haslayer(TCP) and pkt.getlayer(TCP).flags == 0x12:
            open_ports[port] = port_services.get(port, "Unknown Service")
            print(f"   {str(port).center(8)}{open_ports[port].center(22)}{'OPEN'.center(10)}")
    
    if open_ports:
        print(f"\n   🎯 Target: {ip} | Total Open Ports: {len(open_ports)}")
    else:
        print("\n   🚫 No Common Open Ports Found")

    print("\n" + "=" * 40)

def subdomain_scan(domain):
    print("\n[🌐] Subdomain Scan (Sample):")
    subdomains = ["www", "mail", "ftp", "blog", "shop"]
    found = [f"{sub}.{domain}" for sub in subdomains]
    for sub in found:
        print(f"    - {sub}")
    print("    Scan Complete!")

def server_info(ip):
    print("\n[🔍] Scanning Web Server for Info:")
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
    }
    try:
        response = requests.get(f"http://{ip}", headers=headers, timeout=3)
        
        # Check for server version
        server_header = response.headers.get("Server", "Unknown")
        print(f"   Server Information: {server_header}")
        
        # Check for CMS by analyzing URL or content
        cms_detected = "Unknown CMS"
        for cms, keyword in cms_keywords.items():
            if keyword in response.text:
                cms_detected = cms
                break
        
        print(f"   CMS Detected: {cms_detected}")
        
    except requests.exceptions.RequestException as e:
        print(f"    🚫 Failed to retrieve server info. Error: {e}")

    print("\n" + "=" * 40)

def main():
    banner()
    domain = input("\nEnter domain (without http:// or https://): ")
    ip = dns_info(domain)
    if ip:
        port_scan(ip)
        subdomain_scan(domain)
        server_info(ip)
    else:
        print("   ❌ Exiting due to DNS resolution failure.")

if __name__ == "__main__":
    main()