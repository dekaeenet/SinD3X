import socket
import requests
import re
from scapy.all import sr1, IP, TCP
from collections import defaultdict
import sublist3r

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

def banner():
    print(ascii_art)
    print("="*60)
    print(" 🌐 SinD3X - Scan DNS, Subdomain & Network with Precision")
    print(" 🛠️  Developed by: Arya Deka Alhadid")
    print(" 📊 Version: 2.0 (Enhanced Port & Web Server Scan)")
    print("="*60)

def is_valid_domain(domain):
    """Validasi format domain dengan regex."""
    return re.match(r'^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', domain) is not None

def dns_info(domain):
    """Mengambil informasi DNS dari domain."""
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
    """Memindai port untuk menemukan port yang terbuka."""
    print("\n[🔍] Scanning Ports with 90% Accuracy:\n")
    common_ports = sorted(port_services.keys())
    open_ports = defaultdict(str)
    
    print(f"   {'PORT'.center(8)}{'SERVICE'.center(22)}{'STATUS'.center(10)}")
    print(f"   {'-' * 40}")
    
    for port in common_ports:
        pkt = sr1(IP(dst=ip)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        if pkt:
            if pkt.haslayer(TCP):
                if pkt.getlayer(TCP).flags == 0x12:
                    open_ports[port] = port_services.get(port, "Unknown Service")
                    print(f"   {str(port).center(8)}{open_ports[port].center(22)}{'OPEN'.center(10)}")
                elif pkt.getlayer(TCP).flags == 0x14:
                    print(f"   {str(port).center(8)}{'Closed'.center(22)}{'CLOSED'.center(10)}")
            else:
                print(f"   {str(port).center(8)}{'Unknown Service'.center(22)}{'TIMEOUT'.center(10)}")
    
    if open_ports:
        print(f"\n   🎯 Target: {ip} | Total Open Ports: {len(open_ports)}")
    else:
        print("\n   🚫 No Common Open Ports Found")

    print("\n" + "=" * 40)

def subdomain_scan(domain):
    """Memindai subdomain dari domain yang diberikan menggunakan sublist3r."""
    print(f"\n[🌐] Scanning Subdomains for {domain} with Sublist3r:")
    subdomains = sublist3r.main(domain, verbose=False, threads=10)
    
    if subdomains:
        for sub in subdomains:
            print(f"    - {sub}")
    else:
        print("    🚫 No subdomains found.")
    print("    Scan Complete!")

def check_cms(ip):
    """Menentukan CMS yang digunakan oleh website berdasarkan pola-pola tertentu."""
    try:
        response = requests.get(f"http://{ip}", timeout=2)
        
        # Cek WordPress
        if 'wp-content' in response.text:
            print(f"   ✔ WordPress site detected on {ip}")
        
        # Cek Joomla
        elif 'Joomla' in response.text:
            print(f"   ✔ Joomla site detected on {ip}")
        
        # Cek Drupal
        elif 'Drupal' in response.text:
            print(f"   ✔ Drupal site detected on {ip}")
        
        # Cek Magento
        elif 'Magento' in response.text:
            print(f"   ✔ Magento site detected on {ip}")
        
        # Cek Shopify
        elif 'Shopify' in response.text:
            print(f"   ✔ Shopify site detected on {ip}")
        
        else:
            print(f"   🚫 No CMS detected on {ip}")
            
    except requests.exceptions.RequestException as e:
        print(f"   🚫 Error connecting to server: {e}")

def check_web_server(ip):
    """Menentukan jenis web server berdasarkan HTTP headers."""
    try:
        response = requests.get(f"http://{ip}", timeout=2)
        if 'Server' in response.headers:
            server = response.headers['Server']
            print(f"   ✔ Web Server Detected: {server}")
        else:
            print(f"   🚫 Unable to detect Web Server")
    except requests.exceptions.RequestException as e:
        print(f"   🚫 Error connecting to server: {e}")

def server_info(ip):
    """Menampilkan informasi server berdasarkan IP dengan melakukan request HTTP."""
    try:
        response = requests.get(f"http://{ip}", timeout=2)
        if response.status_code == 200:
            print(f"   ✔ Server is Up: {ip}")
            print(f"   📋 Server Info: {response.text[:200]}")  # Print first 200 characters
        else:
            print(f"   🚫 Server returned status code {response.status_code}")
    except requests.exceptions.RequestException as e:
        print(f"   🚫 Error connecting to server: {e}")

def main():
    banner()
    domain = input("\nMasukkan domain (tanpa http:// atau https://): ")
    
    if not is_valid_domain(domain):
        print("   ❌ Format domain tidak valid. Silakan masukkan domain yang valid.")
        return
    
    ip = dns_info(domain)
    if ip:
        port_scan(ip)
        subdomain_scan(domain)
        check_cms(ip)
        check_web_server(ip)
        server_info(ip)
    else:
        print("   ❌ Keluar karena kegagalan resolusi DNS.")

if __name__ == "__main__":
    main()