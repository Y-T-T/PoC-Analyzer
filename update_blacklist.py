import requests
import csv
import os
import re
from datetime import datetime
from urllib.parse import urlparse

# Update from URLHaus recent blacklist
URLHAUS_CSV_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"
BLACKLIST_FILE = "rules/data/blacklist.txt"
MAX_ENTRIES = 500 # Restrict to top 500 entries

# Markers to distinguish auto-generated and manually input content
MARKER_START = "# ================== AUTO-GENERATED URLHAUS START =================="
MARKER_END = "# ================== AUTO-GENERATED URLHAUS END =================="

def get_urlhaus_data():
    """Download and parse URLHaus CSV"""
    print(f"[*] Downloading blacklist from {URLHAUS_CSV_URL}...")
    try:
        response = requests.get(URLHAUS_CSV_URL, timeout=30)
        response.raise_for_status()
        
        content = response.text
        # Some lines in URLHaus CSV start with # as comments, which may confuse csv reader, so filter them out
        lines = [line for line in content.splitlines() if not line.startswith('#')]
        
        csv_reader = csv.reader(lines)
        urls = []
        seen_hosts = set()
        
        # CSV fields: id, dateadded, url, url_status, last_online, threat, ...
        # We only take the url (field 2)
        for row in csv_reader:
            if len(row) > 2:
                full_url = row[2]
                try:
                    # Use urlparse to extract domain or IP (netloc)
                    parsed = urlparse(full_url)
                    host = parsed.netloc
                    
                    # If there is a Port (e.g., 1.2.3.4:80), remove the Port and keep the IP/Domain
                    if ':' in host:
                        host = host.split(':')[0]
                        
                    if host and host not in seen_hosts:
                        seen_hosts.add(host)
                        # Escape the Host to convert it into a Regex pattern
                        safe_pattern = re.escape(host)
                        urls.append(safe_pattern)
                except Exception:
                    continue

                if len(urls) >= MAX_ENTRIES:
                    break
        
        print(f"[*] Fetched {len(urls)} unique malicious IPs/Domains.")
        return urls
        
    except Exception as e:
        print(f"[!] Error fetching data: {e}")
        return []

def update_blacklist_file(new_urls):
    """Update blacklist file, preserving user manually input content"""
    if not os.path.exists(BLACKLIST_FILE):
        print(f"[!] Error: {BLACKLIST_FILE} not found.")
        return

    # Read existing content
    with open(BLACKLIST_FILE, 'r') as f:
        content = f.read()

    # Prepare new block content
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    new_block = f"{MARKER_START}\n# Updated at: {timestamp}\n" + "\n".join(new_urls) + f"\n{MARKER_END}"

    # Check if auto-generated block already exists
    if MARKER_START in content and MARKER_END in content:
        # Use Regex to replace old block
        pattern = re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END)
        # re.DOTALL allows . to match newline characters
        new_content = re.sub(pattern, new_block, content, flags=re.DOTALL)
        print("[*] Updating existing auto-generated block...")
    else:
        # If no block, append directly at the end of the file
        new_content = content.strip() + "\n\n" + new_block
        print("[*] Appending new auto-generated block...")

    # Write back to file
    with open(BLACKLIST_FILE, 'w') as f:
        f.write(new_content)
    
    print(f"[+] Successfully updated {BLACKLIST_FILE}")

if __name__ == "__main__":
    urls = get_urlhaus_data()
    if urls:
        update_blacklist_file(urls)
