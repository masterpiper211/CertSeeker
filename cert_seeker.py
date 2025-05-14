#!/usr/bin/env python3

import argparse
import requests
import json
import sys
import re
from pyfiglet import Figlet

TOOL_NAME = "CertSeeker"
VERSION = "1.0"

BLUE = "\033[94m"
RESET = "\033[0m"

def display_banner(tool_name: str) -> None:
    """Displays an ASCII art banner with tool info."""
    try:
        banner = Figlet(font="slant").renderText(tool_name)
        print(f"{BLUE}{banner}{RESET}")
        print(f"   A CLI tool for domain discovery using crt.sh - v{VERSION}\n")
    except Exception as e:
        print(f"{tool_name} - v{VERSION}")
        print(f"[!] Error displaying banner: {e}\n")

def is_valid_domain(domain: str) -> bool:
    """Very basic regex check to validate domain format."""
    pattern = re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$")
    return bool(pattern.match(domain))

def clean_domain(entry: str) -> str:
    """Normalizes a domain string."""
    return entry.strip().lower()

def extract_domains_from_entry(entry: dict) -> set:
    """Extracts and cleans domain values from a crt.sh certificate entry."""
    domains = set()

    cn = entry.get("common_name", "")
    if cn:
        cn = clean_domain(cn)
        if cn and cn != "*":
            domains.add(cn)

    name_value = entry.get("name_value", "")
    if name_value:
        for line in name_value.splitlines():
            domain = clean_domain(line)
            if domain and domain != "*":
                domains.add(domain)
    return domains

def query_crtsh(domain: str) -> list:
    """
    Queries crt.sh for certificate records related to a domain.
    Returns a sorted list of filtered unique domains.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    headers = {'User-Agent': f'{TOOL_NAME}/{VERSION}'}
    print(f"[*] Querying crt.sh for: {domain}...")

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()

        if not resp.text.strip():
            print("[-] Empty response from crt.sh.")
            return []

        content_type = resp.headers.get("Content-Type", "")
        if "application/json" not in content_type:
            print(f"[-] Unexpected content type: {content_type}")
            print(f"[-] Response: {resp.text[:200]}...")
            return []

        data = resp.json()
        if not isinstance(data, list):
            print("[-] Unexpected JSON structure from crt.sh.")
            return []

        found_domains = set()
        for entry in data:
            found_domains.update(extract_domains_from_entry(entry))

        # Filter only domains that end with the target domain
        filtered = sorted(d for d in found_domains if domain in d)
        return filtered

    except requests.exceptions.Timeout:
        print("[-] crt.sh request timed out.")
    except requests.exceptions.ConnectionError:
        print("[-] Connection error. Check your internet.")
    except requests.exceptions.HTTPError as e:
        print(f"[-] HTTP error: {e}")
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
    except json.JSONDecodeError:
        print("[-] JSON decoding error from crt.sh response.")
        print(f"[-] Raw content: {resp.text[:200]}...")
    
    return []

def save_to_file(domains: list, output_file: str) -> None:
    """Saves discovered domains to a specified file."""
    try:
        with open(output_file, "w") as f:
            for domain in domains:
                f.write(domain + "\n")
        print(f"[+] Saved {len(domains)} domains to: {output_file}")
    except Exception as e:
        print(f"[-] Error saving to file: {e}")

def main():
    display_banner(TOOL_NAME)

    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - Discover domains and subdomains via crt.sh",
        epilog="Example: python cert_seeker.py example.com -o domains.txt"
    )
    parser.add_argument(
        "domain", 
        help="Target base domain (e.g., example.com)"
    )
    parser.add_argument(
        "-o", "--output",
        help="Optional output file to save discovered domains"
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s v{VERSION}"
    )

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()
    target_domain = clean_domain(args.domain)

    if not is_valid_domain(target_domain):
        print("[-] Invalid domain format. Please enter a valid domain (e.g., example.com).")
        sys.exit(1)

    domains = query_crtsh(target_domain)

    if domains:
        print(f"[+] Found {len(domains)} domain(s):")
        for d in domains:
            print(f"  - {d}")

        if args.output:
            save_to_file(domains, args.output)
    else:
        print("[!] No domains found or crt.sh returned no usable results.")

if __name__ == "__main__":
    main()
