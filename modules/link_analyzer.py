# modules/link_analyzer.py

import re
import whois
from datetime import datetime, timedelta

def find_urls(text: str) -> list:
    """Finds all URLs in a given string and returns them in a list."""
    # A robust regex to find URLs
    url_regex = r'(?:(?:https?|ftp):\/\/)?[\w/\-?=%.]+\.[\w/\-?=%.]+'
    return re.findall(url_regex, text)

def analyze_domain_age(domain: str) -> bool:
    """
    Checks if a domain was created recently.
    Returns True if the domain is very new (less than 30 days old), False otherwise.
    """
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date

        # whois can return a single date or a list of dates
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if creation_date is None:
            return False # Can't determine age

        # Check if the domain is less than 30 days old
        if datetime.now() - creation_date < timedelta(days=30):
            return True # This is a very new, suspicious domain
    except Exception as e:
        print(f"Could not check domain age for {domain}: {e}")
        # If we can't check it, assume it's not new for safety
        return False
    
    return False

def analyze_links(body: str) -> list:
    """
    Analyzes all links found in a message body.
    
    Args:
        body: The text content of the message.
        
    Returns:
        A list of string codes for any suspicious link-related findings.
    """
    findings = []
    urls = find_urls(body)
    
    if not urls:
        return findings

    findings.append(f"CONTAINS_{len(urls)}_URLS")

    for url in urls:
        # Check 1: Is the link just an IP address? (Very suspicious)
        # NEW, IMPROVED CODE
        # Extract the host part of the URL first (e.g., '123.45.67.89' from 'http://123.45.67.89/login')
        try:
            host = url.split('//')[-1].split('/')[0].split(':')[0] # also remove port if present
        except:
            host = '' # Could not parse, move on

        # Now check if the extracted host is an IP address
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
            findings.append("LINK_IS_IP_ADDRESS")
            continue # No need to check domain age for an IP

        # Extract domain from URL (a simple way)
        try:
            domain = url.split('//')[-1].split('/')[0]
            
            # Check 2: Is the domain very new?
            if analyze_domain_age(domain):
                findings.append(f"NEW_DOMAIN_DETECTED:{domain}")

        except Exception as e:
            print(f"Could not parse domain from URL {url}: {e}")

    return findings