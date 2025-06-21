# modules/structural_analyzer.py

import re

def analyze_structure(body: str) -> list:
    """
    Analyzes the structural properties of a message body.
    
    Args:
        body: The text content of the message.
        
    Returns:
        A list of string codes for any suspicious findings.
    """
    findings = []
    
    # Check 1: Excessive use of capitalization (a common sign of urgency/spam)
    # We'll consider it "excessive" if more than 30% of the alphabetic characters are uppercase.
    alpha_chars = [char for char in body if char.isalpha()]
    if len(alpha_chars) > 20: # Only check on messages with enough text
        uppercase_chars = [char for char in alpha_chars if char.isupper()]
        uppercase_ratio = len(uppercase_chars) / len(alpha_chars)
        if uppercase_ratio > 0.3:
            findings.append("EXCESSIVE_CAPITALIZATION")

    # Check 2: Presence of unusual characters or character sets
    # This is a simple check for characters not common in standard English text
    if re.search(r'[^\x00-\x7F]+', body):
        findings.append("CONTAINS_NON_ASCII_CHARS")
        
    # Check 3: Is the message extremely short? (Could be a lure to click a link)
    if len(body.split()) < 5:
        findings.append("EXTREMELY_SHORT_BODY")

    return findings