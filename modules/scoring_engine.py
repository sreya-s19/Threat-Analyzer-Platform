# modules/scoring_engine.py

# Define the risk score for each finding. These values can be tuned.
FINDING_SCORES = {
    # Structural findings
    "EXCESSIVE_CAPITALIZATION": 5,
    "CONTAINS_NON_ASCII_CHARS": 10,
    "EXTREMELY_SHORT_BODY": 5,

    # Link findings
    "CONTAINS_URLS": 2, # Base score for just having a URL
    "LINK_IS_IP_ADDRESS": 40, # This is a major red flag
    "NEW_DOMAIN_DETECTED": 25, # Also a major red flag

    # NLP findings
    "HIGH_URGENCY_DETECTED": 15,
    "FINANCIAL_TOPIC_DETECTED": 20,
    "AUTHORITY_IMPERSONATION_ATTEMPT": 20,

    # General/Error
    "NLP_MODEL_NOT_FOUND": 0
}

def calculate_score(findings: list) -> int:
    """
    Calculates a total threat score based on a list of findings.
    
    Args:
        findings: A list of string codes for all findings.
        
    Returns:
        An integer representing the total threat score.
    """
    total_score = 0
    
    # Use a set to handle unique findings, in case some are duplicated
    unique_findings = set(findings)
    
    for finding in unique_findings:
        # Some findings might have data attached (e.g., "NEW_DOMAIN_DETECTED:example.com")
        # We need to strip that off to match our dictionary key.
        base_finding = finding.split(':')[0]
        
        # Add the score from our dictionary. Use .get() for safety in case a finding isn't in the dict.
        total_score += FINDING_SCORES.get(base_finding, 0)

        # Special handling for findings that have a count, like CONTAINS_X_URLS
        if base_finding == "CONTAINS_URLS":
             # Extract the number of URLs and add a small score for each
             try:
                 num_urls = int(finding.split('_')[1])
                 total_score += FINDING_SCORES.get("CONTAINS_URLS", 0) * num_urls
             except:
                 pass # Ignore if parsing fails

    return total_score