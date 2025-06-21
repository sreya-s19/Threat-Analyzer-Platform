# modules/nlp_analyzer.py

import spacy

# Load the spaCy model once when the module is imported. This is efficient.
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    print("Spacy model not found. Please run 'python -m spacy download en_core_web_sm'")
    nlp = None

def analyze_linguistics(body: str) -> list:
    """
    Analyzes the linguistic and psychological patterns in a message body.
    
    Args:
        body: The text content of the message.
        
    Returns:
        A list of string codes for any suspicious linguistic findings.
    """
    if nlp is None:
        return ["NLP_MODEL_NOT_FOUND"]

    findings = []
    
    # Process the text with spaCy
    doc = nlp(body.lower()) # Process in lowercase for easier matching

    # --- Define our psychological trigger keywords ---
    urgency_keywords = ["urgent", "immediately", "now", "action required", "final notice", "limited time"]
    financial_keywords = ["invoice", "payment", "bank", "account", "transfer", "wire", "card", "billing"]
    authority_keywords = ["ceo", "manager", "boss", "admin", "it department", "support"]

    # --- Check for the presence of these keywords ---
    
    # Create a set of all tokens in the doc for fast lookups
    tokens = {token.text for token in doc}

    if any(keyword in tokens for keyword in urgency_keywords):
        findings.append("HIGH_URGENCY_DETECTED")

    if any(keyword in tokens for keyword in financial_keywords):
        findings.append("FINANCIAL_TOPIC_DETECTED")
    
    if any(keyword in tokens for keyword in authority_keywords):
        findings.append("AUTHORITY_IMPERSONATION_ATTEMPT")

    return findings