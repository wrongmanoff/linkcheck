import re
import unicodedata
from urllib.parse import unquote, urlparse
import math

#1️⃣ Unicode / Homograph Detection

def check_unicode_domain(domain: str) -> dict | None:
    if not domain:
        return None

    # Punycode indicator
    if "xn--" in domain:
        return {
            "score": 30,
            "reason": "Punycode domain detected (possible homograph attack)"
        }

    # Non-ASCII characters
    for ch in domain:
        if ord(ch) > 127:
            return {
                "score": 20,
                "reason": "Unicode characters detected in domain"
            }

    return None



# 2️⃣ URL Encoding Abuse Detection

def check_encoded_keywords(url: str, keywords: list[str]) -> list[dict]:
    findings = []
    decoded_url = unquote(url)

    # If decoding didn't change anything, skip
    if decoded_url == url:
        return findings

    decoded_lower = decoded_url.lower()

    for kw in keywords:
        if kw in decoded_lower:
            findings.append({
                "score": 10,
                "reason": f"Suspicious keyword hidden via URL encoding: {kw}"
            })

    return findings



# 3️⃣ Brand Impersonation Heuristics

COMMON_BRANDS = [
    "paypal",
    "google",
    "microsoft",
    "amazon",
    "apple",
    "facebook",
    "instagram",
    "bank",
    "government",
    "hdfc",
    "sbi",
]


def check_brand_impersonation(url: str, registered_domain: str) -> list[dict]:

    findings = []

    if not registered_domain:
        return findings

    parsed = urlparse(url)
    host = parsed.hostname or ""

    host_lower = host.lower()
    domain_lower = registered_domain.lower()

    for brand in COMMON_BRANDS:
        if brand in host_lower and brand not in domain_lower:
            findings.append({
                "score": 20,
                "reason": f"Possible brand impersonation detected: {brand}"
            })

    return findings

def check_domain_entropy(registered_domain: str) -> dict | None:
    if not registered_domain:
        return None

    # Extract the main label (before TLD)
    label = registered_domain.split(".")[0].lower()

    # Ignore very short domains (e.g. ibm.com)
    if len(label) < 5:
        return None

    # Character frequency
    freq = {}
    for ch in label:
        if ch.isalpha():
            freq[ch] = freq.get(ch, 0) + 1

    # Shannon entropy
    entropy = 0.0
    for count in freq.values():
        p = count / len(label)
        entropy -= p * math.log2(p)

    # Vowel ratio (human words have vowels)
    vowels = sum(1 for c in label if c in "aeiou")
    vowel_ratio = vowels / len(label)

    # Heuristics
    if entropy > 3.5 and vowel_ratio < 0.35:
        return {
            "score": 25,
            "reason": "High-entropy / random-looking domain name detected"
        }

    return None

def check_subdomain_entropy(url: str) -> dict | None:
    """
    Detect high-entropy / random-looking subdomains.
    """
    from urllib.parse import urlparse

    parsed = urlparse(url)
    host = parsed.hostname or ""

    if not host:
        return None

    parts = host.split(".")

    # Need at least one subdomain + domain + tld
    if len(parts) < 3:
        return None

    # Extract subdomain part(s)
    subdomain = ".".join(parts[:-2]).lower()

    # Ignore very common benign subdomains
    COMMON_SUBDOMAINS = {
        "www", "mail", "ftp", "api", "cdn", "web", "secure", "login"
    }

    labels = [
        lbl for lbl in subdomain.replace("-", ".").split(".")
        if lbl and lbl not in COMMON_SUBDOMAINS
    ]

    if not labels:
        return None

    for label in labels:
        if len(label) < 5:
            continue

        # Shannon entropy
        freq = {}
        for ch in label:
            if ch.isalpha():
                freq[ch] = freq.get(ch, 0) + 1

        entropy = 0.0
        for count in freq.values():
            p = count / len(label)
            entropy -= p * math.log2(p)

        vowels = sum(1 for c in label if c in "aeiou")
        vowel_ratio = vowels / len(label)

        if entropy > 3.5 and vowel_ratio < 0.35:
            return {
                "score": 25,
                "reason": "High-entropy / random-looking subdomain detected"
            }

    return None


def check_url_shortener(url: str, shorteners: list[str]) -> dict | None:
    """
    Detect known URL shortening services.
    """
    parsed = urlparse(url)
    host = parsed.hostname or ""

    host = host.lower()

    for shortener in shorteners:
        if host == shortener or host.endswith("." + shortener):
            return {
                "score": 15,
                "reason": f"URL shortener detected ({host})"
            }

    return None
