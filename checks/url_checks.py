import re
import ipaddress
from urllib.parse import urlparse
import tldextract


def check_suspicious_keywords(url: str, keywords: list[str]) -> list[dict]:
    findings = []
    lower_url = url.lower()

    for kw in keywords:
        pattern = rf"(^|[\/\.\-_]){re.escape(kw)}($|[\/\.\-_0-9])"
        if re.search(pattern, lower_url):
            findings.append({
                "score": 10,
                "reason": f"Suspicious keyword found: {kw}"
            })

    return findings


def check_excessive_subdomains(url: str) -> dict | None:
    extracted = tldextract.extract(url)
    subdomain = extracted.subdomain

    if not subdomain:
        return None

    subdomain_parts = subdomain.split(".")

    if len(subdomain_parts) >= 3:
        return {
            "score": 15,
            "reason": f"Excessive subdomains detected ({len(subdomain_parts)})"
        }

    return None


def check_ip_address(url: str) -> dict | None:
    parsed = urlparse(url)
    host = parsed.hostname

    if not host:
        return None

    try:
        ipaddress.ip_address(host)
        return {
            "score": 25,
            "reason": "IP address used instead of domain"
        }
    except ValueError:
        return None


def check_url_length(url: str) -> dict | None:
    length = len(url)

    if length > 150:
        return {"score": 10, "reason": f"Very long URL ({length} characters)"}
    elif length > 100:
        return {"score": 5, "reason": f"Long URL ({length} characters)"}

    return None
def run_checks(url: str, keywords: list[str]) -> list[dict]:
    findings = []

    checks = [
        check_excessive_subdomains,
        check_ip_address,
        check_url_length,
    ]

    for check in checks:
        result = check(url)
        if result:
            findings.append(result)

    findings.extend(check_suspicious_keywords(url, keywords))
    return findings
