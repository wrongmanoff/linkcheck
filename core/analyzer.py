from checks.url_checks import run_checks
from core.scorer import calculate_risk
from checks.domain_checks import (
    check_domain_age,
    check_registrar,
    check_risky_tld,
)
from utils.domain import extract_registered_domain

def load_keywords(filepath: str) -> list[str]:
    """
    Load suspicious keywords from file.
    """
    keywords = []

    try:
        with open(filepath, "r") as f:
            for line in f:
                keyword = line.strip().lower()
                if keyword:
                    keywords.append(keyword)
    except FileNotFoundError:
        # Fail safe: no keywords, no keyword-based findings
        return []

    return keywords


def analyze_url(url: str) -> dict:

    findings = []

    keywords = load_keywords("data/keywords.txt")

    findings.extend( run_checks(url, keywords))

    registered_domain = extract_registered_domain(url)

    if registered_domain:
        risky_tlds = load_keywords("data/risky_tlds.txt")
        shady_registrars = load_keywords("data/shady_registrars.txt")

        # Domain age
        result = check_domain_age(registered_domain)
        if result:
            findings.append(result)

        # Registrar reputation
        result = check_registrar(registered_domain, shady_registrars)
        if result:
            findings.append(result)

        # Risky TLD
        result = check_risky_tld(registered_domain, risky_tlds)
        if result:
            findings.append(result)

    result = calculate_risk(findings)

    return {
        "url": url,
	"domain": registered_domain,
        "score": result["score"],
        "verdict": result["verdict"],
        "reasons": result["reasons"],
    }
