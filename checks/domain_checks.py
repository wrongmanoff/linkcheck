import whois
from datetime import datetime


def check_domain_age(domain: str) -> dict | None:
    """
    Check how recently a domain was registered using WHOIS.
    """
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if not creation_date:
            return {"score": 10, "reason": "Domain creation date unavailable"}

        # Handle timezone-aware datetimes
        if creation_date.tzinfo is not None:
            creation_date = creation_date.replace(tzinfo=None)

        age_days = (datetime.utcnow() - creation_date).days

        if age_days < 7:
            return {"score": 30, "reason": f"Domain registered {age_days} days ago"}
        elif age_days < 30:
            return {"score": 20, "reason": f"Domain registered {age_days} days ago"}
        elif age_days < 90:
            return {"score": 10, "reason": f"Domain registered {age_days} days ago"}

    except Exception:
        return {"score": 10, "reason": "WHOIS lookup failed"}

    return None


def check_registrar(domain: str, shady_registrars: list[str]) -> dict | None:
    """
    Check registrar reputation using WHOIS.
    """
    try:
        w = whois.whois(domain)
    except Exception:
        return None

    registrar = w.registrar
    if not registrar:
        return None

    registrar_lower = registrar.lower()

    for bad in shady_registrars:
        if bad in registrar_lower:
            return {
                "score": 15,
                "reason": f"Registrar commonly used in phishing ({registrar})"
            }

    return None


def check_risky_tld(domain: str, risky_tlds: list[str]) -> dict | None:
    """
    Check if the domain's TLD is risky.
    Assumes input is a registered domain (e.g. example.co.uk, verify-user.ru)
    """
    try:
        tld = domain.split(".")[-1]
    except IndexError:
        return None

    if tld in risky_tlds:
        return {
            "score": 10,
            "reason": f"Suspicious TLD detected (.{tld})"
        }

    return None
