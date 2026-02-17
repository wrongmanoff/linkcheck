from urllib.parse import urlparse


def analyze_redirect_chain(
    chain: list[str],
    shortener_detected: bool
) -> list[dict]:
    """
    Analyze redirect chain behavior and return risk findings.
    """
    findings = []

    hops = len(chain) - 1  # redirects count

    # ── Excessive redirect hops ───────────────────────────────
    if hops >= 2:
        findings.append({
            "score": 10,
            "reason": f"Multiple redirects detected ({hops} hops)"
        })

    if hops >= 4:
        findings.append({
            "score": 20,
            "reason": f"Excessive redirect chain length ({hops} hops)"
        })

    # ── Shortener that failed to expand ───────────────────────
    if shortener_detected and hops == 0:
        findings.append({
            "score": 10,
            "reason": "URL shortener detected but destination could not be expanded"
        })

    # ── Domain / TLD hopping ──────────────────────────────────
    domains = []
    for url in chain:
        parsed = urlparse(url)
        if parsed.hostname:
            domains.append(parsed.hostname.lower())

    unique_domains = set(domains)

    if len(unique_domains) >= 2:
        findings.append({
            "score": 10,
            "reason": "Redirect chain spans multiple domains"
        })

    return findings
