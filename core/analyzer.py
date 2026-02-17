from checks.url_checks import run_checks
from core.scorer import calculate_risk
from checks.domain_checks import (
    check_domain_age,
    check_registrar,
    check_risky_tld,
)
from checks.evasion_checks import (
    check_unicode_domain,
    check_encoded_keywords,
    check_brand_impersonation,
    check_domain_entropy,
    check_subdomain_entropy,
    check_url_shortener,
)
from utils.domain import extract_registered_domain
from utils.redirector import expand_url
from checks.redirect_checks import analyze_redirect_chain\

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


def analyze_url(url: str, reanalyze: bool = True) -> dict:

    findings = []
    #phase 1 url level check
    keywords = load_keywords("data/keywords.txt")
    shorteners = load_keywords("data/url_shorteners.txt") 

    findings.extend( run_checks(url, keywords))
# phase 2 domain level checks
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
# phase 3a evasion and deception
    result = check_unicode_domain(registered_domain)
    if result:
        findings.append(result)

    # Encoded keyword abuse
    findings.extend(check_encoded_keywords(url, keywords))

    # Brand impersonation
    findings.extend(
        check_brand_impersonation(url, registered_domain)
    )
   # Domain entropy / gibberish detection
    result = check_domain_entropy(registered_domain)
    if result:
        findings.append(result)
    result = check_subdomain_entropy(url)
    if result:
         findings.append(result)
    redirect_result = None
    shortener_hit = False

    if reanalyze:
          result = check_url_shortener(url, shorteners)
          if result:
             shortener_hit = True
             findings.append(result)
          redirect_result = expand_url(url) 
          findings.extend(
                  analyze_redirect_chain(
                    redirect_result.chain,
                    shortener_hit
                   )
          )

    # ── Phase 3B.4: Final URL re-analysis ────────────────────────
    if redirect_result and redirect_result.final_url != url:
        final_analysis = analyze_url(
            redirect_result.final_url,
            reanalyze=False
        )

        for reason in final_analysis["reasons"]:
            findings.append({
                    "score": 0,
                    "reason": f"Inherited from final URL: {reason}"
               })

    result = calculate_risk(findings)

    return {
        "url": url,
    "domain": registered_domain,
        "score": result["score"],
        "verdict": result["verdict"],
        "reasons": result["reasons"],
    }
