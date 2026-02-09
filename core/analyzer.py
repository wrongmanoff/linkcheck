from checks.url_checks import run_checks
from core.scorer import calculate_risk


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

    keywords = load_keywords("data/keywords.txt")

    findings = run_checks(url, keywords)

    result = calculate_risk(findings)

    return {
        "url": url,
        "score": result["score"],
        "verdict": result["verdict"],
        "reasons": result["reasons"],
    }
