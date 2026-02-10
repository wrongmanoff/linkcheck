import tldextract


def extract_registered_domain(url_or_domain: str) -> str | None:
    extracted = tldextract.extract(url_or_domain)

    if not extracted.domain or not extracted.suffix:
        return None

    return f"{extracted.domain}.{extracted.suffix}"


def extract_domain_parts(url_or_domain: str) -> tuple[str, str] | None:
    extracted = tldextract.extract(url_or_domain)

    if not extracted.domain or not extracted.suffix:
        return None

    return extracted.domain, extracted.suffix
