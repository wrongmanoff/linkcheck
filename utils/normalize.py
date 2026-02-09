from urllib.parse import urlparse, urlunparse


def normalize_url(url: str) -> str | None:

    if not url or not isinstance(url, str):
        return None

    url = url.strip()

    # Add scheme if missing
    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.hostname:
        return None

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname.lower()

    # Preserve port if present
    netloc = hostname
    if parsed.port:
        netloc = f"{hostname}:{parsed.port}"

    normalized = urlunparse((
        scheme,
        netloc,
        parsed.path or "",
        parsed.params or "",
        parsed.query or "",
        parsed.fragment or ""
    ))

    return normalized
