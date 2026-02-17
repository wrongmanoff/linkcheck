import requests
from urllib.parse import urljoin


class RedirectResult:
    def __init__(self, final_url, chain, error=None):
        self.final_url = final_url
        self.chain = chain
        self.error = error


def expand_url(
    url: str,
    max_redirects: int = 4,
    timeout: int = 3
) -> RedirectResult:
    """
    Safely expand a URL using HEAD requests.
    """
    current_url = url
    chain = [url]

    session = requests.Session()
    session.headers.update({
        "User-Agent": "LinkCheck/1.0"
    })

    try:
        for _ in range(max_redirects):
            response = session.head(
                current_url,
                allow_redirects=False,
                timeout=timeout
            )

            # Check for redirect status codes
            if response.status_code in (301, 302, 303, 307, 308):
                location = response.headers.get("Location")
                if not location:
                    break

                # Handle relative redirects
                next_url = urljoin(current_url, location)
                chain.append(next_url)
                current_url = next_url
            else:
                break

        return RedirectResult(
            final_url=current_url,
            chain=chain
        )

    except requests.RequestException as e:
        return RedirectResult(
            final_url=current_url,
            chain=chain,
            error=str(e)
        )
