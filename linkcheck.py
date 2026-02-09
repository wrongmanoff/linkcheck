#!/usr/bin/env python3

import argparse
import sys
from utils.normalize import normalize_url


def main():
    parser = argparse.ArgumentParser(
        description="LinkCheck - CLI tool to analyze URL safety"
    )
    parser.add_argument(
        "url",
        help="URL to analyze"
    )

    args = parser.parse_args()

    input_url = args.url.strip()
    normalized_url = normalize_url(input_url)

    if not normalized_url:
        print("❌ Error: Invalid URL format")
        sys.exit(1)

    print(f"[+] Input URL      : {input_url}")
    print(f"[+] Normalized URL : {normalized_url}")


if __name__ == "__main__":
    main()
