#!/usr/bin/env python3

import argparse
import sys
from utils.normalize import normalize_url
from core.analyzer import analyze_url

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

     #  Run static analysis
    result = analyze_url(normalized_url)

    #  Output results
    print(f"Risk Score: {result['score']}")
    print("Reasons:")

    if result["reasons"]:
        for reason in result["reasons"]:
            print(f" - {reason}")
    else:
        print(" - No suspicious indicators found")

    verdict = result["verdict"]

    if verdict == "SAFE":
        verdict_str = "SAFE "
    elif verdict == "SUSPICIOUS":
        verdict_str = "SUSPICIOUS "
    else:
        verdict_str = "MALICIOUS "

    print(f"\nFinal Verdict: {verdict_str}")


if __name__ == "__main__":
    main()
