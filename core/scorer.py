def calculate_risk(findings: list[dict]) -> dict:

    total_score = 0
    reasons = []

    for finding in findings:
        score = finding.get("score", 0)
        reason = finding.get("reason", "")

        total_score += score

        if reason:
            reasons.append(reason)

    verdict = determine_verdict(total_score)

    return {
        "score": total_score,
        "verdict": verdict,
        "reasons": reasons
    }


def determine_verdict(score: int) -> str:
    thresholds = [
        (51, "MALICIOUS"),
        (21, "SUSPICIOUS"),
        (0,  "SAFE"),
    ]

    for limit, verdict in thresholds:
        if score >= limit:
            return verdict

