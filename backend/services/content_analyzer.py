import re


CATEGORY_KEYWORDS = {
    "credential_theft": [
        "password",
        "username",
        "login",
        "credential",
        "verify your account",
        "confirm your password",
        "sign in",
        "authentication",
        "verification"
    ],

    "financial_fraud": [
        "bank",
        "bank account",
        "credit card",
        "debit card",
        "payment",
        "invoice",
        "refund",
        "transaction",
        "money",
        "transfer",
        "billing"
    ],

    "otp_fraud": [
        "otp",
        "one time password",
        "verification code",
        "security code",
        "authentication code"
    ],

    "urgency": [
        "urgent",
        "immediately",
        "as soon as possible",
        "act now",
        "within 24 hours",
        "limited time",
        "final warning",
        "last warning",
        "immediate action"
    ],

    "account_takeover": [
        "account suspended",
        "account locked",
        "account compromised",
        "unusual login",
        "suspicious login",
        "unauthorized access",
        "security alert"
    ],

    "social_engineering": [
        "click here",
        "do not ignore",
        "important notice",
        "warning",
        "congratulations",
        "winner",
        "prize",
        "claim now",
        "confirm now"
    ]
}


def normalize_text(text):
    """
    Normalize email content for analysis.
    """

    if not text:
        return ""

    text = text.lower()

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


def find_keyword_matches(text, keywords):
    """
    Find keyword/phrase matches.
    """

    matches = []

    for keyword in keywords:

        if keyword.lower() in text:

            matches.append(keyword)

    return sorted(set(matches))


def analyze_content(text):
    """
    Perform rule-based NLP/content analysis
    on email text.
    """

    normalized_text = normalize_text(text)

    categories = {}

    total_matches = 0

    for category, keywords in CATEGORY_KEYWORDS.items():

        matches = find_keyword_matches(
            normalized_text,
            keywords
        )

        categories[category] = {
            "detected": bool(matches),
            "matches": matches,
            "count": len(matches)
        }

        total_matches += len(matches)

    # -------------------------------------------------
    # INDIVIDUAL INDICATORS
    # -------------------------------------------------

    has_url = bool(
        re.search(
            r"https?://",
            normalized_text
        )
    )

    has_ip = bool(
        re.search(
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
            normalized_text
        )
    )

    has_html_form_language = any(
        phrase in normalized_text
        for phrase in [
            "enter your password",
            "enter your otp",
            "enter your card number",
            "enter your bank details"
        ]
    )

    # -------------------------------------------------
    # RISK SCORE
    # -------------------------------------------------

    score = 0

    score += min(
        total_matches * 4,
        40
    )

    if categories["credential_theft"]["detected"]:
        score += 15

    if categories["financial_fraud"]["detected"]:
        score += 15

    if categories["otp_fraud"]["detected"]:
        score += 10

    if categories["account_takeover"]["detected"]:
        score += 10

    if categories["urgency"]["detected"]:
        score += 10

    if categories["social_engineering"]["detected"]:
        score += 10

    if has_url:
        score += 5

    if has_ip:
        score += 10

    if has_html_form_language:
        score += 15

    score = min(
        score,
        100
    )

    # -------------------------------------------------
    # RISK LEVEL
    # -------------------------------------------------

    if score >= 75:

        risk_level = "CRITICAL"

    elif score >= 50:

        risk_level = "HIGH"

    elif score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # -------------------------------------------------
    # THREAT CATEGORIES
    # -------------------------------------------------

    threat_categories = []

    if categories["credential_theft"]["detected"]:
        threat_categories.append(
            "Credential Phishing"
        )

    if categories["financial_fraud"]["detected"]:
        threat_categories.append(
            "Financial Fraud"
        )

    if categories["otp_fraud"]["detected"]:
        threat_categories.append(
            "OTP Fraud"
        )

    if categories["account_takeover"]["detected"]:
        threat_categories.append(
            "Account Takeover"
        )

    if categories["social_engineering"]["detected"]:
        threat_categories.append(
            "Social Engineering"
        )

    if not threat_categories:
        threat_categories.append(
            "No Major Content Threat Detected"
        )

    # -------------------------------------------------
    # EXPLANATION
    # -------------------------------------------------

    explanations = []

    if categories["credential_theft"]["detected"]:

        explanations.append(
            "Email contains language commonly associated "
            "with credential or password theft."
        )

    if categories["financial_fraud"]["detected"]:

        explanations.append(
            "Email contains financial or banking-related "
            "fraud indicators."
        )

    if categories["otp_fraud"]["detected"]:

        explanations.append(
            "Email requests or references one-time "
            "authentication codes."
        )

    if categories["urgency"]["detected"]:

        explanations.append(
            "Urgency-based language may be used to "
            "pressure the recipient into immediate action."
        )

    if categories["account_takeover"]["detected"]:

        explanations.append(
            "Email contains account compromise or "
            "suspicious-login indicators."
        )

    if has_url:

        explanations.append(
            "Email contains a URL that requires "
            "additional infrastructure analysis."
        )

    if has_ip:

        explanations.append(
            "Email contains an IP address."
        )

    if not explanations:

        explanations.append(
            "No significant suspicious language "
            "was detected."
        )

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "categories": categories,
        "threat_categories": threat_categories,
        "explanations": explanations,
        "indicators": {
            "has_url": has_url,
            "has_ip": has_ip,
            "has_html_form_language": has_html_form_language
        },
        "total_keyword_matches": total_matches
    }