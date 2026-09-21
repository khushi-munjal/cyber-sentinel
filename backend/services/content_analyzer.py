import re


# =========================================================
# CONTENT ANALYSIS RULES
# =========================================================

CATEGORY_KEYWORDS = {

    "credential_theft": [
        "password",
        "username",
        "credential",
        "verify your account",
        "confirm your password",
        "enter your password",
        "enter your username",
        "password reset",
        "reset your password",
        "credential verification"
    ],

    "financial_fraud": [
        "bank account",
        "credit card",
        "debit card",
        "payment",
        "invoice",
        "refund",
        "transaction",
        "money transfer",
        "wire transfer",
        "billing information",
        "bank details",
        "card number",
        "account number"
    ],

    "otp_fraud": [
        "otp",
        "one time password",
        "verification code",
        "security code",
        "authentication code",
        "enter the code",
        "share the code"
    ],

    "urgency": [
        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "limited time",
        "final warning",
        "last warning",
        "immediate action",
        "your account will be suspended",
        "your account will be closed"
    ],

    "account_takeover": [
        "account suspended",
        "account locked",
        "account compromised",
        "unusual login",
        "suspicious login",
        "unauthorized access",
        "unauthorized activity",
        "security alert",
        "account security"
    ],

    "social_engineering": [
        "click here",
        "do not ignore",
        "important notice",
        "warning",
        "claim now",
        "confirm now",
        "you have won",
        "winner",
        "prize",
        "gift card",
        "act immediately"
    ]
}


# =========================================================
# NORMALIZATION
# =========================================================

def normalize_text(text):
    """
    Normalize email content for analysis.
    """

    if not text:
        return ""

    text = str(text).lower()

    # Remove excessive whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# =========================================================
# KEYWORD MATCHING
# =========================================================

def find_keyword_matches(text, keywords):
    """
    Find exact keyword/phrase occurrences.

    Uses word boundaries for single words so that
    a word such as 'passwords' is not accidentally
    treated as an exact 'password' match unless intended.
    """

    matches = []

    for keyword in keywords:

        keyword = keyword.lower().strip()

        if not keyword:
            continue

        # Multi-word phrases
        if " " in keyword:

            pattern = (
                r"\b"
                + re.escape(keyword)
                + r"\b"
            )

        else:

            pattern = (
                r"\b"
                + re.escape(keyword)
                + r"\b"
            )

        if re.search(
            pattern,
            text,
            flags=re.IGNORECASE
        ):

            matches.append(keyword)

    return sorted(
        set(matches)
    )


# =========================================================
# URL DETECTION
# =========================================================

def extract_urls(text):
    """
    Extract HTTP/HTTPS URLs from email content.
    """

    if not text:
        return []

    pattern = r"https?://[^\s<>\"]+"

    urls = re.findall(
        pattern,
        text,
        flags=re.IGNORECASE
    )

    # Remove duplicate URLs
    return list(
        dict.fromkeys(urls)
    )


# =========================================================
# IP DETECTION
# =========================================================

def extract_ipv4_addresses(text):
    """
    Extract IPv4 addresses from email content.

    Presence of an IP address is NOT automatically
    considered malicious.
    """

    if not text:
        return []

    pattern = (
        r"\b"
        r"(?:"
        r"(?:25[0-5]|2[0-4]\d|"
        r"1\d\d|[1-9]?\d)"
        r"\."
        r"){3}"
        r"(?:25[0-5]|2[0-4]\d|"
        r"1\d\d|[1-9]?\d)"
        r"\b"
    )

    addresses = re.findall(
        pattern,
        text
    )

    return list(
        dict.fromkeys(addresses)
    )


# =========================================================
# SENSITIVE DATA REQUEST DETECTION
# =========================================================

def detect_sensitive_requests(text):
    """
    Detect language asking the user to submit sensitive
    information.

    This is stronger evidence than generic words such as
    'login' or 'verification'.
    """

    patterns = {

        "password_request": [
            "enter your password",
            "provide your password",
            "submit your password",
            "confirm your password",
            "type your password"
        ],

        "credential_request": [
            "enter your username and password",
            "provide your credentials",
            "enter your credentials",
            "confirm your credentials"
        ],

        "otp_request": [
            "enter your otp",
            "provide your otp",
            "share your otp",
            "enter the verification code",
            "share the verification code"
        ],

        "financial_request": [
            "enter your card number",
            "enter your bank details",
            "provide your bank details",
            "enter your account number",
            "provide your credit card",
            "provide your debit card"
        ]
    }

    detected = {}

    for request_type, patterns_list in patterns.items():

        matches = []

        for phrase in patterns_list:

            if re.search(
                r"\b"
                + re.escape(phrase)
                + r"\b",
                text,
                flags=re.IGNORECASE
            ):

                matches.append(phrase)

        detected[request_type] = list(
            dict.fromkeys(matches)
        )

    return detected


# =========================================================
# CONTEXT ANALYSIS
# =========================================================

def analyze_context(
    normalized_text,
    categories,
    sensitive_requests
):
    """
    Determine whether keyword matches have meaningful
    suspicious context.

    Generic words such as 'login' or 'sign in' are not
    treated as strong phishing evidence.
    """

    context_signals = []

    credential_requests = (
        sensitive_requests.get(
            "password_request",
            []
        )
        + sensitive_requests.get(
            "credential_request",
            []
        )
    )

    otp_requests = sensitive_requests.get(
        "otp_request",
        []
    )

    financial_requests = sensitive_requests.get(
        "financial_request",
        []
    )

    urgency_detected = (
        categories["urgency"]["detected"]
    )

    account_takeover_detected = (
        categories["account_takeover"]["detected"]
    )

    # -----------------------------------------------------
    # Credential context
    # -----------------------------------------------------

    if credential_requests:

        context_signals.append(
            "Sensitive credential information is explicitly requested."
        )

    # -----------------------------------------------------
    # OTP context
    # -----------------------------------------------------

    if otp_requests:

        context_signals.append(
            "The email explicitly requests an OTP or verification code."
        )

    # -----------------------------------------------------
    # Financial context
    # -----------------------------------------------------

    if financial_requests:

        context_signals.append(
            "The email explicitly requests financial or banking information."
        )

    # -----------------------------------------------------
    # Urgency + account/security context
    # -----------------------------------------------------

    if (
        urgency_detected
        and (
            categories["credential_theft"]["detected"]
            or account_takeover_detected
            or categories["otp_fraud"]["detected"]
            or categories["financial_fraud"]["detected"]
        )
    ):

        context_signals.append(
            "Urgency is combined with account, credential, OTP or financial language."
        )

    # -----------------------------------------------------
    # Account takeover context
    # -----------------------------------------------------

    if account_takeover_detected:

        context_signals.append(
            "The email contains account-security or unauthorized-access language."
        )

    return context_signals


# =========================================================
# MAIN CONTENT ANALYZER
# =========================================================

def analyze_content(text):
    """
    Perform context-aware rule-based content analysis.

    The analyzer is intentionally conservative:
    generic words such as 'login', 'sign in', 'verification'
    and the presence of a URL do not automatically indicate
    phishing.
    """

    normalized_text = normalize_text(
        text
    )

    # -----------------------------------------------------
    # Empty input
    # -----------------------------------------------------

    if not normalized_text:

        return {
            "risk_score": 0,
            "risk_level": "LOW",
            "categories": {},
            "threat_categories": [
                "Insufficient Content"
            ],
            "explanations": [
                "No meaningful email body content was available for analysis."
            ],
            "indicators": {
                "has_url": False,
                "has_ip": False,
                "has_html_form_language": False,
                "sensitive_requests": {}
            },
            "total_keyword_matches": 0,
            "context_signals": []
        }

    # -----------------------------------------------------
    # CATEGORY ANALYSIS
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # URL / IP
    # -----------------------------------------------------

    urls = extract_urls(
        normalized_text
    )

    ip_addresses = extract_ipv4_addresses(
        normalized_text
    )

    has_url = bool(
        urls
    )

    has_ip = bool(
        ip_addresses
    )

    # -----------------------------------------------------
    # SENSITIVE REQUESTS
    # -----------------------------------------------------

    sensitive_requests = detect_sensitive_requests(
        normalized_text
    )

    has_sensitive_request = any(
        bool(matches)
        for matches in sensitive_requests.values()
    )

    # -----------------------------------------------------
    # HTML FORM LANGUAGE
    # -----------------------------------------------------

    html_form_phrases = [
        "enter your password",
        "enter your otp",
        "enter your card number",
        "enter your bank details",
        "enter your account number",
        "provide your credentials",
        "enter your credentials"
    ]

    html_form_matches = []

    for phrase in html_form_phrases:

        if phrase in normalized_text:

            html_form_matches.append(
                phrase
            )

    has_html_form_language = bool(
        html_form_matches
    )

    # -----------------------------------------------------
    # CONTEXT
    # -----------------------------------------------------

    context_signals = analyze_context(
        normalized_text,
        categories,
        sensitive_requests
    )

    # =====================================================
    # RISK SCORING
    # =====================================================

    score = 0.0

    # -----------------------------------------------------
    # 1. Generic keyword matches
    # -----------------------------------------------------
    #
    # Generic keywords have deliberately low weight.
    #
    # Example:
    # "Please sign in to GitHub"
    #
    # should NOT automatically become phishing.

    score += min(
        total_matches * 1.5,
        10
    )

    # -----------------------------------------------------
    # 2. Credential theft
    # -----------------------------------------------------

    if categories["credential_theft"]["detected"]:

        score += 8

    # Stronger if sensitive credentials are explicitly
    # requested.

    if (
        sensitive_requests.get(
            "password_request"
        )
        or sensitive_requests.get(
            "credential_request"
        )
    ):

        score += 20

    # -----------------------------------------------------
    # 3. Financial fraud
    # -----------------------------------------------------

    if categories["financial_fraud"]["detected"]:

        score += 10

    if sensitive_requests.get(
        "financial_request"
    ):

        score += 20

    # -----------------------------------------------------
    # 4. OTP fraud
    # -----------------------------------------------------

    if categories["otp_fraud"]["detected"]:

        score += 5

    if sensitive_requests.get(
        "otp_request"
    ):

        score += 15

    # -----------------------------------------------------
    # 5. Account takeover
    # -----------------------------------------------------

    if categories["account_takeover"]["detected"]:

        score += 8

    # -----------------------------------------------------
    # 6. Urgency
    # -----------------------------------------------------
    #
    # Urgency alone is weak evidence.

    if categories["urgency"]["detected"]:

        score += 5

    # -----------------------------------------------------
    # 7. Social engineering
    # -----------------------------------------------------

    if categories["social_engineering"]["detected"]:

        score += 5

    # -----------------------------------------------------
    # 8. URL
    # -----------------------------------------------------
    #
    # URL existence alone is NOT malicious.
    #
    # URL analyzer handles actual URL characteristics.

    if has_url:

        score += 1

    # -----------------------------------------------------
    # 9. IP
    # -----------------------------------------------------
    #
    # IP presence alone is NOT malicious.

    if has_ip:

        score += 0

    # -----------------------------------------------------
    # 10. Sensitive form language
    # -----------------------------------------------------

    if has_html_form_language:

        score += 15

    # -----------------------------------------------------
    # 11. Strong context combinations
    # -----------------------------------------------------

    if (
        has_sensitive_request
        and has_url
    ):

        score += 10

    if (
        categories["urgency"]["detected"]
        and has_sensitive_request
    ):

        score += 10

    if (
        categories["account_takeover"]["detected"]
        and has_url
        and has_sensitive_request
    ):

        score += 10

    # -----------------------------------------------------
    # Limit score
    # -----------------------------------------------------

    score = round(
        min(
            max(score, 0),
            100
        ),
        2
    )

    # =====================================================
    # RISK LEVEL
    # =====================================================

    if score >= 75:

        risk_level = "CRITICAL"

    elif score >= 50:

        risk_level = "HIGH"

    elif score >= 25:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    # =====================================================
    # THREAT CATEGORIES
    # =====================================================

    threat_categories = []

    # Credential phishing only when meaningful credential
    # evidence exists.

    if (
        categories["credential_theft"]["detected"]
        and (
            sensitive_requests.get(
                "password_request"
            )
            or sensitive_requests.get(
                "credential_request"
            )
            or categories["urgency"]["detected"]
        )
    ):

        threat_categories.append(
            "Credential Phishing"
        )

    # Financial fraud

    if (
        categories["financial_fraud"]["detected"]
        and (
            sensitive_requests.get(
                "financial_request"
            )
            or categories["urgency"]["detected"]
        )
    ):

        threat_categories.append(
            "Financial Fraud"
        )

    # OTP fraud

    if (
        categories["otp_fraud"]["detected"]
        and (
            sensitive_requests.get(
                "otp_request"
            )
            or categories["urgency"]["detected"]
        )
    ):

        threat_categories.append(
            "OTP Fraud"
        )

    # Account takeover

    if categories["account_takeover"]["detected"]:

        threat_categories.append(
            "Account Takeover"
        )

    # Social engineering

    if (
        categories["social_engineering"]["detected"]
        and (
            categories["urgency"]["detected"]
            or has_sensitive_request
        )
    ):

        threat_categories.append(
            "Social Engineering"
        )

    if not threat_categories:

        threat_categories.append(
            "No Major Content Threat Detected"
        )

    # =====================================================
    # EXPLANATIONS
    # =====================================================

    explanations = []

    # Credential explanation

    if sensitive_requests.get(
        "password_request"
    ):

        explanations.append(
            "The email explicitly requests password information."
        )

    elif sensitive_requests.get(
        "credential_request"
    ):

        explanations.append(
            "The email explicitly requests account credentials."
        )

    elif categories["credential_theft"]["detected"]:

        explanations.append(
            "Credential-related language was detected, "
            "but generic login/sign-in wording alone is "
            "not treated as proof of phishing."
        )

    # Financial

    if sensitive_requests.get(
        "financial_request"
    ):

        explanations.append(
            "The email explicitly requests banking or payment information."
        )

    elif categories["financial_fraud"]["detected"]:

        explanations.append(
            "Financial or transaction-related language was detected."
        )

    # OTP

    if sensitive_requests.get(
        "otp_request"
    ):

        explanations.append(
            "The email explicitly requests an OTP or verification code."
        )

    elif categories["otp_fraud"]["detected"]:

        explanations.append(
            "OTP or verification-code terminology was detected, "
            "but its presence alone does not prove fraud."
        )

    # Account takeover

    if categories["account_takeover"]["detected"]:

        explanations.append(
            "Account-security or unauthorized-access language was detected."
        )

    # Urgency

    if categories["urgency"]["detected"]:

        explanations.append(
            "Urgency-based language was detected and may "
            "pressure the recipient into immediate action."
        )

    # URL

    if has_url:

        explanations.append(
            str(len(urls))
            + " URL(s) were found. URL reputation and "
            "structure are evaluated separately by the URL analyzer."
        )

    # IP

    if has_ip:

        explanations.append(
            str(len(ip_addresses))
            + " IP address(es) were found in the email content. "
            "IP presence alone is not considered malicious."
        )

    # Context

    for signal in context_signals:

        if signal not in explanations:

            explanations.append(
                signal
            )

    # No suspicious evidence

    if not explanations:

        explanations.append(
            "No significant suspicious content patterns were detected."
        )

    # =====================================================
    # RETURN RESULT
    # =====================================================

    return {
        "risk_score": score,
        "risk_level": risk_level,

        "categories": categories,

        "threat_categories": threat_categories,

        "explanations": explanations,

        "indicators": {
            "has_url": has_url,
            "has_ip": has_ip,
            "has_html_form_language": has_html_form_language,
            "has_sensitive_request": has_sensitive_request,
            "sensitive_requests": sensitive_requests,
            "url_count": len(urls),
            "ip_count": len(ip_addresses)
        },

        "urls": urls,

        "ip_addresses": ip_addresses,

        "context_signals": context_signals,

        "total_keyword_matches": total_matches
    }