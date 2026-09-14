def calculate_risk(
    ml_result,
    header_result,
    ioc_result,
    url_result,
    ip_result,
    content_result
):
    """
    Explainable hybrid risk engine.

    Combines:
    - Machine Learning
    - Header forensics
    - SPF/DKIM/DMARC
    - IOC analysis
    - URL analysis
    - IP intelligence
    - Content analysis

    The final score is 0-100.
    """

    score = 0.0
    reasons = []
    evidence = []

    # =====================================================
    # 1. MACHINE LEARNING
    # =====================================================

    ml_available = ml_result.get(
        "available",
        False
    )

    ml_prediction = str(
        ml_result.get(
            "prediction",
            "unknown"
        )
    ).lower()

    ml_confidence = float(
        ml_result.get(
            "confidence",
            0.0
        )
    )

    if ml_available:

        # ML is a supporting signal.
        # We intentionally do NOT allow low model confidence
        # to hide strong forensic evidence.
        ml_score = min(
            ml_confidence * 20,
            20
        )

        score += ml_score

        evidence.append({
            "source": "Machine Learning",
            "signal": ml_prediction,
            "confidence": round(
                ml_confidence * 100,
                2
            ),
            "score_contribution": round(
                ml_score,
                2
            )
        })

        if ml_prediction != "legitimate":

            reasons.append({
                "category": "ML Threat Classification",
                "severity": "HIGH",
                "message": (
                    "ML model identified the email as "
                    + ml_prediction.replace(
                        "_",
                        " "
                    ).title()
                    + "."
                )
            })

    else:

        evidence.append({
            "source": "Machine Learning",
            "signal": "unavailable",
            "confidence": 0,
            "score_contribution": 0
        })


    # =====================================================
    # 2. HEADER FORENSICS
    # =====================================================

    anomaly_count = int(
        header_result.get(
            "anomaly_count",
            0
        )
    )

    authentication = header_result.get(
        "authentication",
        {}
    )

    header_score = 0

    # Header anomalies
    if anomaly_count > 0:

        anomaly_score = min(
            anomaly_count * 8,
            20
        )

        header_score += anomaly_score

        for anomaly in header_result.get(
            "anomalies",
            []
        ):

            reasons.append({
                "category": "Header Forensics",
                "severity": anomaly.get(
                    "severity",
                    "MEDIUM"
                ),
                "message": anomaly.get(
                    "message",
                    "Email header anomaly detected."
                )
            })


    # SPF
    spf = str(
        authentication.get(
            "spf",
            "NOT_FOUND"
        )
    ).upper()

    if spf == "FAIL":

        header_score += 6

        reasons.append({
            "category": "Authentication",
            "severity": "HIGH",
            "message": "SPF authentication failed."
        })


    # DKIM
    dkim = str(
        authentication.get(
            "dkim",
            "NOT_FOUND"
        )
    ).upper()

    if dkim == "FAIL":

        header_score += 6

        reasons.append({
            "category": "Authentication",
            "severity": "HIGH",
            "message": "DKIM authentication failed."
        })


    # DMARC
    dmarc = str(
        authentication.get(
            "dmarc",
            "NOT_FOUND"
        )
    ).upper()

    if dmarc == "FAIL":

        header_score += 8

        reasons.append({
            "category": "Authentication",
            "severity": "HIGH",
            "message": "DMARC authentication failed."
        })


    header_score = min(
        header_score,
        30
    )

    score += header_score

    evidence.append({
        "source": "Header Forensics",
        "anomalies": anomaly_count,
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc,
        "score_contribution": header_score
    })


    # =====================================================
    # 3. IOC ANALYSIS
    # =====================================================

    ioc_summary = ioc_result.get(
        "summary",
        {}
    )

    total_iocs = int(
        ioc_summary.get(
            "total_iocs",
            0
        )
    )

    ioc_score = min(
        total_iocs * 2,
        10
    )

    score += ioc_score

    if total_iocs > 0:

        reasons.append({
            "category": "IOC Analysis",
            "severity": "MEDIUM",
            "message": (
                str(total_iocs)
                + " indicators of compromise "
                + "were extracted."
            )
        })

    evidence.append({
        "source": "IOC Analysis",
        "total_iocs": total_iocs,
        "score_contribution": ioc_score
    })


    # =====================================================
    # 4. URL ANALYSIS
    # =====================================================

    url_score = 0.0

    if isinstance(
        url_result,
        dict
    ):

        url_score = float(
            url_result.get(
                "score",
                0
            )
        )

        url_score = min(
            url_score,
            10
        )

        if url_score > 0:

            reasons.append({
                "category": "URL Analysis",
                "severity": (
                    "HIGH"
                    if url_score >= 7
                    else "MEDIUM"
                ),
                "message": (
                    "Suspicious URL characteristics "
                    "were detected."
                )
            })

    score += url_score

    evidence.append({
        "source": "URL Analysis",
        "score_contribution": round(
            url_score,
            2
        )
    })


    # =====================================================
    # 5. IP ANALYSIS
    # =====================================================

    ip_score = 0.0

    if isinstance(
        ip_result,
        dict
    ):

        ip_score = float(
            ip_result.get(
                "score",
                0
            )
        )

        ip_score = min(
            ip_score,
            5
        )

        if ip_score > 0:

            reasons.append({
                "category": "IP Intelligence",
                "severity": "MEDIUM",
                "message": (
                    "Suspicious or externally routable "
                    "IP infrastructure was detected."
                )
            })

    score += ip_score

    evidence.append({
        "source": "IP Intelligence",
        "score_contribution": round(
            ip_score,
            2
        )
    })


    # =====================================================
    # 6. CONTENT ANALYSIS
    # =====================================================

    content_score = 0.0

    raw_content_score = 0.0

    content_categories = []

    if isinstance(
        content_result,
        dict
    ):

        raw_content_score = float(
            content_result.get(
                "risk_score",
                0
            )
        )

        content_categories = content_result.get(
            "threat_categories",
            []
        )

        # Content gets up to 20 points.
        content_score = min(
            raw_content_score * 0.20,
            20
        )

        score += content_score

        if raw_content_score > 0:

            reasons.append({
                "category": "Content Analysis",
                "severity": (
                    "HIGH"
                    if raw_content_score >= 60
                    else "MEDIUM"
                ),
                "message": (
                    "Suspicious language patterns detected: "
                    + (
                        ", ".join(
                            content_categories
                        )
                        if content_categories
                        else
                        "suspicious content"
                    )
                )
            })

    evidence.append({
        "source": "Content Analysis",
        "raw_score": raw_content_score,
        "categories": content_categories,
        "score_contribution": round(
            content_score,
            2
        )
    })


    # =====================================================
    # 7. STRONG FORENSIC SIGNALS
    # =====================================================
    #
    # These rules prevent a low-confidence ML prediction
    # from incorrectly marking an obviously suspicious email
    # as LOW risk.
    #

    forensic_bonus = 0

    failed_auth_count = 0

    if spf == "FAIL":
        failed_auth_count += 1

    if dkim == "FAIL":
        failed_auth_count += 1

    if dmarc == "FAIL":
        failed_auth_count += 1


    # Multiple authentication failures
    if failed_auth_count >= 2:

        forensic_bonus += 10

        reasons.append({
            "category": "Forensic Correlation",
            "severity": "HIGH",
            "message": (
                "Multiple email authentication "
                "mechanisms failed."
            )
        })


    # Strong social-engineering/payment signal
    lower_categories = [
        str(category).lower()
        for category in content_categories
    ]

    payment_signal = any(
        keyword in lower_categories
        for keyword in [
            "financial fraud",
            "account takeover",
            "credential theft",
            "social engineering",
            "otp fraud"
        ]
    )

    if payment_signal:

        forensic_bonus += 10

        reasons.append({
            "category": "Threat Correlation",
            "severity": "HIGH",
            "message": (
                "Content analysis indicates a "
                "high-risk social-engineering or "
                "fraud-related pattern."
            )
        })


    # BEC-specific correlation
    if (
        ml_prediction == "bec"
        or "bec" in lower_categories
    ):

        forensic_bonus += 15

        reasons.append({
            "category": "BEC Detection",
            "severity": "CRITICAL",
            "message": (
                "Business Email Compromise indicators "
                "were detected."
            )
        })


    # Header anomaly + failed authentication
    if (
        anomaly_count > 0
        and failed_auth_count >= 1
    ):

        forensic_bonus += 8

        reasons.append({
            "category": "Identity Forensics",
            "severity": "HIGH",
            "message": (
                "Header anomalies correlate with "
                "failed sender authentication."
            )
        })


    forensic_bonus = min(
        forensic_bonus,
        35
    )

    score += forensic_bonus

    evidence.append({
        "source": "Forensic Correlation",
        "score_contribution": forensic_bonus
    })


    # =====================================================
    # 8. FINAL SCORE
    # =====================================================

    score = round(
        min(
            max(
                score,
                0
            ),
            100
        ),
        2
    )


    # =====================================================
    # 9. RISK LEVEL
    # =====================================================

    if score >= 80:

        risk_level = "CRITICAL"

    elif score >= 60:

        risk_level = "HIGH"

    elif score >= 35:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"


    # =====================================================
    # 10. PRIMARY THREAT
    # =====================================================

    if (
        ml_available
        and ml_prediction != "legitimate"
    ):

        primary_threat = ml_prediction

    elif content_categories:

        primary_threat = content_categories[0]

    else:

        primary_threat = "legitimate"


    # =====================================================
    # 11. THREAT DETECTED
    # =====================================================

    threat_detected = (
        primary_threat != "legitimate"
        and risk_level != "LOW"
    )


    # =====================================================
    # 12. RECOMMENDED ACTION
    # =====================================================

    if risk_level == "CRITICAL":

        recommended_action = (
            "Immediate containment, sender verification "
            "and forensic investigation recommended."
        )

    elif risk_level == "HIGH":

        recommended_action = (
            "Investigate sender, authentication results, "
            "content and available IOCs immediately."
        )

    elif risk_level == "MEDIUM":

        recommended_action = (
            "Further investigation and manual "
            "verification recommended."
        )

    else:

        recommended_action = (
            "No immediate threat detected; "
            "continue normal monitoring."
        )


    # =====================================================
    # 13. FINAL RESULT
    # =====================================================

    return {
        "score": score,
        "level": risk_level,
        "threat_detected": threat_detected,
        "primary_threat": primary_threat,
        "reasons": reasons,
        "evidence": evidence,
        "recommended_action": recommended_action
    }