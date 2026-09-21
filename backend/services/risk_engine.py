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

    Important principles:
    - Public IP != malicious IP
    - Missing authentication != authentication failure
    - Low-confidence ML is only a supporting signal
    - Generic words such as "login" are not enough to mark phishing
    - Final verdict is based on correlated evidence
    """

    score = 0.0
    reasons = []
    evidence = []

    # =====================================================
    # 1. MACHINE LEARNING
    # =====================================================

    ml_available = bool(
        ml_result.get("available", False)
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

    ml_confidence_level = str(
        ml_result.get(
            "confidence_level",
            ""
        )
    ).upper()

    ml_usable = bool(
        ml_result.get(
            "usable_for_primary_verdict",
            False
        )
    )

    ml_score = 0.0

    if ml_available:

        # ML contributes only a limited amount.
        #
        # Low-confidence predictions do NOT receive
        # a strong score contribution.

        if ml_confidence >= 0.70:
            ml_score = min(
                ml_confidence * 15,
                15
            )

        elif ml_confidence >= 0.40:
            ml_score = min(
                ml_confidence * 8,
                5
            )

        else:
            ml_score = 0.0

        score += ml_score

        evidence.append({
            "source": "Machine Learning",
            "signal": ml_prediction,
            "confidence": round(
                ml_confidence * 100,
                2
            ),
            "confidence_level": (
                ml_confidence_level
                if ml_confidence_level
                else "UNKNOWN"
            ),
            "usable_for_primary_verdict": ml_usable,
            "score_contribution": round(
                ml_score,
                2
            )
        })

        # IMPORTANT:
        # Do not create a threat reason merely because
        # the model selected a non-legitimate class.
        #
        # Only strong/moderate model signals are reported
        # as meaningful evidence.

        if ml_usable and ml_prediction != "legitimate":

            severity = (
                "HIGH"
                if ml_confidence >= 0.70
                else "MEDIUM"
            )

            reasons.append({
                "category": "ML Threat Classification",
                "severity": severity,
                "message": (
                    "ML model classified the email as "
                    + ml_prediction.replace(
                        "_",
                        " "
                    ).title()
                    + " with "
                    + str(round(
                        ml_confidence * 100,
                        2
                    ))
                    + "% confidence."
                )
            })

        elif (
            ml_available
            and ml_confidence < 0.40
        ):

            reasons.append({
                "category": "ML Evidence",
                "severity": "LOW",
                "message": (
                    "ML classification confidence is low; "
                    "the model prediction is not used as "
                    "a primary threat verdict."
                )
            })

    else:

        evidence.append({
            "source": "Machine Learning",
            "signal": "unavailable",
            "confidence": 0,
            "confidence_level": "NONE",
            "usable_for_primary_verdict": False,
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

    header_score = 0.0

    spf = str(
        authentication.get(
            "spf",
            "NOT_FOUND"
        )
    ).upper()

    dkim = str(
        authentication.get(
            "dkim",
            "NOT_FOUND"
        )
    ).upper()

    dmarc = str(
        authentication.get(
            "dmarc",
            "NOT_FOUND"
        )
    ).upper()

    # -----------------------------------------------------
    # Header anomalies
    # -----------------------------------------------------

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

    # -----------------------------------------------------
    # SPF
    # -----------------------------------------------------

    if spf == "FAIL":

        header_score += 6

        reasons.append({
            "category": "Authentication",
            "severity": "HIGH",
            "message": (
                "SPF authentication failed."
            )
        })

    # -----------------------------------------------------
    # DKIM
    # -----------------------------------------------------

    if dkim == "FAIL":

        header_score += 6

        reasons.append({
            "category": "Authentication",
            "severity": "HIGH",
            "message": (
                "DKIM authentication failed."
            )
        })

    # -----------------------------------------------------
    # DMARC
    # -----------------------------------------------------

    if dmarc == "FAIL":

        header_score += 8

        reasons.append({
            "category": "Authentication",
            "severity": "HIGH",
            "message": (
                "DMARC authentication failed."
            )
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
        "score_contribution": round(
            header_score,
            2
        )
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

    # Number of extracted IOCs alone does not prove
    # maliciousness. URLs/emails/domains can be legitimate.
    #
    # Therefore IOC quantity receives only a small
    # supporting contribution.

    ioc_score = min(
        total_iocs * 0.5,
        5
    )

    score += ioc_score

    if total_iocs > 0:

        reasons.append({
            "category": "IOC Analysis",
            "severity": "LOW",
            "message": (
                str(total_iocs)
                + " indicators were extracted "
                "for further analysis."
            )
        })

    evidence.append({
        "source": "IOC Analysis",
        "total_iocs": total_iocs,
        "score_contribution": round(
            ioc_score,
            2
        )
    })

    # =====================================================
    # 4. URL ANALYSIS
    # =====================================================

    url_score = 0.0

    url_findings = []

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
            max(url_score, 0),
            15
        )

        url_findings = url_result.get(
            "findings",
            []
        )

        if url_score >= 7:

            reasons.append({
                "category": "URL Analysis",
                "severity": "HIGH",
                "message": (
                    "Suspicious URL characteristics "
                    "were detected."
                )
            })

        elif url_score > 0:

            reasons.append({
                "category": "URL Analysis",
                "severity": "MEDIUM",
                "message": (
                    "The email contains URL characteristics "
                    "that require further investigation."
                )
            })

    score += url_score

    evidence.append({
        "source": "URL Analysis",
        "score_contribution": round(
            url_score,
            2
        ),
        "findings": url_findings
    })

    # =====================================================
    # 5. IP ANALYSIS
    # =====================================================

    ip_score = 0.0

    ip_findings = []

    if isinstance(
        ip_result,
        dict
    ):

        # IMPORTANT:
        # A public IP is normal.
        # Do not automatically add risk because
        # an IP is externally routable.

        ip_score = float(
            ip_result.get(
                "score",
                0
            )
        )

        ip_score = min(
            max(ip_score, 0),
            5
        )

        ip_findings = ip_result.get(
            "results",
            []
        )

        # Only report IP risk if the IP analysis itself
        # has an actual suspicious finding.

        if ip_score > 0:

            reasons.append({
                "category": "IP Intelligence",
                "severity": "MEDIUM",
                "message": (
                    "IP analysis identified a special-use "
                    "or otherwise noteworthy IP characteristic."
                )
            })

    score += ip_score

    evidence.append({
        "source": "IP Intelligence",
        "score_contribution": round(
            ip_score,
            2
        ),
        "findings": ip_findings
    })

    # =====================================================
    # 6. CONTENT ANALYSIS
    # =====================================================

    content_score = 0.0

    raw_content_score = 0.0

    content_categories = []

    content_indicators = {}

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

        content_indicators = content_result.get(
            "indicators",
            {}
        )

        # Content is capped at 20 points.

        content_score = min(
            max(raw_content_score * 0.20, 0),
            20
        )

        score += content_score

        # Do not call generic login/sign-in language
        # automatically malicious.

        meaningful_content_signal = (
            raw_content_score >= 50
            or len(content_categories) >= 2
        )

        if meaningful_content_signal:

            reasons.append({
                "category": "Content Analysis",
                "severity": (
                    "HIGH"
                    if raw_content_score >= 70
                    else "MEDIUM"
                ),
                "message": (
                    "Content analysis identified "
                    "potentially suspicious language patterns: "
                    + (
                        ", ".join(
                            str(category)
                            for category in content_categories
                        )
                        if content_categories
                        else "suspicious content"
                    )
                )
            })

    evidence.append({
        "source": "Content Analysis",
        "raw_score": raw_content_score,
        "categories": content_categories,
        "indicators": content_indicators,
        "score_contribution": round(
            content_score,
            2
        )
    })

    # =====================================================
    # 7. FORENSIC CORRELATION
    # =====================================================

    forensic_bonus = 0.0

    failed_auth_count = 0

    if spf == "FAIL":
        failed_auth_count += 1

    if dkim == "FAIL":
        failed_auth_count += 1

    if dmarc == "FAIL":
        failed_auth_count += 1

    # -----------------------------------------------------
    # Multiple authentication failures
    # -----------------------------------------------------

    if failed_auth_count >= 2:

        forensic_bonus += 10

        reasons.append({
            "category": "Forensic Correlation",
            "severity": "HIGH",
            "message": (
                "Multiple sender authentication "
                "mechanisms failed."
            )
        })

    # -----------------------------------------------------
    # Strong content correlation
    # -----------------------------------------------------

    lower_categories = [
        str(category).lower()
        for category in content_categories
    ]

    high_risk_categories = {
        "financial fraud",
        "otp fraud",
        "credential theft",
        "account takeover",
        "social engineering"
    }

    detected_high_risk_categories = [
        category
        for category in lower_categories
        if category in high_risk_categories
    ]

    # Require stronger content evidence before
    # applying a correlation bonus.

    if (
        detected_high_risk_categories
        and raw_content_score >= 50
    ):

        forensic_bonus += 8

        reasons.append({
            "category": "Threat Correlation",
            "severity": "HIGH",
            "message": (
                "Content analysis indicates a "
                "potentially high-risk "
                "social-engineering or fraud pattern."
            )
        })

    # -----------------------------------------------------
    # BEC correlation
    # -----------------------------------------------------

    # CRITICAL CHANGE:
    #
    # Low-confidence ML prediction of BEC alone
    # cannot create a CRITICAL finding.

    strong_bec_signal = (
        ml_prediction == "bec"
        and ml_confidence >= 0.70
        and ml_usable
    )

    content_bec_signal = any(
        "bec" in category
        or "business email compromise" in category
        for category in lower_categories
    )

    if (
        strong_bec_signal
        or (
            content_bec_signal
            and raw_content_score >= 60
        )
    ):

        forensic_bonus += 10

        reasons.append({
            "category": "BEC Detection",
            "severity": "HIGH",
            "message": (
                "Multiple available signals support "
                "a Business Email Compromise pattern."
            )
        })

    # -----------------------------------------------------
    # Header anomaly + authentication failure
    # -----------------------------------------------------

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
        25
    )

    score += forensic_bonus

    evidence.append({
        "source": "Forensic Correlation",
        "score_contribution": round(
            forensic_bonus,
            2
        )
    })

    # =====================================================
    # 8. FINAL SCORE
    # =====================================================

    score = round(
        min(
            max(score, 0),
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

    # Strong ML signal gets priority.

    if (
        ml_usable
        and ml_prediction != "legitimate"
        and ml_confidence >= 0.70
    ):

        primary_threat = ml_prediction

    # Otherwise use meaningful content evidence.

    elif (
        content_categories
        and raw_content_score >= 50
    ):

        primary_threat = str(
            content_categories[0]
        )

    # If there are strong forensic signals but no
    # reliable threat category, keep it generic.

    elif (
        failed_auth_count >= 2
        or anomaly_count >= 2
        or url_score >= 10
    ):

        primary_threat = "suspicious_activity"

    else:

        primary_threat = "legitimate"

    # =====================================================
    # 11. FINAL VERDICT
    # =====================================================

    strong_forensic_signal = (
        failed_auth_count >= 2
        or anomaly_count >= 2
        or url_score >= 10
        or (
            raw_content_score >= 70
            and bool(content_categories)
        )
        or (
            ml_usable
            and ml_prediction != "legitimate"
            and ml_confidence >= 0.70
        )
    )

    moderate_forensic_signal = (
        anomaly_count >= 1
        or failed_auth_count >= 1
        or url_score >= 5
        or (
            raw_content_score >= 50
            and bool(content_categories)
        )
        or (
            ml_usable
            and ml_prediction != "legitimate"
            and ml_confidence >= 0.40
        )
    )

    # -----------------------------------------------------
    # Likely phishing / threat
    # -----------------------------------------------------

    if (
        risk_level in {"HIGH", "CRITICAL"}
        and strong_forensic_signal
    ):

        verdict = "LIKELY_THREAT"
        threat_detected = True

    # -----------------------------------------------------
    # Suspicious
    # -----------------------------------------------------

    elif (
        risk_level == "MEDIUM"
        and moderate_forensic_signal
    ):

        verdict = "SUSPICIOUS"
        threat_detected = True

    # -----------------------------------------------------
    # Insufficient evidence
    # -----------------------------------------------------

    elif (
        ml_available
        and ml_confidence < 0.40
        and not strong_forensic_signal
        and not moderate_forensic_signal
    ):

        verdict = "INSUFFICIENT_EVIDENCE"
        threat_detected = False

    # -----------------------------------------------------
    # Likely legitimate
    # -----------------------------------------------------

    else:

        verdict = "LIKELY_LEGITIMATE"
        threat_detected = False

    # =====================================================
    # 12. AUTHENTICATION SUMMARY
    # =====================================================

    authentication_summary = {
        "spf": spf,
        "dkim": dkim,
        "dmarc": dmarc
    }

    # =====================================================
    # 13. RECOMMENDED ACTION
    # =====================================================

    if verdict == "LIKELY_THREAT":

        recommended_action = (
            "Treat the email as potentially malicious. "
            "Verify the sender through an independent channel, "
            "inspect URLs and IOCs, and perform forensic "
            "investigation before interacting with the message."
        )

    elif verdict == "SUSPICIOUS":

        recommended_action = (
            "Perform additional investigation. "
            "Verify sender identity, inspect authentication "
            "results, URLs, content and available IOCs."
        )

    elif verdict == "INSUFFICIENT_EVIDENCE":

        recommended_action = (
            "The available evidence is insufficient for a "
            "reliable threat classification. Review the "
            "original headers and additional forensic evidence."
        )

    else:

        recommended_action = (
            "No strong malicious indicators were identified "
            "by the available forensic signals. Continue "
            "normal monitoring and verify unexpected requests."
        )

    # =====================================================
    # 14. EVIDENCE SUMMARY
    # =====================================================

    evidence_summary = {
        "ml": {
            "available": ml_available,
            "prediction": ml_prediction,
            "confidence_percent": round(
                ml_confidence * 100,
                2
            ),
            "usable_for_primary_verdict": ml_usable
        },
        "authentication": authentication_summary,
        "header_anomalies": anomaly_count,
        "ioc_count": total_iocs,
        "url_score": round(
            url_score,
            2
        ),
        "ip_score": round(
            ip_score,
            2
        ),
        "content_score": round(
            raw_content_score,
            2
        )
    }

    # =====================================================
    # 15. FINAL RESULT
    # =====================================================

    return {
        "score": score,
        "level": risk_level,
        "verdict": verdict,
        "threat_detected": threat_detected,
        "primary_threat": primary_threat,
        "reasons": reasons,
        "evidence": evidence,
        "evidence_summary": evidence_summary,
        "recommended_action": recommended_action
    }