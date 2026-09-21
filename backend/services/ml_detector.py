import os
import joblib


# =========================================================
# MODEL PATH
# =========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "model.pkl"
)


# =========================================================
# THREAT LABELS
# =========================================================

THREAT_NAMES = {
    "legitimate": "Legitimate Email",
    "phishing": "Phishing",
    "spoofing": "Spoofing / Impersonation",
    "bec": "Business Email Compromise",
    "credential_theft": "Credential Theft",
    "financial_fraud": "Financial Fraud",
    "otp_fraud": "OTP Fraud",
    "account_takeover": "Account Takeover",
    "social_engineering": "Social Engineering",
    "malware_delivery": "Malware Delivery"
}


# =========================================================
# CONFIDENCE THRESHOLDS
# =========================================================
#
# These thresholds prevent a nearly-uniform probability
# distribution from being presented as a strong detection.
#
# Example:
#
# BEC         11.85%
# Spoofing    11.35%
# ATO         10.68%
#
# This is NOT a confident BEC prediction.
#
# =========================================================

STRONG_CONFIDENCE = 0.70
MODERATE_CONFIDENCE = 0.40


# =========================================================
# LOAD MODEL
# =========================================================

def load_model():
    """
    Load the trained MailTrace AI ML model.
    """

    if not os.path.exists(MODEL_PATH):
        return None

    try:

        return joblib.load(
            MODEL_PATH
        )

    except Exception:

        return None


# =========================================================
# CONFIDENCE INTERPRETATION
# =========================================================

def classify_confidence(confidence):
    """
    Convert model probability into an interpretable
    confidence category.

    IMPORTANT:
    This does not mean the probability is calibrated.
    It only prevents very weak predictions from being
    presented as strong detections.
    """

    confidence = float(confidence)

    if confidence >= STRONG_CONFIDENCE:

        return {
            "level": "HIGH",
            "status": "STRONG_MODEL_SIGNAL",
            "usable_for_primary_verdict": True
        }

    if confidence >= MODERATE_CONFIDENCE:

        return {
            "level": "MEDIUM",
            "status": "MODERATE_MODEL_SIGNAL",
            "usable_for_primary_verdict": True
        }

    return {
        "level": "LOW",
        "status": "LOW_CONFIDENCE",
        "usable_for_primary_verdict": False
    }


# =========================================================
# PREDICT EMAIL
# =========================================================

def predict_email(text):
    """
    Predict the primary cyber threat category
    for an email using the trained ML model.

    The ML prediction is treated as ONE signal.
    It is not automatically treated as proof of phishing,
    BEC, spoofing, or any other threat.
    """

    model = load_model()

    # -----------------------------------------------------
    # MODEL UNAVAILABLE
    # -----------------------------------------------------

    if model is None:

        return {
            "available": False,
            "prediction": "MODEL_NOT_TRAINED",
            "display_name": "ML Model Not Trained",
            "confidence": 0.0,
            "confidence_percent": 0.0,
            "confidence_level": "NONE",
            "classification_status": "MODEL_UNAVAILABLE",
            "usable_for_primary_verdict": False,
            "probabilities": {},
            "top_predictions": [],
            "message": (
                "ML model is not available. "
                "Train the model first."
            )
        }

    try:

        # -------------------------------------------------
        # CLEAN INPUT
        # -------------------------------------------------

        text = str(text).strip()

        if not text:

            return {
                "available": False,
                "prediction": "INSUFFICIENT_INPUT",
                "display_name": "Insufficient Email Content",
                "confidence": 0.0,
                "confidence_percent": 0.0,
                "confidence_level": "NONE",
                "classification_status": "INSUFFICIENT_INPUT",
                "usable_for_primary_verdict": False,
                "probabilities": {},
                "top_predictions": [],
                "message": (
                    "No meaningful email content was "
                    "available for ML classification."
                )
            }

        # -------------------------------------------------
        # MODEL PREDICTION
        # -------------------------------------------------

        prediction_result = model.predict(
            [text]
        )

        prediction = str(
            prediction_result[0]
        ).lower()

        # -------------------------------------------------
        # PROBABILITIES
        # -------------------------------------------------

        if hasattr(model, "predict_proba"):

            probabilities = model.predict_proba(
                [text]
            )[0]

            classes = list(
                model.classes_
            )

        else:

            probabilities = []

            classes = []

        probability_map = {}

        for label, probability in zip(
            classes,
            probabilities
        ):

            probability_map[
                str(label).lower()
            ] = round(
                float(probability),
                4
            )

        # -------------------------------------------------
        # MODEL CONFIDENCE
        # -------------------------------------------------

        confidence = probability_map.get(
            prediction,
            0.0
        )

        # -------------------------------------------------
        # SORT ALL PREDICTIONS
        # -------------------------------------------------

        sorted_probabilities = sorted(
            probability_map.items(),
            key=lambda item: item[1],
            reverse=True
        )

        # -------------------------------------------------
        # TOP PREDICTIONS
        # -------------------------------------------------

        top_predictions = []

        for label, probability in sorted_probabilities[:5]:

            top_predictions.append({
                "label": label,

                "name": THREAT_NAMES.get(
                    label,
                    label.replace(
                        "_",
                        " "
                    ).title()
                ),

                "probability": probability,

                "probability_percent": round(
                    probability * 100,
                    2
                )
            })

        # -------------------------------------------------
        # CONFIDENCE CATEGORY
        # -------------------------------------------------

        confidence_info = classify_confidence(
            confidence
        )

        # -------------------------------------------------
        # DISPLAY NAME
        # -------------------------------------------------

        display_name = THREAT_NAMES.get(
            prediction,
            prediction.replace(
                "_",
                " "
            ).title()
        )

        # -------------------------------------------------
        # HUMAN-READABLE MESSAGE
        # -------------------------------------------------

        if (
            confidence_info["level"] == "HIGH"
        ):

            message = (
                "The ML model produced a strong "
                "classification signal. This should "
                "still be evaluated together with "
                "email headers, URLs, IOCs, and "
                "content evidence."
            )

        elif (
            confidence_info["level"] == "MEDIUM"
        ):

            message = (
                "The ML model produced a moderate "
                "classification signal. Additional "
                "forensic evidence should be considered "
                "before reaching a final verdict."
            )

        else:

            message = (
                "The ML model produced a low-confidence "
                "classification. The top class should "
                "not be treated as a confirmed threat "
                "without supporting forensic evidence."
            )

        # -------------------------------------------------
        # FINAL RESULT
        # -------------------------------------------------

        return {

            "available": True,

            "prediction": prediction,

            "display_name": display_name,

            "confidence": round(
                confidence,
                4
            ),

            "confidence_percent": round(
                confidence * 100,
                2
            ),

            "confidence_level": (
                confidence_info["level"]
            ),

            "classification_status": (
                confidence_info["status"]
            ),

            "usable_for_primary_verdict": (
                confidence_info[
                    "usable_for_primary_verdict"
                ]
            ),

            "probabilities": probability_map,

            "top_predictions": top_predictions,

            "message": message
        }

    except Exception as error:

        return {

            "available": False,

            "prediction": "ERROR",

            "display_name": "ML Prediction Error",

            "confidence": 0.0,

            "confidence_percent": 0.0,

            "confidence_level": "NONE",

            "classification_status": "MODEL_ERROR",

            "usable_for_primary_verdict": False,

            "probabilities": {},

            "top_predictions": [],

            "message": str(error)
        }