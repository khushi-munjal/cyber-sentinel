import os
import joblib


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


def predict_email(text):
    """
    Predict the primary cyber threat category
    for an email using the trained ML model.
    """

    model = load_model()

    if model is None:

        return {
            "available": False,
            "prediction": "MODEL_NOT_TRAINED",
            "display_name": "ML Model Not Trained",
            "confidence": 0.0,
            "probabilities": {},
            "message": (
                "ML model is not available. "
                "Train the model first."
            )
        }

    try:

        text = str(text)

        prediction = model.predict(
            [text]
        )[0]

        probabilities = model.predict_proba(
            [text]
        )[0]

        classes = list(
            model.classes_
        )

        probability_map = {}

        for label, probability in zip(
            classes,
            probabilities
        ):

            probability_map[str(label)] = round(
                float(probability),
                4
            )

        prediction = str(
            prediction
        ).lower()

        confidence = probability_map.get(
            prediction,
            0.0
        )

        display_name = THREAT_NAMES.get(
            prediction,
            prediction.replace(
                "_",
                " "
            ).title()
        )

        sorted_probabilities = sorted(
            probability_map.items(),
            key=lambda item: item[1],
            reverse=True
        )

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
                "probability": probability
            })

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
            "probabilities": probability_map,
            "top_predictions": top_predictions
        }

    except Exception as error:

        return {
            "available": False,
            "prediction": "ERROR",
            "display_name": "ML Prediction Error",
            "confidence": 0.0,
            "probabilities": {},
            "message": str(error)
        }