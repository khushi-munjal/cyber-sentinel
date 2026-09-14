import os
import pandas as pd
import joblib

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report


# ============================================================
# PATH CONFIGURATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

DATASET_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "training_data.csv"
)

MODEL_PATH = os.path.join(
    BASE_DIR,
    "ml",
    "model.pkl"
)


# ============================================================
# MAILTRACE AI - 10 THREAT CLASSES
# ============================================================

ALLOWED_LABELS = {
    "legitimate",
    "phishing",
    "spoofing",
    "bec",
    "credential_theft",
    "financial_fraud",
    "otp_fraud",
    "account_takeover",
    "social_engineering",
    "malware_delivery"
}


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model():

    print("\n==============================================")
    print("          MAILTRACE AI ML TRAINING")
    print("==============================================")

    # --------------------------------------------------------
    # Check dataset
    # --------------------------------------------------------

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"\nTraining dataset not found:\n{DATASET_PATH}"
        )

    print(f"\nDataset found:")
    print(DATASET_PATH)

    # --------------------------------------------------------
    # Load dataset
    # --------------------------------------------------------

    data = pd.read_csv(DATASET_PATH)

    print(f"\nTotal dataset rows: {len(data)}")

    # --------------------------------------------------------
    # Check required columns
    # --------------------------------------------------------

    required_columns = [
        "text",
        "label"
    ]

    for column in required_columns:

        if column not in data.columns:

            raise ValueError(
                f"Dataset must contain column: {column}"
            )

    # --------------------------------------------------------
    # Remove empty rows
    # --------------------------------------------------------

    data = data.dropna(
        subset=[
            "text",
            "label"
        ]
    )

    # --------------------------------------------------------
    # Clean text and labels
    # --------------------------------------------------------

    data["text"] = (
        data["text"]
        .astype(str)
        .str.strip()
    )

    data["label"] = (
        data["label"]
        .astype(str)
        .str.lower()
        .str.strip()
    )

    # --------------------------------------------------------
    # Keep only supported threat classes
    # --------------------------------------------------------

    data = data[
        data["label"].isin(ALLOWED_LABELS)
    ]

    if data.empty:

        raise ValueError(
            "\nNo valid training data found.\n"
            "Check the label column in training_data.csv."
        )

    # --------------------------------------------------------
    # Display class distribution
    # --------------------------------------------------------

    label_counts = data["label"].value_counts()

    print("\n==============================================")
    print("             TRAINING CLASSES")
    print("==============================================")

    for label in sorted(ALLOWED_LABELS):

        count = int(
            label_counts.get(label, 0)
        )

        print(
            f"{label:<22} : {count} samples"
        )

    # --------------------------------------------------------
    # Make sure all 10 classes exist
    # --------------------------------------------------------

    missing_classes = (
        ALLOWED_LABELS
        - set(label_counts.index)
    )

    if missing_classes:

        print("\nWARNING:")
        print("The following classes are missing:")

        for label in sorted(missing_classes):
            print(f"  - {label}")

        raise ValueError(
            "\nYour training_data.csv must contain "
            "all 10 MailTrace AI threat classes."
        )

    # --------------------------------------------------------
    # Every class needs at least 2 samples
    # --------------------------------------------------------

    if label_counts.min() < 2:

        raise ValueError(
            "\nEvery threat class must contain "
            "at least 2 training examples."
        )

    # --------------------------------------------------------
    # Prepare training data
    # --------------------------------------------------------

    X = data["text"]
    y = data["label"]

    # --------------------------------------------------------
    # Train / test split
    # --------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=42,
        stratify=y
    )

    print("\n==============================================")
    print("             DATASET SPLIT")
    print("==============================================")

    print(
        f"Training samples : {len(X_train)}"
    )

    print(
        f"Testing samples  : {len(X_test)}"
    )

    # --------------------------------------------------------
    # TF-IDF + Logistic Regression
    # --------------------------------------------------------

    model = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    lowercase=True,
                    stop_words="english",
                    ngram_range=(1, 2),
                    max_features=15000,
                    sublinear_tf=True
                )
            ),

            (
                "classifier",
                LogisticRegression(
                    max_iter=3000,
                    class_weight="balanced",
                    random_state=42
                )
            )
        ]
    )

    # --------------------------------------------------------
    # Train
    # --------------------------------------------------------

    print("\n==============================================")
    print("             TRAINING MODEL")
    print("==============================================")

    print(
        "\nTraining TF-IDF + Logistic Regression..."
    )

    model.fit(
        X_train,
        y_train
    )

    print(
        "Training completed successfully."
    )

    # --------------------------------------------------------
    # Evaluate
    # --------------------------------------------------------

    predictions = model.predict(
        X_test
    )

    print("\n==============================================")
    print("             MODEL EVALUATION")
    print("==============================================")

    print(
        classification_report(
            y_test,
            predictions,
            labels=sorted(ALLOWED_LABELS),
            zero_division=0
        )
    )

    # --------------------------------------------------------
    # Save trained model
    # --------------------------------------------------------

    joblib.dump(
        model,
        MODEL_PATH
    )

    print("\n==============================================")
    print("          MODEL TRAINING COMPLETE")
    print("==============================================")

    print(
        f"\nModel saved successfully at:"
    )

    print(
        MODEL_PATH
    )

    # --------------------------------------------------------
    # Display detected classes
    # --------------------------------------------------------

    print("\n==============================================")
    print("             DETECTED CLASSES")
    print("==============================================")

    for class_name in model.classes_:

        print(
            f"  ✓ {class_name}"
        )

    print("\n==============================================")
    print("        MAILTRACE AI MODEL READY")
    print("==============================================\n")


# ============================================================
# RUN TRAINING
# ============================================================

if __name__ == "__main__":

    train_model()