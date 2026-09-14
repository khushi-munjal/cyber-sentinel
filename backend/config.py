import os
from dotenv import load_dotenv

load_dotenv()

PROJECT_NAME = "MailTrace AI"
VERSION = "3.0.0"

DATABASE_NAME = "mailtrace.db"

MODEL_PATH = os.path.join("ml", "model.pkl")

REPORTS_DIR = "reports"
DEMO_EMAILS_DIR = "demo_emails"

MAX_FILE_SIZE_MB = 10

INVESTIGATOR_LATITUDE = 29.3909
INVESTIGATOR_LONGITUDE = 76.9635
INVESTIGATOR_LOCATION_NAME = "smalkha, Haryana, India"