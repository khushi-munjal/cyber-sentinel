import os
import uuid
import tempfile
from datetime import datetime

from fastapi import (
    FastAPI,
    UploadFile,
    File,
    HTTPException
)

from fastapi.middleware.cors import CORSMiddleware

from fastapi.responses import (
    JSONResponse,
    FileResponse
)

from database import (
    init_db,
    save_case,
    get_cases
)

from services.email_parser import parse_email
from services.header_analyzer import analyze_headers
from services.ioc_extractor import extract_iocs
from services.url_analyzer import analyze_urls
from services.ip_analyzer import analyze_ips
from services.content_analyzer import analyze_content
from services.ml_detector import predict_email
from services.risk_engine import calculate_risk
from services.geo_service import get_geo_intelligence
from services.threat_graph import build_threat_graph
from services.report_generator import generate_forensic_report


app = FastAPI(
    title="MailTrace AI",
    description=(
        "AI-powered forensic email "
        "threat intelligence system"
    ),
    version="3.0.0"
)


# ---------------------------------------------------------
# INITIALIZE DATABASE
# ---------------------------------------------------------

init_db()


# ---------------------------------------------------------
# CORS
# ---------------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


# ---------------------------------------------------------
# IN-MEMORY CASE STORAGE
# ---------------------------------------------------------
# Used for the current running backend session.
# SQLite remains the persistent case store.
# ---------------------------------------------------------

CASE_CACHE = {}


# ---------------------------------------------------------
# HOME
# ---------------------------------------------------------

@app.get("/")
def home():

    return {
        "project": "MailTrace AI",
        "status": "online",
        "message": (
            "MailTrace AI Threat Intelligence "
            "Engine is running"
        ),
        "version": "3.0.0"
    }


# ---------------------------------------------------------
# HEALTH
# ---------------------------------------------------------

@app.get("/health")
def health():

    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat()
    }


# ---------------------------------------------------------
# CASE LIST
# ---------------------------------------------------------

@app.get("/cases")
def cases():

    case_list = get_cases()

    return {
        "total_cases": len(case_list),
        "cases": case_list
    }


# ---------------------------------------------------------
# ANALYZE EMAIL
# ---------------------------------------------------------

@app.post("/analyze")
async def analyze_email(
    file: UploadFile = File(...)
):

    # -----------------------------------------------------
    # BASIC FILE VALIDATION
    # -----------------------------------------------------

    if not file.filename:

        raise HTTPException(
            status_code=400,
            detail="No filename provided."
        )

    filename = file.filename.lower()

    if not filename.endswith(
        ".eml"
    ):

        raise HTTPException(
            status_code=400,
            detail=(
                "Only .eml email files "
                "are supported."
            )
        )


    # -----------------------------------------------------
    # READ FILE
    # -----------------------------------------------------

    content = await file.read()

    if not content:

        raise HTTPException(
            status_code=400,
            detail="Uploaded email file is empty."
        )


    # -----------------------------------------------------
    # CASE ID
    # -----------------------------------------------------

    case_id = (
        "MT-"
        + datetime.now().strftime(
            "%Y%m%d%H%M%S"
        )
        + "-"
        + uuid.uuid4().hex[:6].upper()
    )


    # -----------------------------------------------------
    # PARSE EMAIL
    # -----------------------------------------------------

    try:

        email_data = parse_email(
            content
        )

    except Exception as error:

        raise HTTPException(
            status_code=400,
            detail=(
                "Unable to parse the email file: "
                + str(error)
            )
        )


    email_data["filename"] = (
        file.filename
    )


    # -----------------------------------------------------
    # COMBINE EMAIL TEXT
    # -----------------------------------------------------

    body_text = email_data.get(
        "body_text",
        ""
    )

    body_html = email_data.get(
        "body_html",
        ""
    )

    subject = email_data.get(
        "subject",
        ""
    )

    sender = email_data.get(
        "sender",
        ""
    )

    combined_text = " ".join([
        subject,
        sender,
        body_text,
        body_html
    ])


    # -----------------------------------------------------
    # HEADER FORENSICS
    # -----------------------------------------------------

    header_result = analyze_headers(
        email_data
    )


    # -----------------------------------------------------
    # IOC EXTRACTION
    # -----------------------------------------------------

    ioc_result = extract_iocs(
        email_data
    )


    # -----------------------------------------------------
    # URL ANALYSIS
    # -----------------------------------------------------

    url_result = analyze_urls(
        ioc_result.get(
            "urls",
            []
        )
    )


    # -----------------------------------------------------
    # IP ANALYSIS
    # -----------------------------------------------------

    ip_result = analyze_ips(
        ioc_result.get(
            "ip_addresses",
            []
        )
    )


    # -----------------------------------------------------
    # CONTENT ANALYSIS
    # -----------------------------------------------------

    content_result = analyze_content(
        combined_text
    )


    # -----------------------------------------------------
    # MACHINE LEARNING
    # -----------------------------------------------------

    ml_result = predict_email(
        combined_text
    )


    # -----------------------------------------------------
    # GEO INTELLIGENCE
    # -----------------------------------------------------

    geo_result = get_geo_intelligence(
        ip_addresses=ioc_result.get(
            "ip_addresses",
            []
        ),
        domains=ioc_result.get(
            "domains",
            []
        )
    )


    # -----------------------------------------------------
    # RISK ENGINE
    # -----------------------------------------------------

    risk_result = calculate_risk(
        ml_result=ml_result,
        header_result=header_result,
        ioc_result=ioc_result,
        url_result=url_result,
        ip_result=ip_result,
        content_result=content_result
    )


    # -----------------------------------------------------
    # THREAT GRAPH
    # -----------------------------------------------------

    graph_result = build_threat_graph(
        email_data=email_data,
        ioc_result=ioc_result,
        geo_result=geo_result
    )


    # -----------------------------------------------------
    # FORENSIC REPORT
    # -----------------------------------------------------

    try:

        report_path = (
            generate_forensic_report(
                case_id=case_id,
                email_data=email_data,
                risk_result=risk_result,
                ml_result=ml_result,
                header_result=header_result,
                ioc_result=ioc_result,
                geo_result=geo_result,
                graph_result=graph_result
            )
        )

    except Exception as error:

        report_path = None

        print(
            "Report generation error:",
            error
        )


    # -----------------------------------------------------
    # SAVE CASE TO DATABASE
    # -----------------------------------------------------

    save_case(
        case_id=case_id,
        filename=file.filename,
        sender=email_data.get(
            "sender",
            ""
        ),
        receiver=email_data.get(
            "receiver",
            ""
        ),
        subject=email_data.get(
            "subject",
            ""
        ),
        risk_score=risk_result.get(
            "score",
            0
        ),
        risk_level=risk_result.get(
            "level",
            "UNKNOWN"
        )
    )


    # -----------------------------------------------------
    # FINAL RESPONSE
    # -----------------------------------------------------

    result = {

        "case_id": case_id,

        "status":
            "Analysis completed successfully",

        "email": {
            "filename":
                file.filename,

            "sender":
                email_data.get(
                    "sender",
                    ""
                ),

            "receiver":
                email_data.get(
                    "receiver",
                    ""
                ),

            "subject":
                email_data.get(
                    "subject",
                    ""
                ),

            "date":
                email_data.get(
                    "date",
                    ""
                ),

            "reply_to":
                email_data.get(
                    "reply_to",
                    ""
                ),

            "return_path":
                email_data.get(
                    "return_path",
                    ""
                )
        },

        "risk":
            risk_result,

        "machine_learning":
            ml_result,

        "headers":
            header_result,

        "iocs":
            ioc_result,

        "url_analysis":
            url_result,

        "ip_analysis":
            ip_result,

        "content_analysis":
            content_result,

        "geo_intelligence":
            geo_result,

        "threat_graph":
            graph_result,

        "forensic_report": {
            "available":
                report_path is not None,

            "filename":
                os.path.basename(
                    report_path
                )
                if report_path
                else None
        }
    }


    # -----------------------------------------------------
    # CACHE FULL RESULT
    # -----------------------------------------------------

    CASE_CACHE[
        case_id
    ] = result


    return JSONResponse(
        content=result
    )


# ---------------------------------------------------------
# GET SINGLE CASE
# ---------------------------------------------------------

@app.get(
    "/cases/{case_id}"
)
def get_single_case(
    case_id: str
):

    if case_id in CASE_CACHE:

        return CASE_CACHE[
            case_id
        ]

    raise HTTPException(
        status_code=404,
        detail="Case not found."
    )


# ---------------------------------------------------------
# THREAT GRAPH
# ---------------------------------------------------------

@app.get(
    "/threat-graph/{case_id}"
)
def get_threat_graph(
    case_id: str
):

    case = CASE_CACHE.get(
        case_id
    )

    if not case:

        raise HTTPException(
            status_code=404,
            detail="Case not found."
        )

    return case.get(
        "threat_graph",
        {}
    )


# ---------------------------------------------------------
# GEO INTELLIGENCE
# ---------------------------------------------------------

@app.get(
    "/geo/{case_id}"
)
def get_geo(
    case_id: str
):

    case = CASE_CACHE.get(
        case_id
    )

    if not case:

        raise HTTPException(
            status_code=404,
            detail="Case not found."
        )

    return case.get(
        "geo_intelligence",
        {}
    )


# ---------------------------------------------------------
# ANALYTICS
# ---------------------------------------------------------

@app.get("/analytics")
def analytics():

    case_list = get_cases()

    total_cases = len(
        case_list
    )

    high_risk = 0
    medium_risk = 0
    low_risk = 0
    critical_risk = 0

    for case in case_list:

        level = str(
            case.get(
                "risk_level",
                ""
            )
        ).upper()

        if level == "CRITICAL":

            critical_risk += 1

        elif level == "HIGH":

            high_risk += 1

        elif level == "MEDIUM":

            medium_risk += 1

        elif level == "LOW":

            low_risk += 1


    return {
        "total_cases":
            total_cases,

        "risk_distribution": {
            "critical":
                critical_risk,

            "high":
                high_risk,

            "medium":
                medium_risk,

            "low":
                low_risk
        },

        "engine": {
            "ml_detection":
                True,

            "header_forensics":
                True,

            "ioc_extraction":
                True,

            "geo_intelligence":
                True,

            "threat_graph":
                True,

            "forensic_reporting":
                True
        }
    }


# ---------------------------------------------------------
# DOWNLOAD FORENSIC REPORT
# ---------------------------------------------------------

@app.get(
    "/reports/{case_id}"
)
def download_report(
    case_id: str
):

    report_path = os.path.join(
        "reports",
        f"{case_id}_forensic_report.pdf"
    )

    if not os.path.exists(
        report_path
    ):

        raise HTTPException(
            status_code=404,
            detail=(
                "Forensic report "
                "not found."
            )
        )

    return FileResponse(
        path=report_path,
        media_type="application/pdf",
        filename=(
            f"{case_id}_forensic_report.pdf"
        )
    )