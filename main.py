# main.py - FastAPI Backend with ML Integration for Outlook Add-in
from dotenv import load_dotenv
from datetime import datetime
load_dotenv()
from fastapi import FastAPI
from pydantic import BaseModel
from model import PhishingDetectorML, PhishingDetectorStep1
from fastapi.middleware.cors import CORSMiddleware
from ai_explainer import generate_ai_explanation

from typing import Optional, List
from step2_features import (
    extract_links, 
    extract_suspicious_words,
    get_suspicious_links,
    get_risk_indicators
)
ADMIN_REPORT_EMAIL = "VinayChetti@outlook.com"  # TEMP
REPORTING_ENABLED = True
app = FastAPI(title="Phishing Detection — ML + Rule-Based (Outlook Integration)")

# ---------- CORS ----------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://localhost:3000",
        "http://localhost:3000",
        "https://localhost:3001",
        "http://localhost:3001",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------- INITIALIZE DETECTORS ----------
# Try ML detector first, fallback to rule-based if models not available
try:
    detector = PhishingDetectorML(models_dir="models")
    print("🤖 Using ML-based detector (SVM)")
except Exception as e:
    print(f"⚠️  ML models not available, using rule-based detector: {e}")
    detector = PhishingDetectorStep1()

# Keep rule-based as fallback
rule_based_detector = PhishingDetectorStep1()

# ---------- REQUEST MODELS ----------
class EmailRequest(BaseModel):
    sender: Optional[str] = ""
    subject: str
    body: str

class OutlookEmailRequest(BaseModel):
    sender: Optional[str] = ""
    subject: str
    body: str
    messageId: str = ""
# ---------- REPORT REQUEST MODEL ----------
class ReportRequest(BaseModel):
    messageId: str
    category: str
    confidence: Optional[float] = None
    ruleHits: List[str] = []
    sender: Optional[str] = ""
    reportedBy: Optional[str] = ""

def build_rule_explanation(category: str, details: dict, reasons: list | None):
    points = []

    links = details.get("links") or []
    suspicious_words = details.get("suspiciousWords") or []

    if links:
        points.append("it contains suspicious links")

    if suspicious_words:
        points.append("it uses words commonly seen in phishing or scam messages")

    if reasons:
        points.append("multiple security rules were triggered")

    if category == "PHISHING":
        intro = "This email was marked as PHISHING because"
    elif category == "SUSPICIOUS":
        intro = "This email was marked as SUSPICIOUS because"
    else:
        return "This email appears safe based on current security checks."

    if not points:
        return intro + " it shows patterns commonly used in phishing attacks."

    return intro + " " + ", and ".join(points) + "."


# ==========================================================
# ANALYSIS MESSAGE BUILDER (Keep your original logic)
# ==========================================================

def build_analysis_message(is_phishing, links, words, confidence):
    """
    Build user-friendly analysis message for Outlook UI
    """
    if not is_phishing and not links and not words:
        return (
            "This email looks safe. "
            "We did not find any suspicious links or risky words. "
            "The sender and content appear normal."
        )

    if is_phishing:
        confidence_text = f"with {confidence:100.0f}% confidence" if confidence > 0.7 else ""
        return (
            f"⚠️ This email is likely a phishing attempt {confidence_text}. "
            f"Suspicious links found: {', '.join(links[:3]) if links else 'None'}. "
            f"Risky words detected: {', '.join(words[:5]) if words else 'None'}. "
            "❌ DO NOT click on any links or share personal information."
        )

    return (
        "⚠️ This email has some warning signs. "
        f"Risky words detected: {', '.join(words[:5]) if words else 'None'}. "
        "Please verify the sender before taking action."
    )

# ==========================================================
# RISK LEVEL CALCULATOR (Keep your original logic)
# ==========================================================

def calculate_risk_level(is_phishing: bool, confidence: float, links: List[str], 
                         words: List[str], risk_indicators: dict) -> str:
    """
    Calculate risk level based on multiple factors
    """
    if is_phishing and confidence > 0.8:
        return "HIGH"
    elif is_phishing:
        return "HIGH"
    elif risk_indicators.get('has_ip_links') or risk_indicators.get('link_domain_mismatch'):
        return "HIGH"
    elif len(words) >= 3 or links or risk_indicators.get('has_shortened_urls'):
        return "MEDIUM"
    elif len(words) >= 1 and not risk_indicators.get('trusted_domain', True):
        return "MEDIUM"

    else:
        return "LOW"

# ==========================================================
# BASIC ANALYZE ENDPOINT (Keep for backward compatibility)
# ==========================================================

@app.post("/analyze")
def analyze_email(email: EmailRequest):
    """
    Basic analysis endpoint (backward compatible)
    """
    # Use ML detector
    result = detector.predict(email.dict())
    
    # Get risk indicators
    risk_indicators = get_risk_indicators(
        body=email.body,
        subject=email.subject,
        sender=email.sender or ""
    )
    
    return {
        "result": result["is_phishing"],
        "confidence": result["confidence"],
        "method": result.get("method", "unknown"),
        "risk_indicators": risk_indicators
    }

# ==========================================================
# OUTLOOK ADD-IN ENDPOINT (Main endpoint - Enhanced with ML)
# ==========================================================
from step2_features import (
    is_internal_email,
    requests_credentials,
    has_ip_link,
    has_shortened_link,
    brand_impersonation_link,
    requests_personal_info,
    has_unknown_links
)

@app.post("/analyze-outlook")
def analyze_outlook_email(email: OutlookEmailRequest):

    full_text = f"{email.subject} {email.body}"
    internal = is_internal_email(email.sender or "")
    # ===============================
    # INTERNAL HR SAFE GUARD
    # ===============================
    from step2_features import has_trusted_link
    # ===============================
    # INTERNAL HR SAFE GUARD
    # ===============================
    if internal and not has_unknown_links(full_text):
        details = {
            "links": extract_links(full_text),
            "suspiciousWords": extract_suspicious_words(full_text)
        }

        analysis_msg = build_rule_explanation("SAFE", details, ["internal trusted email"])

        ai_explanation = generate_ai_explanation(
            category="SAFE",
            ml_confidence=None,
            rule_hits=[],
            is_internal=internal,
            has_trusted_links=True
        )

        return {
            "category": "SAFE",
            "isInternal": True,
            "reason": "Internal HR communication",
            "details": details,
            "analysisMessage": analysis_msg,
            "aiExplanation": ai_explanation
        }




    # ===============================
    # STRONG RULES → PHISHING
    # ===============================
    strong_hits = []

    if requests_credentials(full_text) and not internal:
        strong_hits.append("credential request")

    if has_ip_link(full_text)  and not internal:
        strong_hits.append("IP-based link")

    if has_shortened_link(full_text) and not internal:
        strong_hits.append("shortened URL")

    if brand_impersonation_link(full_text)  and not internal:
        strong_hits.append("brand impersonation")

    if strong_hits:
        ml_result = detector.predict(email.dict())
        confidence = max(90.0, round(ml_result["confidence"] * 100, 1))

        ai_explanation = generate_ai_explanation(
            category="PHISHING",
            ml_confidence=ml_result["confidence"],
            rule_hits=strong_hits,
            is_internal=internal,
            has_trusted_links=True
        )
       
        details = {
            "links": extract_links(full_text),
            "suspiciousWords": extract_suspicious_words(full_text)
        }

        analysis_msg = build_rule_explanation("PHISHING", details, strong_hits)

        return {
            "category": "PHISHING",
            "confidence": confidence,
            "isInternal": internal,
            "reason": "; ".join(strong_hits),
            "details": details,
            "analysisMessage": analysis_msg,     # ✅ Always available
            "aiExplanation": ai_explanation       # ✅ Optional
        }

    # ===============================
    # MEDIUM RULES → SUSPICIOUS
    # ===============================
    medium_hits = []

    if requests_personal_info(full_text):
        medium_hits.append("personal information request")

    if has_unknown_links(full_text):
        medium_hits.append("external links")

    if medium_hits:
        ai_explanation = generate_ai_explanation(
            category="SUSPICIOUS",
            ml_confidence=None,
            rule_hits=medium_hits,
            is_internal=internal,
            has_trusted_links=True
        )

        details = {
            "links": extract_links(full_text),
            "suspiciousWords": extract_suspicious_words(full_text)
        }

        analysis_msg = build_rule_explanation("SUSPICIOUS", details, medium_hits)

        return {
            "category": "SUSPICIOUS",
            "isInternal": internal,
            "reason": "; ".join(medium_hits),
            "details": details,
            "analysisMessage": analysis_msg,     # ✅ Always available
            "aiExplanation": ai_explanation
        }


    # ===============================
    # SAFE
    # ===============================
    ai_explanation = generate_ai_explanation(
        category="SAFE",
        ml_confidence=None,
        rule_hits=[],
        is_internal=internal,
        has_trusted_links=True
    )

    details = {
        "links": extract_links(full_text),
        "suspiciousWords": extract_suspicious_words(full_text)
    }

    analysis_msg = build_rule_explanation("SAFE", details, [])

    return {
        "category": "SAFE",
        "isInternal": internal,
        "reason": "No phishing indicators detected",
        "details": details,
        "analysisMessage": analysis_msg,     # ✅ Rule-based explanation
        "aiExplanation": ai_explanation      # ✅ Optional
    }




# ==========================================================
# MODEL INFO ENDPOINT (New - useful for debugging)
# ==========================================================

@app.get("/model-info")
def get_model_info():
    """
    Get information about the loaded model
    """
    import os
    
    ml_loaded = hasattr(detector, 'is_loaded') and detector.is_loaded
    
    info = {
        "ml_model_loaded": ml_loaded,
        "detector_type": "ML (SVM)" if ml_loaded else "Rule-Based",
        "models_directory": os.path.abspath("models"),
        "required_files": [
            "svm_model.pkl",
            "tfidf_vectorizer.pkl",
            "scaler.pkl"
        ]
    }
    
    # Check which files exist
    if os.path.exists("models"):
        info["available_files"] = os.listdir("models")
    else:
        info["available_files"] = []
    
    # Load training info if available
    training_info_path = os.path.join("models", "training_info.json")
    if os.path.exists(training_info_path):
        import json
        with open(training_info_path, 'r') as f:
            info["training_info"] = json.load(f)
    
    return info

# ==========================================================
# BATCH ANALYSIS ENDPOINT (New - for testing multiple emails)
# ==========================================================

@app.post("/analyze-batch")
def analyze_batch(emails: List[EmailRequest]):
    """
    Analyze multiple emails at once
    Useful for testing/validation
    """
    results = []
    
    for email in emails:
        result = detector.predict(email.dict())
        
        results.append({
            "subject": email.subject[:50],  # Truncate for readability
            "isPhishing": result["is_phishing"],
            "confidence": round(result["confidence"] * 100, 1),
            "method": result.get("method", "unknown")
        })
    
    return {
        "total": len(emails),
        "phishing_detected": sum(1 for r in results if r["isPhishing"]),
        "results": results
    }

# ==========================================================
# HEALTH CHECK
# ==========================================================

@app.get("/")
def root():
    """
    Health check and status endpoint
    """
    ml_loaded = hasattr(detector, 'is_loaded') and detector.is_loaded
    
    return {
        "message": "Phishing Detection Backend — ML + Rule-Based Ready",
        "status": "operational",
        "ml_model_loaded": ml_loaded,
        "detector_type": "ML (SVM)" if ml_loaded else "Rule-Based Fallback",
        "endpoints": {
            "outlook_analysis": "/analyze-outlook",
            "basic_analysis": "/analyze",
            "batch_analysis": "/analyze-batch",
            "model_info": "/model-info"
        },
        "note": "Train the ML model by running: python train_model.py" if not ml_loaded else None
    }

@app.get("/health")
def health_check():
    """
    Simple health check for monitoring
    """
    return {"status": "healthy", "service": "phishing-detection"}

# ==========================================================
# STARTUP EVENT
# ==========================================================

@app.on_event("startup")
async def startup_event():
    """
    Print startup information
    """
    ml_loaded = hasattr(detector, 'is_loaded') and detector.is_loaded
    
    print("\n" + "="*60)
    print("🚀 PHISHING DETECTION API STARTED")
    print("="*60)
    print(f"Detector Type: {'ML (SVM)' if ml_loaded else 'Rule-Based Fallback'}")
    print(f"ML Model Status: {'✅ Loaded' if ml_loaded else '❌ Not Trained'}")
    
    if not ml_loaded:
        print("\n⚠️  WARNING: ML models not found!")
        print("   To train the model, run: python train_model.py")
        print("   Currently using rule-based detection as fallback.")
    
    print("\n📡 Available Endpoints:")
    print("   POST /analyze-outlook  - Main Outlook add-in endpoint")
    print("   POST /analyze          - Basic analysis")
    print("   POST /analyze-batch    - Batch analysis")
    print("   GET  /model-info       - Model information")
    print("   GET  /health           - Health check")
    print("="*60 + "\n")

@app.post("/report-to-admin")
def report_to_admin(report: ReportRequest):
    """
    User-initiated report to Admin (TEMP)
    """

    if not REPORTING_ENABLED:
        return {"status": "disabled"}

    # Basic validation
    if report.category not in ["PHISHING", "SUSPICIOUS"]:
        return {
            "status": "ignored",
            "reason": "Only PHISHING or SUSPICIOUS emails can be reported"
        }

    # Build safe report payload
    report_payload = {
        "to": ADMIN_REPORT_EMAIL,
        "messageId": report.messageId,
        "category": report.category,
        "confidence": report.confidence,
        "ruleHits": report.ruleHits,
        "sender": report.sender,
        "reportedBy": report.reportedBy,
        "reportedAt": datetime.utcnow().isoformat()
    }

    # 🔒 TEMP: just log (no email yet)
    print("🚨 ADMIN REPORT (TEMP)")
    print(report_payload)

    return {
        "status": "reported",
        "sentTo": ADMIN_REPORT_EMAIL
    }