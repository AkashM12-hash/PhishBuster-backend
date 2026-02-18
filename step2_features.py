# step2_features.py
import re
from typing import List
from urllib.parse import urlparse

ADMIN_REPORT_EMAIL = "VinayChetti@outlook.com"  # TEMP
REPORTING_ENABLED = True

# ===============================
# CONFIG
# ===============================

INTERNAL_COMPANY_DOMAIN = "claaps.com"

TRUSTED_PUBLIC_DOMAINS = [
    # Microsoft / Work
    "teams.microsoft.com",
    "microsoft.com",
    "office.com",
    "office365.com",
    "microsoftonline.com",
    "outlook.com",
    "aka.ms",

    # LinkedIn
    "linkedin.com",
    "email.linkedin.com",

    # Google
    "google.com",
    "mail.google.com",
    "accounts.google.com",

    # Others
    "amazon.com",
    "stripe.com",
    "paypal.com",
    "github.com",
    # others-2
    "urldefense.com",
    "svc.ms",
    "go.microsoft.com",
    "apple.com",
    "itunes.apple.com",
    "play.google.com"
  
    # Zoho (Company tools)
    "zoho.com",
    "zoho.in",
    "accounts.zoho.in",
    "people.zoho.in"

]

SHORTENED_URLS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly"]

# 🔴 STRONG PHISHING SIGNALS
CREDENTIAL_KEYWORDS = [
    "password",
    "otp",
    "one time password",
    "verification code",
    "pin",
    "cvv",
    "bank details",
    "net banking",
    "debit card",
    "credit card"
]

# 🟡 SUSPICIOUS SIGNALS
PERSONAL_INFO_KEYWORDS = [
    "phone number",
    "contact number",
    "whatsapp",
    "email id",
    "address"
]

BRAND_KEYWORDS = [
    "outlook",
    "microsoft",
    "office",
    "office365",
    "gmail",
    "google"
    
]

# ===============================
# BASIC HELPERS
# ===============================

def extract_links(text: str) -> List[str]:
    return re.findall(r"http[s]?://\S+", text)


def extract_domain(sender: str) -> str:
    return sender.split("@")[-1].lower() if sender and "@" in sender else ""




def extract_email_address(sender: str) -> str:
    if not sender:
        return ""
    match = re.search(r'[\w\.-]+@[\w\.-]+', sender)
    if match:
        return match.group(0).lower()
    return sender.lower()

def is_internal_email(sender: str) -> bool:
    email = extract_email_address(sender)
    return email.endswith("@" + INTERNAL_COMPANY_DOMAIN)

def clean_url(url: str) -> str:
    # remove quotes and html leftovers
    url = url.strip().strip('"').strip("'").strip(">")
    url = url.replace("&amp;", "&")
    return url


def is_trusted_public_domain(domain: str) -> bool:
    domain = domain.strip().strip('"').strip("'").lower()
    return any(domain == d or domain.endswith("." + d) for d in TRUSTED_PUBLIC_DOMAINS)

def has_trusted_link(text: str) -> bool:
    links = extract_links(text)

    for link in links:
        try:
            link=clean_url(link)
            domain = urlparse(link).netloc.lower()
            if is_trusted_public_domain(domain):
                return True
        except:
            continue

    return False


# ===============================
# DISPLAY NAME IMPERSONATION
# ===============================

# Protect important internal names / roles
PROTECTED_DISPLAY_NAMES = [
    "venkateswarlu mandula",   # CEO
    "human resources",
    "hr",
    "finance",
    "accounts",
    "it support",
    "admin",
    "security team"
]

def normalize_name(name: str) -> str:
    return re.sub(r"\s+", " ", name.lower().strip())

def is_display_name_impersonation(sender_name: str, sender_email: str) -> bool:
    if not sender_name or not sender_email:
        return False

    name = normalize_name(sender_name)
    email = extract_email_address(sender_email)

    # If email is internal, allow it (legit HR, CEO, etc.)
    if email.endswith("@" + INTERNAL_COMPANY_DOMAIN):
        return False

    # If display name matches protected internal names BUT email is external → impersonation
    for protected in PROTECTED_DISPLAY_NAMES:
        if protected in name:
            return True

    return False



# ===============================
# STRONG RULES → PHISHING
# ===============================

def requests_credentials(text: str) -> bool:
    t = text.lower()

    STRICT_PATTERNS = [
        r"\benter your password\b",
        r"\bverify your account\b",
        r"\benter otp\b",
        r"\bone time password\b",
        r"\bverification code\b",
        r"\blog in to continue\b"
    ]

    return any(re.search(p, t) for p in STRICT_PATTERNS)


def has_ip_link(text: str) -> bool:
    return bool(re.search(r"http[s]?://(?:\d{1,3}\.){3}\d{1,3}", text))




def has_shortened_link(text: str) -> bool:
    links = extract_links(text)

    SHORTENERS = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "ow.ly"
    ]

    for link in links:
        try:
            domain = urlparse(link).netloc.lower().split(":")[0]
            if domain.endswith(INTERNAL_COMPANY_DOMAIN):
                continue
            # Ignore trusted domains completely
            if is_trusted_public_domain(domain):
                continue

            # Exact domain or subdomain match ONLY
            for short in SHORTENERS:
                if domain == short or domain.endswith("." + short):
                    return True

        except Exception:
            continue

    return False



def brand_impersonation_link(text: str) -> bool:
    links = extract_links(text)

    BRAND_KEYWORDS = ["microsoft", "office", "office365", "outlook", "google", "gmail"]

    for link in links:
        try:
            domain = urlparse(link).netloc.lower()

            # Ignore internal company domain
            if domain.endswith(INTERNAL_COMPANY_DOMAIN):
                continue

            # Ignore trusted public domains (microsoft.com, aka.ms, linkedin.com, etc.)
            if is_trusted_public_domain(domain):
                continue

            # If domain contains brand keyword but is not trusted → impersonation
            for brand in BRAND_KEYWORDS:
                if brand in domain:
                    return True

        except:
            continue

    return False




# ===============================
# MEDIUM RULES → SUSPICIOUS
# ===============================

def requests_personal_info(text: str) -> bool:
    t = text.lower()
    return any(k in t for k in PERSONAL_INFO_KEYWORDS)


def has_unknown_links(text: str) -> bool:
    links = extract_links(text)

    for link in links:
        try:
            domain = urlparse(link).netloc.lower()

            if domain.endswith(INTERNAL_COMPANY_DOMAIN):
                continue

            if is_trusted_public_domain(domain):
                continue

            return True
        except:
            return True

    return False


# ==========================================================
# LEGACY / ML SUPPORT (DO NOT REMOVE)
# ==========================================================

def extract_suspicious_words(text: str):
    keywords = [
        "urgent", "verify", "login",
        "password", "otp", "bank", "click here",
        "immediately", "suspended"
    ]
    t = text.lower()
    return [w for w in keywords if w in t]


def get_suspicious_links(text: str):
    return [l for l in extract_links(text) if has_ip_link(l) or has_shortened_link(l)]


def get_risk_indicators(body: str, subject: str, sender: str):
    full_text = f"{subject} {body}"
    domain = extract_domain(sender)

    return {
        "suspicious_links": get_suspicious_links(full_text),
        "suspicious_words": extract_suspicious_words(full_text),
        "trusted_domain": is_trusted_public_domain(domain),
        "has_ip_links": has_ip_link(full_text),
        "has_shortened_urls": has_shortened_link(full_text),
        "brand_impersonation": brand_impersonation_link(full_text)
    }


def build_step2_features(body: str, subject: str, sender: str):
    full_text = f"{subject} {body}".lower()
    domain = extract_domain(sender)

    return {
        "link_count": len(extract_links(full_text)),
        "suspicious_word_count": len(extract_suspicious_words(full_text)),
        "email_length": len(full_text),
        "is_trusted_domain": int(is_trusted_public_domain(domain)),
        "has_ip_address_link": int(has_ip_link(full_text)),
        "has_shortened_url": int(has_shortened_link(full_text)),
        "link_domain_mismatch": int(brand_impersonation_link(full_text))
    }
from datetime import datetime



