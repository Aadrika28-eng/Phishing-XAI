import re
import math
from collections import Counter
from urllib.parse import urlparse


# ============================================================
# 1. SAFE URL PARSING
# ============================================================

def parse_url(url):
    """
    Safely parse a URL.

    Handles URLs with or without schemes and prevents
    malformed URLs from crashing the feature pipeline.
    """

    url = str(url).strip()

    try:
        if "://" in url:
            return urlparse(url)
        else:
            return urlparse("//" + url)

    except ValueError:
        # Handles malformed URLs such as invalid IPv6 notation
        return urlparse("")


# ============================================================
# 2. BASIC URL CHARACTER FEATURES
# ============================================================

def count_characters(url):

    url = str(url).strip()

    parsed = parse_url(url)

    hostname = parsed.hostname or ""
    path = parsed.path or ""

    return {

        "url_length": len(url),

        "hostname_length": len(hostname),

        "path_length": len(path),

        "num_dots": url.count("."),

        "num_hyphens": url.count("-"),

        "num_slashes": url.count("/"),

        "num_digits": sum(
            c.isdigit() for c in url
        ),

        "num_letters": sum(
            c.isalpha() for c in url
        ),

        "num_special_chars": sum(
            not c.isalnum() for c in url
        ),

        "num_at": url.count("@"),

        "num_question": url.count("?"),

        "num_equal": url.count("="),

        "num_percent": url.count("%"),
    }


# ============================================================
# 3. SECURITY AND STRUCTURAL FEATURES
# ============================================================

def security_features(url):

    url = str(url).strip()

    url_lower = url.lower()

    parsed = parse_url(url)

    hostname = parsed.hostname or ""

    # --------------------------------------------------------
    # IPv4 detection
    # --------------------------------------------------------

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    has_ip = int(
        bool(re.match(ip_pattern, hostname))
    )

    # --------------------------------------------------------
    # HTTPS detection
    # --------------------------------------------------------

    has_https = int(
        url_lower.startswith("https://")
    )

    # --------------------------------------------------------
    # Subdomain count
    # --------------------------------------------------------

    parts = hostname.split(".") if hostname else []

    num_subdomains = max(
        len(parts) - 2,
        0
    )

    return {

        "has_ip": has_ip,

        "has_https": has_https,

        "num_subdomains": num_subdomains,

        "domain_length": len(hostname),
    }


# ============================================================
# 4. SUSPICIOUS KEYWORDS
# ============================================================

SUSPICIOUS_KEYWORDS = [

    "login",

    "signin",

    "sign-in",

    "verify",

    "verification",

    "account",

    "secure",

    "update",

    "password",

    "bank",

    "paypal",

    "confirm",

    "billing",

    "authenticate",
]


def suspicious_keyword_features(url):

    url_lower = str(url).lower()

    keyword_count = sum(

        1

        for keyword in SUSPICIOUS_KEYWORDS

        if keyword in url_lower

    )

    return {

        "suspicious_keyword_count":
            keyword_count

    }


# ============================================================
# 5. URL SHORTENER
# ============================================================

SHORTENERS = [

    "bit.ly",

    "tinyurl.com",

    "goo.gl",

    "t.co",

    "ow.ly",

    "is.gd",

    "buff.ly",

    "cutt.ly",

]


def shortener_feature(url):

    url_lower = str(url).lower()

    is_shortener = int(

        any(

            shortener in url_lower

            for shortener in SHORTENERS

        )

    )

    return {

        "is_url_shortener":
            is_shortener

    }


# ============================================================
# 6. RATIO FEATURES
# ============================================================

def ratio_features(url):

    url = str(url)

    length = max(
        len(url),
        1
    )

    digit_count = sum(
        c.isdigit()
        for c in url
    )

    special_count = sum(
        not c.isalnum()
        for c in url
    )

    return {

        "digit_ratio":
            digit_count / length,

        "special_char_ratio":
            special_count / length,

    }


# ============================================================
# 7. SHANNON ENTROPY
# ============================================================

def shannon_entropy(url):

    url = str(url)

    if not url:
        return 0

    counts = Counter(url)

    length = len(url)

    entropy = 0

    for count in counts.values():

        probability = (
            count / length
        )

        entropy -= (

            probability
            * math.log2(probability)

        )

    return entropy


# ============================================================
# 8. MAIN FEATURE EXTRACTION
# ============================================================

def extract_features(url):

    features = {}

    # Basic features
    features.update(
        count_characters(url)
    )

    # Security features
    features.update(
        security_features(url)
    )

    # Suspicious keywords
    features.update(
        suspicious_keyword_features(url)
    )

    # URL shortener
    features.update(
        shortener_feature(url)
    )

    # Ratios
    features.update(
        ratio_features(url)
    )

    # Entropy
    features["url_entropy"] = (
        shannon_entropy(url)
    )

    return features