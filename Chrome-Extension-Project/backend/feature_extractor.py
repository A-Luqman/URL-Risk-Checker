import math
import re
from collections import Counter
from urllib.parse import urlparse
import tldextract

# ---------- Regex ----------
_IPV4_RE = re.compile(r"\b\d{1,3}(\.\d{1,3}){3}\b")
_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")

# ---------- Keywords ----------
SUSPICIOUS_KEYWORDS = sorted(set([
    "account", "confirm", "banking", "secure", "ebyisapi", "webscr",
    "signin", "mail", "install", "toolbar", "backup", "paypal",
    "password", "username", "verify", "update", "login", "support",
    "billing", "transaction", "security", "payment", "online",
    "customer", "service", "accountupdate", "verification",
    "important", "confidential", "limited", "access",
    "securitycheck", "verifyaccount", "information", "change",
    "notice", "myaccount", "updateinfo", "loginsecure", "protect",
    "identity", "member", "personal", "actionrequired",
    "loginverify", "validate", "paymentupdate", "urgent"
]))

COMMON_TLDS = {
    "com", "org", "net", "edu", "gov", "mil",
    "co", "io", "uk", "us", "de", "jp", "fr", "ai",
    "in", "gg",
}

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".scr", ".bat", ".cmd", ".sh",
    ".js", ".vbs", ".ps1",
    ".zip", ".rar", ".7z", ".gz", ".tar",
    ".apk", ".msi", ".iso",
    ".php", ".html", ".htm"  # optional (phishing landing pages)
}

def shannon_entropy(s: str) -> float:
    """
    Shannon entropy of a string.
    Higher entropy can indicate randomness/obfuscation (often seen in malicious URLs).
    """
    if not s:
        return 0.0
    counts = Counter(s)
    probs = [count / len(s) for count in counts.values()]
    return -sum(p * math.log2(p) for p in probs)

# ---------- Domain helpers ----------
def get_registered_domain(url: str) -> str:
    """
    Returns registrable domain like 'google.com' from any URL or hostname.
    """
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ""

def tokenize_url(url: str):
    """
    Tokenize URL on common separators.
    """
    return re.split(r"[\/\.\-_?=&]", url)

def keyword_features(url: str, keywords=SUSPICIOUS_KEYWORDS) -> dict:
    """
    Suspicious keyword hit features from full URL string.
    """
    url_l = (url or "").lower()
    hits = [kw for kw in keywords if kw in url_l]
    return {
        "has_any_suspicious_keyword": int(len(hits) > 0),
        "num_suspicious_keywords": len(hits),
        "max_suspicious_keyword_length": max((len(k) for k in hits), default=0),
        "keyword_density": len(hits) / max(len(url_l), 1),
    }

def extract_features(url) -> dict:
    """
    Extract the 25 URL lexical features used by the trained model.
    """
    url = str(url).strip()
    p = urlparse(url)

    # raw parsed pieces
    netloc = p.netloc or ""
    path = p.path or ""
    query = p.query or ""
    scheme = (p.scheme or "").lower()

    path_lower = path.lower()
    has_suspicious_extension = int(
        any(path_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
    )

    ext = tldextract.extract(url)
    tld = ext.suffix or ""

    # ---------- v1 base features ----------
    features = {
        # Length-based
        "url_length": len(url),
        "domain_length": len(netloc),
        "path_length": len(path),
        "query_length": len(query),

        # Character counts
        "num_dots": url.count("."),
        "num_hyphens": url.count("-"),
        "num_digits": sum(c.isdigit() for c in url),
        "num_slashes": url.count("/"),
        "num_subdomains": netloc.count("."),

        # Query symbols (explicit)
        "num_question_marks": url.count("?"),
        "num_equals": url.count("="),
        "num_ampersands": url.count("&"),
        "has_query": int("?" in url),
        "num_special_chars": sum(not c.isalnum() for c in url),

        # TLD features
        "tld_length": len(tld),
        "is_common_tld": int(tld in COMMON_TLDS),

        "is_https": int(scheme == "https"),
        "has_ipv4": int(bool(_IPV4_RE.search(netloc))),
        "suspicious_file_extension": has_suspicious_extension,

        # Statistical
        "entropy": shannon_entropy(url),
    }

    # ---------- v2 extras ----------
    tokens = tokenize_url(url.lower())
    url_len = max(len(url), 1)

    features.update({
        "digit_ratio": features["num_digits"] / url_len,
        "letter_ratio": sum(c.isalpha() for c in url) / url_len,
        "special_char_ratio": features["num_special_chars"] / url_len,
    })

    features.update(keyword_features(url, SUSPICIOUS_KEYWORDS))

    encoded_matches = _ENCODED_RE.findall(url)
    features.update({
        "num_encoded_chars": len(encoded_matches),
        "has_url_encoding": int(len(encoded_matches) > 0),
        "longest_token_length": max((len(t) for t in tokens if t), default=0),
    })

    return features