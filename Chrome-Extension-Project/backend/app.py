from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import numpy as np
from typing import Tuple, List, Dict, Optional
import httpx
import re
from urllib.parse import urlparse

from feature_extractor import extract_features

MODEL_PATH = "phishing_model_v2.joblib"

app = FastAPI(title="URL Risk Predictor API")

# Allow Chrome extension to call this API.
# In production, lock this down to your extension id origin.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    url: str

def normalize_url(u: str) -> str:
    u = (u or "").strip()
    if not u:
        raise HTTPException(status_code=400, detail="Empty URL")
    parsed = urlparse(u)
    if not parsed.scheme:
        # Assume https if user pastes without scheme
        u = "https://" + u

    # Upgrade known shorteners to HTTPS
    host = (parsed.netloc or "").lower()
    if host.endswith("t.co") and parsed.scheme == "http":
        u = u.replace("http://", "https://", 1)

    return u

def get_feature_order(model) -> list:
    """
    Best-case: if model trained with pandas DataFrame, sklearn stores feature_names_in_.
    Otherwise you must hardcode the feature order that matches training.
    """
    if hasattr(model, "feature_names_in_"):
        return list(model.feature_names_in_)

    # FALLBACK: you MUST edit this to your actual 25-feature order
    return [
        "url_length","domain_length","path_length","query_length",
        "num_dots","num_hyphens","num_digits","num_slashes","num_subdomains",
        "num_question_marks","num_equals","num_ampersands","has_query","num_special_chars",
        "tld_length","is_common_tld",
        # "is_https",
        "has_ipv4","suspicious_file_extension","entropy",
        "digit_ratio","letter_ratio","special_char_ratio",
        "has_any_suspicious_keyword","num_suspicious_keywords","max_suspicious_keyword_length","keyword_density",
        "num_encoded_chars","has_url_encoding","longest_token_length",
    ]

@app.on_event("startup")
def load_model():
    global model, feature_order
    try:
        model = joblib.load(MODEL_PATH)
    except Exception as e:
        raise RuntimeError(f"Failed to load model at {MODEL_PATH}: {e}")
    feature_order = get_feature_order(model)

MAX_REDIRECTS = 10

_META_REFRESH_RE = re.compile(
    r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\']?\s*\d+\s*;\s*url=([^"\'>\s]+)',
    re.IGNORECASE
)
_JS_REDIRECT_RE = re.compile(
    r'(?:window\.location|location\.href|location)\s*=\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)
_REFRESH_HEADER_RE = re.compile(r'^\s*\d+\s*;\s*url=(.+)\s*$', re.IGNORECASE)

SHORTENER_HOSTS = {
    "t.co", "bit.ly", "tinyurl.com", "goo.gl", "is.gd",
    "buff.ly", "ow.ly", "cutt.ly", "rb.gy", "s.id"
}

def _is_html(resp: httpx.Response) -> bool:
    ct = (resp.headers.get("content-type") or "").lower()
    return "text/html" in ct or "application/xhtml" in ct

def extract_html_redirect(resp: httpx.Response) -> str | None:
    # 1) Refresh header
    refresh = resp.headers.get("refresh")
    if refresh:
        m = _REFRESH_HEADER_RE.match(refresh)
        if m:
            return m.group(1).strip()

    # 2) Meta refresh / JS redirect (limit how much we read)
    try:
        text = resp.text[:50000]
    except Exception:
        return None

    m = _META_REFRESH_RE.search(text)
    if m:
        return m.group(1).strip()

    m = _JS_REDIRECT_RE.search(text)
    if m:
        return m.group(1).strip()

    return None

async def resolve_redirects(
    url: str,
    timeout_s: float = 10.0,
    verify_ssl: bool = True
) -> Tuple[Optional[str], List[Dict], Dict]:
    """
    Returns (final_url or None, chain, resolution_report)
    chain item: {url, status_code, location?}
    resolution_report: {status, reason_code, message, details, used_insecure_ssl}
    """
    report = {
        "status": "FAILED",
        "reason_code": None,
        "message": None,
        "details": {},
        "used_insecure_ssl": (not verify_ssl),
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                      "(KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36"
    }

    # Safer redirect handling: prevent infinite loops
    limits = httpx.Limits(max_connections=20, max_keepalive_connections=10)
    timeout = httpx.Timeout(timeout_s)

    chain: List[Dict] = []

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,   # we'll follow manually so we can explain each step
            timeout=timeout,
            verify=verify_ssl,
            headers=headers,
            limits=limits
        ) as client:

            current = url
            seen = set()

            for i in range(MAX_REDIRECTS + 1):
                if current in seen:
                    report.update({
                        "status": "FAILED",
                        "reason_code": "REDIRECT_LOOP",
                        "message": "Redirect loop detected (the URL keeps redirecting in a cycle).",
                        "details": {"step": i}
                    })
                    return None, chain, report
                seen.add(current)

                host_current = (urlparse(current).netloc or "").lower()

                # 1️⃣ Try HEAD first (cheap)
                if host_current in SHORTENER_HOSTS:
                    resp = await client.get(current)
                else:
                    # Try HEAD first
                    try:
                        resp = await client.head(current)
                    except httpx.RequestError:
                        resp = None

                    # If HEAD failed or server doesn't like HEAD, fallback to GET
                    if resp is None or resp.status_code in (400, 403, 405):
                        resp = await client.get(current)

                status = resp.status_code
                location = resp.headers.get("location")
                is_html = (status == 200 and _is_html(resp))
                chain.append({
                    "url": str(resp.url),
                    "status_code": status,
                    **({"location": location} if location else {})
                })

                # 🔹 HTML-based redirect detection (e.g. t.co returns 200 but redirects via HTML/JS)
                if status == 200 and _is_html(resp):
                    html_next = extract_html_redirect(resp)
                    if html_next:
                        next_url = str(resp.url.join(html_next))
                        chain.append({
                            "url": str(resp.url),
                            "status_code": status,
                            "location": next_url,
                            "note": "html_redirect"
                        })
                        current = next_url
                        continue

                # Handle redirects manually
                if status in (301, 302, 303, 307, 308) and location:
                    # httpx can join relative redirects
                    next_url = str(resp.url.join(location))
                    current = next_url
                    continue

                # 200 OK but no redirect detected (possible interstitial / bot protection)
                if status == 200 and not location and not is_html and host_current in SHORTENER_HOSTS:
                    report.update({
                        "status": "PARTIAL",
                        "reason_code": "NO_REDIRECT_ON_GET",
                        "message": "Shortener returned HTTP 200 but did not redirect. Possible bot protection or interstitial.",
                        "details": {"content_type": resp.headers.get("content-type")}
                    })
                    return str(resp.url), chain, report

                # Not a redirect → final
                if 200 <= status < 400:
                    report.update({
                        "status": "RESOLVED",
                        "reason_code": "OK",
                        "message": "Final destination resolved successfully.",
                        "details": {"http_status": status}
                    })
                    return str(resp.url), chain, report

                # Common “blocked / rate limit / forbidden” outcomes
                if status == 401:
                    report.update({
                        "status": "PARTIAL",
                        "reason_code": "UNAUTHORIZED_401",
                        "message": "Destination exists but requires authentication (401).",
                        "details": {"http_status": status}
                    })
                    return str(resp.url), chain, report

                if status == 403:
                    report.update({
                        "status": "PARTIAL",
                        "reason_code": "FORBIDDEN_403",
                        "message": "Request was blocked by the server (403). This can happen due to WAF/bot protection.",
                        "details": {"http_status": status}
                    })
                    return str(resp.url), chain, report

                if status == 404:
                    report.update({
                        "status": "FAILED",
                        "reason_code": "NOT_FOUND_404",
                        "message": "Destination not found (404). The page may be removed.",
                        "details": {"http_status": status}
                    })
                    return None, chain, report

                if status == 429:
                    report.update({
                        "status": "PARTIAL",
                        "reason_code": "RATE_LIMIT_429",
                        "message": "Rate limited by the server (429). Try again later.",
                        "details": {"http_status": status}
                    })
                    return str(resp.url), chain, report

                if 500 <= status <= 599:
                    report.update({
                        "status": "FAILED",
                        "reason_code": "SERVER_ERROR_5XX",
                        "message": f"Server error ({status}). Destination server might be down.",
                        "details": {"http_status": status}
                    })
                    return None, chain, report

                # Other unusual status
                report.update({
                    "status": "PARTIAL",
                    "reason_code": "UNEXPECTED_STATUS",
                    "message": f"Unexpected HTTP status ({status}).",
                    "details": {"http_status": status}
                })
                return str(resp.url), chain, report

            # Too many redirects
            report.update({
                "status": "FAILED",
                "reason_code": "TOO_MANY_REDIRECTS",
                "message": f"Too many redirects (>{MAX_REDIRECTS}).",
                "details": {"max_redirects": MAX_REDIRECTS}
            })
            return None, chain, report
        
    except httpx.SSLError as e:
        report.update({
            "status": "FAILED",
            "reason_code": "SSL_ERROR",
            "message": "SSL/TLS certificate error while connecting.",
            "details": {"error": str(e)}
        })
        return None, chain, report    
    
    except httpx.ConnectTimeout:
        report.update({
            "status": "FAILED",
            "reason_code": "CONNECT_TIMEOUT",
            "message": "Connection timed out while trying to reach the server.",
            "details": {}
        })
        return None, chain, report

    except httpx.ReadTimeout:
        report.update({
            "status": "FAILED",
            "reason_code": "READ_TIMEOUT",
            "message": "Server took too long to respond (read timeout).",
            "details": {}
        })
        return None, chain, report

    except httpx.ConnectError as e:
        # Covers DNS failures / refused connections
        report.update({
            "status": "FAILED",
            "reason_code": "CONNECT_DNS_ERROR",
            "message": "Could not connect (DNS failed, refused connection, or no route).",
            "details": {"error": str(e)}
        })
        return None, chain, report

    except httpx.RequestError as e:
        report.update({
            "status": "FAILED",
            "reason_code": "REQUEST_ERROR",
            "message": "Network request failed.",
            "details": {"error": str(e)}
        })
        return None, chain, report


def predict_from_features(feats: dict):
    # Build vector in correct order
    missing = [k for k in feature_order if k not in feats]
    if missing:
        raise HTTPException(
            status_code=500,
            detail=f"Feature extractor missing required features: {missing}"
        )

    x = np.array([[feats[k] for k in feature_order]], dtype=float)

    # Probability (if available)
    proba = None
    if hasattr(model, "predict_proba"):
        proba = float(model.predict_proba(x)[0][1])  # assumes class 1 = malicious

    pred = int(model.predict(x)[0])

    return pred, proba

@app.post("/analyze")
async def analyze(req: AnalyzeRequest):
    url = normalize_url(req.url)

     # 1) Expand / resolve
    final_url, redirect_chain, resolution = await resolve_redirects(url, verify_ssl=True)

     # SSL fallback (optional)
    if resolution["reason_code"] == "SSL_ERROR":
        final_url2, chain2, resolution2 = await resolve_redirects(url, verify_ssl=False)
        # Use insecure only if it actually resolves or is more informative
        if resolution2["status"] in ("RESOLVED", "PARTIAL"):
            final_url, redirect_chain, resolution = final_url2, chain2, resolution2
            resolution["message"] = "SSL verification failed; resolved using insecure mode (lab/testing)."


     # If not resolved, predict using original URL; otherwise predict on final
    url_for_prediction = final_url if final_url else url

    # Extract features and predict on the appropriate URL
    feats = extract_features(url_for_prediction)
    pred, proba = predict_from_features(feats)


    # “risk level” text for UI
    risk_score = proba if proba is not None else float(pred)
    if risk_score >= 0.9:
        risk_level = "HIGH"
    elif risk_score >= 0.775:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "input_url": url,
        "final_url": final_url,                 # may be None if failed
        "url_used_for_prediction": url_for_prediction,
        "redirect_chain": redirect_chain,
        "resolution": resolution,               # ✅ structured explanation
        "features": feats,
        "prediction": pred,
        "probability": proba,
        "risk_score": risk_score,
        "risk_level": risk_level,
    }