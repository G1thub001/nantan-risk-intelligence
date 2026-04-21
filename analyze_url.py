import re
from urllib.parse import urlparse

TRUSTED_DOMAINS = {
    "google.com",
    "accounts.google.com",
    "myaccount.google.com",
    "microsoft.com",
    "outlook.com"
}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"
}

HIGH_RISK_TLDS = {
    ".zip", ".mov", ".top", ".xyz", ".click", ".shop", ".gq", ".tk", ".work"
}

SUSPICIOUS_URL_WORDS = {
    "login", "verify", "update", "secure", "reset",
    "account", "password", "signin", "confirm"
}

TRUSTED_BRANDS = [
    "google",
    "microsoft",
    "paypal",
    "amazon",
    "apple",
    "netflix",
    "facebook",
    "instagram"
]

COMMON_SUBSTITUTIONS = {
    "0": "o",
    "1": "l",
    "3": "e",
    "5": "s",
    "@": "a"
}

COMMON_TRACKING_DOMAINS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "awstrack.me"
]

def is_trusted_domain(domain):
    return any(domain.endswith(td) for td in TRUSTED_DOMAINS)

def extract_urls(text):
    if not isinstance(text, str):
        return []
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    return re.findall(url_pattern, text)

def get_domain(url):
    if url.startswith("www."):
        url = "http://" + url
    try:
        return urlparse(url).netloc.lower()
    except Exception:
        return ""

def has_non_ascii(text):
    try:
        text.encode("ascii")
        return False
    except UnicodeEncodeError:
        return True

def is_punycode(domain):
    return domain.startswith("xn--") or ".xn--" in domain

def looks_random(domain):
    return len(domain) > 25

def too_many_subdomains(domain):
    return domain.count(".") > 3

def normalize_lookalike(text):
    normalized = text
    for fake, real in COMMON_SUBSTITUTIONS.items():
        normalized = normalized.replace(fake, real)
    normalized = normalized.replace("rn", "m")
    return normalized

def strip_tld(domain):
    parts = domain.split(".")
    if len(parts) >= 2:
        return parts[-2]
    return domain

def detect_brand_lookalike(domain):
    root = strip_tld(domain)
    normalized = normalize_lookalike(root)

    for brand in TRUSTED_BRANDS:
        if root != brand and normalized == brand:
            return brand
    return None

def analyze_urls(text):
    urls = extract_urls(text)
    findings = []
    risk_score = 0

    for url in urls:
        domain = get_domain(url)

        if not domain:
            continue

        domain_deception = False

        # Shortener detection
        if domain in SHORTENERS:
            findings.append(f"Shortened URL detected: {domain}")
            risk_score += 2

        # Reputation heuristics
        if domain in COMMON_TRACKING_DOMAINS:
            findings.append(f"Known tracking domain: {domain}")
            risk_score += 2

        if looks_random(domain):
            findings.append(f"Unusually long domain: {domain}")
            risk_score += 1

        if too_many_subdomains(domain):
            findings.append(f"Excessive subdomains: {domain}")
            risk_score += 1

        # Punycode detection
        if is_punycode(domain):
            findings.append(f"Punycode domain detected: {domain}")
            risk_score += 5
            domain_deception = True

        # Non-ASCII detection
        if has_non_ascii(domain):
            findings.append(f"Non-ASCII domain detected: {domain}")
            risk_score += 5
            domain_deception = True

        # Brand lookalike detection
        lookalike_brand = detect_brand_lookalike(domain)
        if lookalike_brand:
            findings.append(f"Possible homograph/lookalike domain for {lookalike_brand}: {domain}")
            risk_score += 5
            domain_deception = True

        # High-risk TLD
        for tld in HIGH_RISK_TLDS:
            if domain.endswith(tld):
                findings.append(f"High-risk TLD detected: {domain}")
                risk_score += 3
                break

        # Suspicious keywords in URL
        lowered_url = url.lower()
        matched_words = [word for word in SUSPICIOUS_URL_WORDS if word in lowered_url]

        if matched_words:
            if is_trusted_domain(domain):
                findings.append(
                    f"Trusted domain with sensitive keywords in URL: {url}: {', '.join(matched_words)}"
                )
            elif domain_deception:
                findings.append(
                    f"Sensitive keywords present, but domain deception is already the dominant signal: {url}: {', '.join(matched_words)}"
                )
                # no extra score
            else:
                findings.append(
                    f"Suspicious URL keywords in {url}: {', '.join(matched_words)}"
                )
                risk_score += 1

    return {
        "urls_found": urls,
        "url_risk_score": risk_score,
        "url_findings": findings
    }

# Test
if __name__ == "__main__":
    test_emails = [
        "Normal login link: https://google.com/login",
        "Lookalike domain: https://go0gle.com/login",
        "Lookalike PayPal: https://paypa1.com/security-check",
        "Punycode example: https://xn--googl-fsa.com/login",
        "High-risk TLD: https://google-login.top/verify",
        "Trusted Google alert: https://accounts.google.com/signin",
        "Tracking link: https://awstrack.me/offer/win-big-now",
        "Many subdomains: https://login.secure.verify.account.update.evil.com/reset",
        "Click here: https://awstrack.me/offer/win-big-now",
        "Verify now: https://login.secure.verify.account.update.evil.com"
    ]

    for email in test_emails:
        print("\n" + "=" * 50)
        print(email)
        print(analyze_urls(email))