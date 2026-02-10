import re
from urllib.parse import urlparse
import tldextract
import ipaddress
import math

# --- Academic Feature Definitions ---
# Grouped into Lexical, Host-Based, and Content-Based (simulated) features

SUSPICIOUS_TLDS = {
    'xyz', 'top', 'club', 'online', 'vip', 'cc', 'tk', 'ml', 'ga', 'cf', 'work', 
    'date', 'review', 'link', 'click', 'site', 'win', 'party', 'gq'
}

SENSITIVE_KEYWORDS = [
    'login', 'secure', 'account', 'verify', 'update', 'banking', 'signin', 
    'password', 'confirm', 'security', 'wallet', 'crypto', 'unlock', 'bonus'
]

BRAND_DOMAINS = [
    'apple', 'google', 'paypal', 'amazon', 'microsoft', 'facebook', 'netflix', 
    'instagram', 'whatsapp', 'linkedin', 'dropbox', 'ebay', 'chase', 'wellsfargo', 
    'bankofamerica', 'citibank'
]

def entropy(string):
    """Calculates the Shannon entropy of a string."""
    prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
    entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
    return entropy

class FeatureExtractor:
    """
    Advanced URL Feature Extractor for Phishing Detection.
    Extracts 20+ features categorized into Lexical and Host-based features.
    """
    
    @staticmethod
    def extract(url: str) -> dict:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
            
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
            
            domain = parsed.netloc.lower()
            path = parsed.path.lower()
            query = parsed.query
            tld = ext.suffix.lower()
            
            features = {}
            
            # --- 1. Address Bar Based Features ---
            features['url_length'] = len(url)
            features['domain_length'] = len(domain)
            features['is_https'] = 1 if parsed.scheme == 'https' else 0
            features['ip_in_url'] = FeatureExtractor._has_ip_address(domain)
            features['at_symbol'] = 1 if '@' in url else 0
            features['double_slash_redirect'] = 1 if url.rfind('//') > 7 else 0
            features['dash_in_domain'] = 1 if '-' in domain else 0
            features['dots_in_domain'] = domain.count('.')
            features['https_token_in_domain'] = 1 if 'https' in domain else 0
            
            # --- 2. Abnormal Based Features ---
            features['subdomain_depth'] = ext.subdomain.count('.') + 1 if ext.subdomain else 0
            features['suspicious_tld'] = 1 if tld in SUSPICIOUS_TLDS else 0
            features['shortening_service'] = FeatureExtractor._is_shortener(domain)
            
            # --- 3. Lexical Features ---
            features['path_depth'] = path.count('/')
            features['query_length'] = len(query)
            features['special_chars_count'] = sum(url.count(c) for c in ['?', '=', '&', '%', '_', '~'])
            features['sensitive_words_count'] = sum(1 for w in SENSITIVE_KEYWORDS if w in url.lower())
            features['brand_impersonation'] = FeatureExtractor._check_brand_impersonation(domain, path)
            features['url_entropy'] = entropy(url)
            features['digit_count'] = sum(c.isdigit() for c in url)
            features['letter_count'] = sum(c.isalpha() for c in url)
            
            # --- 4. Derived Features (Simulated for real-time speed) ---
            # In a full system, these would check WHOIS or DNS records
            features['tld_length'] = len(tld)
            
            return features
            
        except Exception as e:
            # Fallback for malformed URLs
            return None

    @staticmethod
    def _has_ip_address(domain):
        try:
            ipaddress.ip_address(domain)
            return 1
        except:
            return 0

    @staticmethod
    def _is_shortener(domain):
        shorteners = {'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 't.co', 'is.gd', 'buff.ly', 'adf.ly', 'bit.do'}
        return 1 if domain in shorteners else 0

    @staticmethod
    def _check_brand_impersonation(domain, path):
        full_str = domain + path
        for brand in BRAND_DOMAINS:
            if brand in full_str and f"{brand}.com" not in domain:
                return 1
        return 0
