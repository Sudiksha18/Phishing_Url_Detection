import re
import requests
import whois
from urllib.parse import urlparse
from googlesearch import search as google_search

class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.domain = urlparse(url).netloc
        self.whois_response = self.get_whois_info()

    def get_whois_info(self):
        try:
            return whois.whois(self.domain)
        except Exception:
            return None

    def get_google_search_results(self):
        try:
            return list(google_search(self.domain, num_results=5))
        except Exception:
            return []

    def get_features(self):
        features = []

        # ✅ **URL-Based Features**
        features.append(len(self.url))  # URL Length
        features.append(self.url.count('/'))  # Slash count
        features.append(self.url.count('.'))  # Dot count (subdomains)
        features.append(self.url.count('-'))  # Hyphen count

        # ✅ **Detect phishing-related keywords**
        phishing_keywords = ['login', 'secure', 'verify', 'bank', 'account', 'password', 'update', 'confirm']
        features.append(sum(1 for word in phishing_keywords if word in self.url.lower()))

        # ✅ **Check if URL contains an IP address (common phishing trick)**
        features.append(1 if re.match(r'http[s]?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.url) else 0)

        # ✅ **Domain-Based Features**
        features.append(1 if '-' in self.domain else 0)  # Prefix-Suffix
        features.append(1 if self.domain.count('.') > 2 else 0)  # Subdomains
        features.append(1 if self.whois_response and self.whois_response.domain_name else 0)  # WHOIS presence

        # ✅ **SSL & Security Features**
        try:
            response = requests.get(self.url, timeout=5)
            features.append(1 if response.url.startswith("https") else 0)  # HTTPS
        except:
            features.append(0)  # Assume no HTTPS if request fails

        # ✅ **Google Index Feature**
        search_results = self.get_google_search_results()
        features.append(1 if len(search_results) > 0 else 0)  # Google Index

        # ✅ **Blacklist Feature**
        blacklist_domains = ["testsafebrowsing.appspot.com", "phishing.com", "malicious.com"]
        features.append(1 if any(domain in self.url for domain in blacklist_domains) else 0)  # Known phishing sites

        # ✅ **Domain Age Feature**
        try:
            creation_date = self.whois_response.creation_date
            expiration_date = self.whois_response.expiration_date
            if creation_date and expiration_date:
                domain_age = (expiration_date[0] - creation_date[0]).days if isinstance(expiration_date, list) else (expiration_date - creation_date).days
                features.append(1 if domain_age < 180 else 0)  # Mark domain as suspicious if it's less than 6 months old
            else:
                features.append(0)
        except:
            features.append(0)

        # ✅ **Ensure Exactly 31 Features**
        while len(features) < 31:
            features.append(0)

        print(f"Extracted Features ({len(features)}): {features}")  # Debugging output
        return features
