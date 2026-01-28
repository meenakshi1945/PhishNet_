import re
import requests
from urllib.parse import urlparse

class PhishingDetector:
    def __init__(self):
        self.suspicious_keywords = [
            'login', 'verify', 'account', 'banking', 'paypal', 'ebay', 'amazon',
            'security', 'update', 'confirm', 'password', 'credential'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top']
        
        self.trusted_domains = [
            'google.com', 'facebook.com', 'amazon.com', 'microsoft.com',
            'apple.com', 'netflix.com', 'twitter.com', 'instagram.com'
        ]
    
    def analyze_url(self, url):
        """Analyze a URL for phishing indicators"""
        score = 0
        alerts = []
        warnings = []
        positive = []
        
        try:
            
            if len(url) > 75:
                score += 15
                alerts.append("URL is unusually long (common in phishing)")
            
            
            ip_pattern = r'\d+\.\d+\.\d+\.\d+'
            if re.search(ip_pattern, url):
                score += 25
                alerts.append("Uses IP address instead of domain name")
            
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            if any(domain.endswith(tld) for tld in self.suspicious_tlds):
                score += 20
                alerts.append("Uses suspicious top-level domain")
            
            
            if '@' in url:
                score += 25
                alerts.append("Contains @ symbol (can hide real domain)")
            
            
            if domain.count('.') > 2:
                score += 10
                warnings.append("Multiple subdomains detected")
            
        
            if any(keyword in url.lower() for keyword in self.suspicious_keywords):
                score += 5
                warnings.append("Contains sensitive keywords")
            
        
            if any(trusted in domain for trusted in self.trusted_domains):
                score -= 10
                positive.append("Contains trusted domain name")
            
        
            if url.startswith('https://'):
                score -= 5
                positive.append("Uses HTTPS encryption")
            else:
                score += 10
                warnings.append("Does not use HTTPS")
            
            
            shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly']
            if any(short in domain for short in shorteners):
                score += 15
                warnings.append("Uses URL shortening service")
            
            
            if score >= 50:
                risk_level = "🚨 HIGH RISK"
                recommendation = "DO NOT PROCEED - Likely phishing site"
                color = "danger"
            elif score >= 25:
                risk_level = "⚠️ MEDIUM RISK"
                recommendation = "Proceed with extreme caution"
                color = "warning"
            elif score >= 10:
                risk_level = "ℹ️ LOW RISK"
                recommendation = "Proceed with caution"
                color = "info"
            else:
                risk_level = "✅ LIKELY SAFE"
                recommendation = "Appears safe to proceed"
                color = "success"
            
            return {
                "risk_score": score,
                "risk_level": risk_level,
                "recommendation": recommendation,
                "color": color,
                "alerts": alerts,
                "warnings": warnings,
                "positive": positive,
                "domain": domain if domain else "Invalid URL"
            }
            
        except Exception as e:
            return {
                "risk_score": 100,
                "risk_level": "🚨 ANALYSIS ERROR",
                "recommendation": "Unable to analyze URL",
                "color": "danger",
                "alerts": [f"Analysis failed: {str(e)}"],
                "warnings": [],
                "positive": [],
                "domain": "Unknown"
            }