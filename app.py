from flask import Flask, render_template, request, jsonify
from detector import PhishingDetector
import json

app = Flask(__name__)
detector = PhishingDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    url = data.get('url', '').strip()
    
    if not url:
        return jsonify({
            "error": "Please enter a URL"
        })
    
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    

    result = detector.analyze_url(url)
    
    return jsonify(result)

@app.route('/examples')
def get_examples():
    """Provide some example URLs for testing"""
    examples = {
        "safe": [
            "https://google.com",
            "https://github.com",
            "https://python.org"
        ],
        "suspicious": [
            "http://paypal-security-verify.com",
            "https://amazon-update-account.tk",
            "http://192.168.1.1/login.php"
        ]
    }
    return jsonify(examples)

if __name__ == '__main__':
    app.run(debug=True, port=5000)