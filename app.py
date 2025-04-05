from flask import Flask, render_template, request, jsonify
import math
import requests
import hashlib
import re

app = Flask(__name__)

def calculate_entropy(password):
    pool_size = 0
    if re.search(r'[a-z]', password): pool_size += 26
    if re.search(r'[A-Z]', password): pool_size += 26
    if re.search(r'[0-9]', password): pool_size += 10
    if re.search(r'[^a-zA-Z0-9]', password): pool_size += 32
    return len(password) * math.log2(pool_size) if pool_size else 0

def check_hibp(password):
    try:
        sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            headers={'User-Agent': 'PasswordAnalyzer'}
        )
        return any(line.startswith(suffix) for line in response.text.splitlines())
    except Exception:
        return False

def analyze_password(password):
    suggestions = []
    strength = 0
    
    # Basic checks
    if len(password) < 8:
        suggestions.append("Use at least 8 characters")
    if not re.search(r'\d', password):
        suggestions.append("Add numbers")
    if not re.search(r'[A-Z]', password):
        suggestions.append("Add uppercase letters")
    if not re.search(r'[^a-zA-Z0-9]', password):
        suggestions.append("Add special characters")
    
    # Entropy calculation
    entropy = calculate_entropy(password)
    strength += min(entropy / 128 * 100, 100)  # Normalize to percentage
    
    # Common patterns
    common_patterns = [
        r'123456', r'password', r'qwerty', 
        r'^\d+$', r'^[a-zA-Z]+$'
    ]
    if any(re.search(p, password) for p in common_patterns):
        suggestions.append("Avoid common patterns")
        strength *= 0.5
    
    # HIBP check
    if check_hibp(password):
        suggestions.append("Password found in known breaches")
        strength *= 0.3
    
    return {
        'strength': min(max(round(strength, 1), 0), 100),
        'suggestions': suggestions,
        'entropy': round(entropy, 1)
    }

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    password = request.json.get('password', '')
    return jsonify(analyze_password(password))

if __name__ == '__main__':
    app.run(debug=True)