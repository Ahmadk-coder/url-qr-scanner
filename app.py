from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)

def analyze_web_content(url):
    features = {
        "has_password_field": 0,
        "external_form_action": 0,
        "suspicious_keywords_in_content": 0,
        "page_reachable": 0,
        "is_https": 0
    }
    
    parsed_url = urlparse(url)
    if parsed_url.scheme == 'https':
        features["is_https"] = 1
    
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        
        if response.status_code == 200:
            features["page_reachable"] = 1
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            if soup.find('input', {'type': 'password'}):
                features["has_password_field"] = 1
                
            parsed_original_url = urlparse(url)
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action:
                    parsed_action = urlparse(action)
                    if parsed_action.netloc and parsed_action.netloc != parsed_original_url.netloc:
                        features["external_form_action"] = 1
                        break
            
            suspicious_words = ['login', 'signin', 'verify', 'update', 'account', 'banking', 'secure', 'تسجيل', 'تحديث', 'حسابك']
            page_text = soup.get_text().lower()
            for word in suspicious_words:
                if word in page_text:
                    features["suspicious_keywords_in_content"] += 1
                    
    except requests.exceptions.RequestException:
        features["page_reachable"] = 0
        
    return features


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    target_url = data.get('url')
    
    if not target_url:
        return jsonify({"error": "No URL provided"}), 400
    
    # تنفيذ الفحص
    content_features = analyze_web_content(target_url)
    
    is_phishing_or_unsafe = (
        content_features["is_https"] == 0 or
        content_features["external_form_action"] == 1 or 
        content_features["has_password_field"] == 1 or
        content_features["suspicious_keywords_in_content"] > 3 or
        content_features["page_reachable"] == 0
    )
    
    # تجهيز النصوص لكي تتطابق مع أي اسم متغير يحتاجه الجافاسكريبت في الواجهة
    status_en = "Phishing / Risky" if is_phishing_or_unsafe else "Legitimate / Safe"
    status_ar = "مشبوه / غير آمن" if is_phishing_or_unsafe else "آمن وصحيح"
    
    short_en = "Phishing" if is_phishing_or_unsafe else "Safe"
    short_ar = "خطر" if is_phishing_or_unsafe else "آمن"
    
    # نرسل كل المفاتيح المحتملة (Result, Status, Message, Prediction, etc.)
    return jsonify({
        # الإنجليزية الأساسية للمتغيرات البرمجية
        "result": short_en,
        "status": short_en,
        "prediction": short_en,
        "message": status_en,
        
        # العربية والإنجليزية التفصيلية
        "message_en": status_en,
        "message_ar": status_ar,
        "short_en": short_en,
        "short_ar": short_ar,
        
        # حقول إضافية لضمان عدم ظهور undefined نهائياً تحت أي ظرف
        "title": short_en,
        "category": short_en,
        "safety": short_en,
        
        "is_safe": not is_phishing_or_unsafe,
        "content_analysis": content_features
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
