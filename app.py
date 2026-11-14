from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = Flask(__name__)

def analyze_web_content(url):
    """
    الدالة المسؤولة عن فحص محتوى الصفحة، تتبع كود الـ HTML، 
    وفحص حقول كلمات المرور والنماذج (Forms) للتأكد مما إذا كانت ترسل البيانات لدومينات خارجية.
    """
    features = {
        "has_password_field": 0,
        "external_form_action": 0,
        "suspicious_keywords_in_content": 0,
        "page_reachable": 0,
        "is_https": 0
    }
    
    # 1. التحقق الصارم من بروتوكول HTTPS
    parsed_url = urlparse(url)
    if parsed_url.scheme == 'https':
        features["is_https"] = 1
    
    try:
        # إرسال طلب HTTP آمن مع مهلة زمنية قصيرة لحماية السيرفر
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        
        if response.status_code == 200:
            features["page_reachable"] = 1
            html_content = response.text
            soup = BeautifulSoup(html_content, 'html.parser')
            
            # 2. البحث عن حقول إدخال كلمة المرور (مؤشر تصيد لسرقة الباسوورد)
            if soup.find('input', {'type': 'password'}):
                features["has_password_field"] = 1
                
            # 3. تتبع نماذج الإدخال (Forms) ومعرفة أين تُرسل البيانات المدخلة
            parsed_original_url = urlparse(url)
            forms = soup.find_all('form')
            for form in forms:
                action = form.get('action', '')
                if action:
                    parsed_action = urlparse(action)
                    # إذا كانت النماذج ترسل البيانات لدومين خارجي مختلف تماماً (External Form Action)
                    if parsed_action.netloc and parsed_action.netloc != parsed_original_url.netloc:
                        features["external_form_action"] = 1
                        break
            
            # 4. تتبع الكلمات المفتاحية الشائعة في صفحات التصيد داخل محتوى الصفحة
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
    
    # تنفيذ الفحص ومحتوى الصفحة
    content_features = analyze_web_content(target_url)
    
    # قواعد القرار الأمنية: الموقع يعتبر مشبوه/غير آمن إذا كان:
    # - يستخدم HTTP (ليس HTTPS)
    # - أو يحتوي على فورم يرسل لخارج الدومين
    # - أو يحتوي على حقل باسوورد في رابط غير مشفر
    # - أو يفتقد لشهادة الأمان
    is_phishing_or_unsafe = (
        content_features["is_https"] == 0 or
        content_features["external_form_action"] == 1 or 
        content_features["has_password_field"] == 1 or
        content_features["suspicious_keywords_in_content"] > 3 or
        content_features["page_reachable"] == 0
    )
    
    # تحديد النتيجة بدقة تامة ومنع التناقض
    result_text = "Risky / Insecure" if is_phishing_or_unsafe else "Legitimate / Safe"
    short_status = "Phishing" if is_phishing_or_unsafe else "Safe"
    
    return jsonify({
        "result": short_status,
        "status": short_status,
        "message": result_text,
        "prediction": short_status,
        "is_safe": not is_phishing_or_unsafe,
        "content_analysis": content_features
    })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
