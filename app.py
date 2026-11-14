from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from PIL import Image
import io

# محاولة استيراد مكتبة قراءة الـ QR
try:
    from pyzbar.pyzbar import decode as decode_qr
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

app = Flask(__name__)

# نطاقات موثوقة أو خاصة بالمشروع لتجنب الإنذارات الكاذبة
TRUSTED_DOMAINS = [
    "url-qr-scanner.onrender.com",
    "localhost",
    "127.0.0.1",
    "google.com",
    "github.com",
    "ksu.edu.sa",
    "absher.sa",
    "iam.gov.sa",
    "microsoft.com",
    "apple.com"
]

def evaluate_url_and_content(url):
    """
    محرك التحليل الذكي: يجمع بين خصائص الرابط (URL Features) وفحص المحتوى الفعلي (Content Analysis)
    ويعطي سبباً واضحاً وبسيطاً يفهمه المستخدم العادي.
    """
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().replace('www.', '')
    
    # استثناء النطاقات الرسمية ونطاق المشروع
    if any(domain == td or domain.endswith('.' + td) for td in TRUSTED_DOMAINS):
        return {
            "is_safe": True,
            "title_ar": "موقع آمن وموثوق",
            "title_en": "Safe & Trusted Website",
            "desc_ar": "هذا الرابط يتبع لنطاق موثوق ولا توجد عليه أي مؤشرات خطورة.",
            "desc_en": "This link belongs to a trusted domain with no risk indicators."
        }

    risk_score = 0
    reasons_ar = []
    reasons_en = []

    # 1. فحص التشفير (HTTPS)
    if parsed.scheme != 'https':
        risk_score += 3
        reasons_ar.append("الرابط غير مشفر (يستخدم HTTP بدلاً من HTTPS) مما يعرض بياناتك للخطر")
        reasons_en.append("Unencrypted connection (uses HTTP instead of HTTPS)")

    # 2. فحص استخدام عنوان IP مباشر بدلاً من اسم نطاق
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}(:\d+)?$', domain):
        risk_score += 4
        reasons_ar.append("الرابط يستخدم عنوان IP مباشر لإخفاء هوية الموقع")
        reasons_en.append("Uses a raw IP address instead of a legitimate domain name")

    # 3. فحص الكلمات المفتاحية الخادعة في الرابط نفسه (مثل login.com أو verify-account)
    phishing_keywords = ['login', 'signin', 'verify', 'update', 'secure', 'account', 'banking', 'wallet', 'free', 'gift', 'prize', 'absher', 'nafath']
    full_url_lower = url.lower()
    matched_keywords = [kw for kw in phishing_keywords if kw in full_url_lower]
    if matched_keywords:
        risk_score += 3
        reasons_ar.append("يحتوي الرابط على كلمات حساسة تُستخدم غالباً في صفحات التصيد وسرقة الحسابات")
        reasons_en.append("URL contains sensitive keywords commonly used in phishing attacks")

    # 4. فحص الامتدادات الرخيصة والمشبوهة بكثرة في التصيد
    suspicious_tlds = ('.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.click')
    if domain.endswith(suspicious_tlds):
        risk_score += 2
        reasons_ar.append("امتداد النطاق يُستخدم بكثرة في المواقع الوهمية والمؤقتة")
        reasons_en.append("Domain extension is frequently abused by temporary phishing sites")

    # 5. فحص رموز التمويه وطول الرابط
    if '@' in url or domain.count('-') >= 3 or domain.count('.') >= 3:
        risk_score += 2
        reasons_ar.append("بنية الرابط معقدة أو تحتوي على رموز تمويه لإخفاء الوجهة الحقيقية")
        reasons_en.append("Obfuscated URL structure with excessive subdomains or symbols")

    # 6. زيارة الصفحة فعلياً وفحص محتواها (Content Inspection)
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=5, allow_redirects=True)
        
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # فحص النماذج التي ترسل البيانات لموقع خارجي
            for form in soup.find_all('form'):
                action = form.get('action', '')
                if action.startswith('http'):
                    action_domain = urlparse(action).netloc.lower().replace('www.', '')
                    if action_domain and action_domain != domain:
                        risk_score += 5
                        reasons_ar.append("الموقع يرسل بياناتك إلى خادم خارجي مختلف (سلوك تصيد صريح)")
                        reasons_en.append("Form submits user data to an external third-party domain")
                        break
            
            # فحص حقول كلمة المرور في المواقع المشبوهة
            if soup.find('input', {'type': 'password'}) and risk_score >= 2:
                risk_score += 3
                reasons_ar.append("الصفحة تطلب كلمة مرور رغم وجود مؤشرات عدم أمان في الرابط")
                reasons_en.append("Page requests a password despite security red flags in the URL")
        else:
            risk_score += 2
            reasons_ar.append("الموقع غير مستقر أو يرفض الاستجابة الطبيعية")
            reasons_en.append("Website returned an abnormal status code")

    except requests.exceptions.RequestException:
        # إذا كان الموقع لا يعمل أصلاً أو وهمي وغير متصل
        risk_score += 3
        reasons_ar.append("تعذر الوصول للموقع أو أنه رابط وهمي غير نشط")
        reasons_en.append("Website is unreachable or inactive")

    # اتخاذ القرار النهائي بناءً على مجموع نقاط الخطر
    if risk_score >= 3:
        return {
            "is_safe": False,
            "title_ar": "تحذير: رابط مشبوه / غير آمن",
            "title_en": "Warning: Suspicious / Unsafe Link",
            "desc_ar": reasons_ar[0] if reasons_ar else "تم رصد مؤشرات تصيد واحتيال في هذا الرابط.",
            "desc_en": reasons_en[0] if reasons_en else "Phishing and fraud indicators detected in this link."
        }
    else:
        return {
            "is_safe": True,
            "title_ar": "الموقع آمن للاستخدام",
            "title_en": "Website is Safe to Use",
            "desc_ar": "الاتصال مشفر والرابط طبيعي ولا يظهر عليه أي سلوك تصيد.",
            "desc_en": "Connection is encrypted and no phishing behavior was detected."
        }


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json()
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    analysis = evaluate_url_and_content(target_url)
    status_label = "Safe" if analysis["is_safe"] else "Dangerous"

    return jsonify({
        "status": status_label,
        "result": status_label,
        "is_safe": analysis["is_safe"],
        "message_ar": analysis["title_ar"],
        "message_en": analysis["title_en"],
        "message": analysis["desc_ar"],
        "compliance_note": analysis["desc_en"]
    })


@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    
    file = request.files['file']
    if not file:
        return jsonify({"error": "Empty file"}), 400

    if not QR_AVAILABLE:
        return jsonify({
            "status": "Dangerous",
            "is_safe": False,
            "extracted_url": "Library Missing",
            "message_ar": "مكتبة قراءة QR غير مثبتة",
            "message_en": "QR Library not installed",
            "message": "يرجى تثبيت مكتبة pyzbar على السيرفر لقراءة الصور."
        })

    try:
        img = Image.open(io.BytesIO(file.read()))
        decoded_objects = decode_qr(img)
        
        if not decoded_objects:
            return jsonify({
                "status": "Dangerous",
                "is_safe": False,
                "extracted_url": "غير مقروء / No QR found",
                "message_ar": "لم يتم العثور على رمز QR واضح",
                "message_en": "No valid QR code found",
                "message": "تأكد من وضوح الصورة وأنها تحتوي على رمز QR صالح."
            })

        extracted_url = decoded_objects[0].data.decode('utf-8')
        analysis = evaluate_url_and_content(extracted_url)
        status_label = "Safe" if analysis["is_safe"] else "Dangerous"

        return jsonify({
            "status": status_label,
            "result": status_label,
            "is_safe": analysis["is_safe"],
            "extracted_url": extracted_url,
            "message_ar": analysis["title_ar"],
            "message_en": analysis["title_en"],
            "message": analysis["desc_ar"],
            "compliance_note": analysis["desc_en"]
        })

    except Exception as e:
        return jsonify({
            "status": "Dangerous",
            "is_safe": False,
            "extracted_url": "Error",
            "message_ar": "خطأ في قراءة الصورة",
            "message_en": "Error reading image",
            "message": "تعذر تحليل الصورة المرفوعة، جرب صورة أخرى."
        })


if __name__ == '__main__':
    app.run(debug=True, port=5000)
