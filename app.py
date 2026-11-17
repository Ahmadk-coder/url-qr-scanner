from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
import io
from PIL import Image

try:
    from pyzbar.pyzbar import decode as decode_qr
    PYZBAR_AVAILABLE = True
except ImportError:
    PYZBAR_AVAILABLE = False

app = Flask(__name__)

# نطاقات موثوقة (تُعتمد فقط بعد التحقق من وجود تشفير HTTPS صالح)
TRUSTED_DOMAINS = [
    "url-qr-scanner.onrender.com",
    "google.com",
    "github.com",
    "ksu.edu.sa",
    "absher.sa",
    "iam.gov.sa",
    "nafath.sa",
    "nca.gov.sa",
    "microsoft.com",
    "apple.com"
]

def evaluate_url_nca(raw_url):
    """
    تقييم أمان الرابط ومحتواه وفق ضوابط الهيئة الوطنية للأمن السيبراني (NCA):
    1. إلزامية التشفير HTTPS وصلاحية شهادة SSL/TLS.
    2. فحص بنية الرابط للكشف عن التصيد والتمويه.
    3. فحص محتوى الصفحة الفعلي وسلوك النماذج (Forms).
    """
    if not raw_url or not isinstance(raw_url, str):
        return False, 0

    url = raw_url.strip()

    # رفض فوري لأي رابط غير مشفر يبدأ بـ http://
    if url.lower().startswith('http://'):
        return False, 0

    # إذا لم يكتب المستخدم البروتوكول نضيف https:// للفحص
    if not url.lower().startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]

    # التحقق من صحة بنية النطاق
    if not domain or '.' not in domain or ' ' in domain:
        return False, 0

    # اعتماد النطاقات الموثوقة بعد ضمان وجود HTTPS
    if any(domain == td or domain.endswith('.' + td) for td in TRUSTED_DOMAINS):
        return True, 100

    risk_score = 0
    score = 90  # نقطة بداية قياسية للمواقع الآمنة عبر HTTPS غير الموجودة في القائمة البيضاء

    # منع عناوين IP المباشرة
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        return False, 0

    # كشف رموز التمويه وانتحال النطاقات (Punycode / @ / كثرة النطاقات الفرعية)
    if '@' in url or 'xn--' in domain or domain.count('.') >= 3 or domain.count('-') >= 3:
        risk_score += 3
        score -= 30

    # كشف الكلمات الحساسة المستخدمة في التصيد
    phishing_keywords = [
        'login', 'signin', 'verify', 'update', 'secure', 'account',
        'banking', 'wallet', 'free', 'gift', 'prize', 'absher',
        'nafath', 'confirm', 'aramco', 'stc', 'alrajhi', 'alinma', 'snb'
    ]
    if any(kw in url.lower() for kw in phishing_keywords):
        risk_score += 3
        score -= 35

    # كشف الامتدادات عالية الخطورة
    suspicious_tlds = ('.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.click', '.zip', '.mov')
    if domain.endswith(suspicious_tlds):
        risk_score += 3
        score -= 35

    if risk_score >= 3:
        return False, max(10, score)

    # الفحص الديناميكي للموقع وشهادة SSL ومحتوى HTML
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=6, allow_redirects=True, verify=True)

        # التأكد أن إعادة التوجيه لم تنقل المستخدم لرابط غير مشفر
        if not response.url.lower().startswith('https://'):
            return False, 20

        final_domain = urlparse(response.url).netloc.lower().split(':')[0].replace('www.', '')

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # فحص النماذج التي ترسل البيانات إلى نطاق خارجي أو غير مشفر
            for form in soup.find_all('form'):
                action = form.get('action', '').strip()
                if action.lower().startswith('http://'):
                    return False, 10
                if action.lower().startswith('https://'):
                    action_domain = urlparse(action).netloc.lower().split(':')[0].replace('www.', '')
                    if action_domain and action_domain != final_domain:
                        score -= 25

            # فحص حقول كلمة المرور عند وجود أي مؤشر اشتباه
            if soup.find('input', {'type': 'password'}) and risk_score >= 1:
                return False, 15
        elif response.status_code >= 500:
            return False, 30

    except requests.exceptions.SSLError:
        return False, 0
    except requests.exceptions.RequestException:
        score -= 20

    score = max(0, min(100, score))
    return True, score


def build_payload(is_safe, score=100, extracted_url=None):
    status_label = "Safe" if is_safe else "Dangerous"
    data = {
        "status": status_label,
        "result": status_label,
        "is_safe": is_safe,
        "score": score  # الحقل المضاف لإرسال نسبة الأمان للواجهة
    }
    if extracted_url is not None:
        data["extracted_url"] = extracted_url
    return data


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_url():
    body = request.get_json() or {}
    target_url = body.get('url', '').strip()

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    is_safe, score = evaluate_url_nca(target_url)
    return jsonify(build_payload(is_safe, score))


@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file or not PYZBAR_AVAILABLE:
        return jsonify(build_payload(False, 0, "تعذر قراءة الرمز"))

    try:
        img = Image.open(io.BytesIO(file.read()))
        decoded_objects = decode_qr(img)
        if not decoded_objects:
            return jsonify(build_payload(False, 0, "لم يتم العثور على رمز QR صالح"))

        extracted_url = decoded_objects[0].data.decode('utf-8').strip()
        is_safe, score = evaluate_url_nca(extracted_url)
        return jsonify(build_payload(is_safe, score, extracted_url))
    except Exception:
        return jsonify(build_payload(False, 0, "خطأ في قراءة الصورة"))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
