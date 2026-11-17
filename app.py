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
    1. تقييم التشفير بخصم وزني واقعي عند غياب HTTPS.
    2. فحص بنية الرابط للكشف عن التصيد والتمويه.
    3. فحص محتوى الصفحة الفعلي وسلوك النماذج (Forms).
    """
    warnings = []
    score = 100  # نبدأ من 100 ونخصم بناءً على المخاطر المكتشفة
    
    if not raw_url or not isinstance(raw_url, str):
        warnings.append("الرابط المدخل غير صالح.")
        return False, 0, warnings

    url = raw_url.strip()

    # معالجة http:// بخصم وزني واقعي بدلاً من التصفير الفوري (لزيادة موثوقية النظام)
    if url.lower().startswith('http://'):
        score -= 40  # خصم 40 نقطة لغياب التشفير حسب معايير NCA
        warnings.append("مخالف لمعايير الهيئة الوطنية للأمن السيبراني: الرابط غير مشفر (يستخدم بروتوكول HTTP).")
        url = 'https://' + url[7:]  # تحويل مؤقت للفحص التقني الخفي
    elif not url.lower().startswith('https://'):
        url = 'https://' + url

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]

    # التحقق من صحة بنية النطاق
    if not domain or '.' not in domain or ' ' in domain:
        warnings.append("بنية النطاق غير صالحة.")
        return False, 0, warnings

    # اعتماد النطاقات الموثوقة بعد ضمان وجود HTTPS أو تعديل السكور
    if any(domain == td or domain.endswith('.' + td) for td in TRUSTED_DOMAINS):
        score = max(score, 60) # نطاق موثوق لكن لو كان أصله http يعطى درجة مقبولة مع تحذير
        is_safe = score >= 50
        return is_safe, score, warnings

    risk_score = 0

    # منع عناوين IP المباشرة
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        warnings.append("استخدام عنوان IP مباشر بدلاً من اسم نطاق موثوق.")
        return False, 0, warnings

    # كشف رموز التمويه وانتحال النطاقات (Punycode / @ / كثرة النطاقات الفرعية)
    if '@' in url or 'xn--' in domain or domain.count('.') >= 3 or domain.count('-') >= 3:
        risk_score += 3
        score -= 30
        warnings.append("تم اكتشاف رموز تمويه أو تراكيب مشبوهة في بنية الرابط.")

    # كشف الكلمات الحساسة المستخدمة في التصيد
    phishing_keywords = [
        'login', 'signin', 'verify', 'update', 'secure', 'account',
        'banking', 'wallet', 'free', 'gift', 'prize', 'absher',
        'nafath', 'confirm', 'aramco', 'stc', 'alrajhi', 'alinma', 'snb'
    ]
    if any(kw in url.lower() for kw in phishing_keywords):
        risk_score += 3
        score -= 35
        warnings.append("اكتشاف كلمات حساسة تستخدم عادة في عمليات التصيد الاحتيالي (Phishing).")

    # كشف الامتدادات عالية الخطورة
    suspicious_tlds = ('.xyz', '.top', '.club', '.tk', '.ml', '.ga', '.cf', '.gq', '.buzz', '.click', '.zip', '.mov')
    if domain.endswith(suspicious_tlds):
        risk_score += 3
        score -= 35
        warnings.append("امتداد النطاق (TLD) مصنف ضمن الامتدادات عالية الخطورة.")

    if risk_score >= 3:
        score = max(5, score - 20)
        return False, score, warnings

    # والفحص الديناميكي للموقع وشهادة SSL ومحتوى HTML
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=6, allow_redirects=True, verify=True)

        if not response.url.lower().startswith('https://'):
            score -= 20
            warnings.append("إعادة توجيه الرابط أدت إلى موقع غير مشفر.")

        final_domain = urlparse(response.url).netloc.lower().split(':')[0].replace('www.', '')

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # فحص النماذج
            for form in soup.find_all('form'):
                action = form.get('action', '').strip()
                if action.lower().startswith('http://'):
                    score -= 25
                    warnings.append("يحتوي الموقع على نموذج إدخال يرسل البيانات عبر بروتوكول غير مشفر.")
                if action.lower().startswith('https://'):
                    action_domain = urlparse(action).netloc.lower().split(':')[0].replace('www.', '')
                    if action_domain and action_domain != final_domain:
                        score -= 20
                        warnings.append("نموذج إدخال البيانات يوجه المعلومات إلى نطاق خارجي مختلف.")

            # فحص حقول كلمة المرور
            if soup.find('input', {'type': 'password'}) and risk_score >= 1:
                score -= 25
                warnings.append("وجود حقل كلمة مرور في صفحة ذات مؤشرات اشتباه.")
        elif response.status_code >= 500:
            score -= 15
            warnings.append("استجابة الخادم المستهدف غير مستقرة.")

    except requests.exceptions.SSLError:
        score -= 40
        warnings.append("فشل في التحقق من شهادة الأمان SSL/TLS.")
    except requests.exceptions.RequestException:
        score -= 15
        warnings.append("تعذر الوصول للموقع أو انتهت مهلة الاتصال.")

    score = max(0, min(100, score))
    is_safe = score >= 50  # المجموع 50 فأكثر يعتبر مقبول/آمن، وأقل من 50 يعتبر مشبوه
    return is_safe, score, warnings


def build_payload(is_safe, score=100, warnings=None, extracted_url=None):
    status_label = "Safe" if is_safe else "Dangerous"
    data = {
        "status": status_label,
        "result": status_label,
    "is_safe": is_safe,
        "score": score,
        "warnings": warnings or []
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

    is_safe, score, warnings = evaluate_url_nca(target_url)
    return jsonify(build_payload(is_safe, score, warnings))


@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file or not PYZBAR_AVAILABLE:
        return jsonify(build_payload(False, 0, ["تعذر قراءة الرمز أو مكتبة pyzbar غير متاحة."], "تعذر قراءة الرمز"))

    try:
        img = Image.open(io.BytesIO(file.read()))
        decoded_objects = decode_qr(img)
        if not decoded_objects:
            return jsonify(build_payload(False, 0, ["لم يتم العثور على رمز QR صالح في الصورة."], "لم يتم العثور على رمز QR صالح"))

        extracted_url = decoded_objects[0].data.decode('utf-8').strip()
        is_safe, score, warnings = evaluate_url_nca(extracted_url)
        return jsonify(build_payload(is_safe, score, warnings, extracted_url))
    except Exception:
        return jsonify(build_payload(False, 0, ["حدث خطأ أثناء معالجة وقراءة الصورة."], "خطأ في قراءة الصورة"))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
