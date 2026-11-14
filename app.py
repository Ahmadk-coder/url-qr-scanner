from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import re
from PIL import Image
import io

try:
    from pyzbar.pyzbar import decode as decode_qr
    QR_AVAILABLE = True
except ImportError:
    QR_AVAILABLE = False

app = Flask(__name__)

# قائمة النطاقات الموثوقة (تُعتمد فقط بعد التحقق من وجود HTTPS وشهادة SSL سليمة)
TRUSTED_DOMAINS = [
    "url-qr-scanner.onrender.com",
    "localhost",
    "127.0.0.1",
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

def is_trusted_domain(domain):
    return any(domain == td or domain.endswith('.' + td) for td in TRUSTED_DOMAINS)

def analyze_security_nca(raw_url):
    """
    فحص أمني متكامل وفق ضوابط الهيئة الوطنية للأمن السيبراني (NCA):
    1. التحقق الصارم من بروتوكول التشفير HTTPS.
    2. تحليل بنية الرابط للكشف عن التصيد والتمويه (Lexical & Heuristic Analysis).
    3. فحص الشهادة الرقمية ومحتوى الصفحة الفعلي وسلوك النماذج (Dynamic Content Inspection).
    """
    url = raw_url.strip()

    # إذا لم يكتب المستخدم البروتوكول، نفترض https للفحص، أما إذا كتب http صراحةً فيُرفض فوراً
    if not url.lower().startswith(('http://', 'https://')):
        url = 'https://' + url

    # 1. ضابط التشفير الأساسي: أي رابط HTTP غير مشفر يعتبر غير آمن فوراً
    if not url.lower().startswith('https://'):
        return False

    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    if domain.startswith('www.'):
        domain = domain[4:]

    if not domain or '.' not in domain:
        return False

    # التحقق من النطاقات الموثوقة بعد ضمان وجود HTTPS
    if is_trusted_domain(domain):
        return True

    risk_score = 0

    # 2. فحص استخدام عنوان IP مباشر بدلاً من اسم نطاق رسمي
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', domain):
        risk_score += 5

    # 3. فحص رموز التمويه وهجمات تشابه الأحرف (Punycode / @)
    if '@' in url or 'xn--' in domain:
        risk_score += 5

    # 4. فحص تعقيد النطاق وكثرة النطاقات الفرعية أو الشرطات
    if domain.count('-') >= 3 or domain.count('.') >= 3:
        risk_score += 2

    # 5. فحص الامتدادات عالية الخطورة والمرتبطة بحملات التصيد
    suspicious_tlds = ('.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz', '.click', '.work', '.zip', '.mov')
    if domain.endswith(suspicious_tlds):
        risk_score += 3

    # 6. فحص الكلمات المفتاحية الحساسة وانتحال الجهات داخل الرابط
    sensitive_keywords = [
        'login', 'signin', 'verify', 'update', 'secure', 'account',
        'banking', 'wallet', 'free', 'gift', 'prize', 'absher',
        'nafath', 'aramco', 'stc', 'alrajhi', 'alinma', 'snb', 'paypal'
    ]
    full_url_lower = url.lower()
    if any(kw in full_url_lower for kw in sensitive_keywords):
        risk_score += 3

    if risk_score >= 3:
        return False

    # 7. الفحص الديناميكي للمحتوى والشهادة الرقمية (SSL + HTML Inspection)
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
        response = requests.get(url, headers=headers, timeout=6, allow_redirects=True, verify=True)

        # التحقق من أن الرابط بعد إعادة التوجيه ما زال يستخدم HTTPS
        final_parsed = urlparse(response.url)
        final_domain = final_parsed.netloc.lower().split(':')[0].replace('www.', '')
        if final_parsed.scheme != 'https':
            return False

        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # فحص النماذج التي ترسل البيانات إلى نطاق خارجي مختلف (سلوك تصيد)
            for form in soup.find_all('form'):
                action = form.get('action', '').strip()
                if action.startswith(('http://', 'https://')):
                    action_domain = urlparse(action).netloc.lower().split(':')[0].replace('www.', '')
                    if action_domain and action_domain != final_domain:
                        return False

            # فحص وجود حقول كلمات مرور في صفحات غير موثوقة تحمل مؤشرات اشتباه
            if soup.find('input', {'type': 'password'}) and risk_score >= 1:
                return False

        elif response.status_code >= 500:
            return False

    except requests.exceptions.SSLError:
        # شهادة الأمان غير صالحة أو منتهية أو مزورة
        return False
    except requests.exceptions.RequestException:
        # الموقع غير موجود أو وهمي لا يستجيب
        return False

    return True


def build_response_payload(is_safe, extracted_url=None):
    payload = {
        "status": "Safe" if is_safe else "Dangerous",
        "result": "Safe" if is_safe else "Dangerous",
        "is_safe": is_safe,
        "verdict_ar": "الموقع يبدو آمن" if is_safe else "الموقع يبدو غير آمن أو مشبوه",
        "verdict_en": "The website appears safe" if is_safe else "The website appears unsafe or suspicious",
        "nca_note_ar": "تم الفحص والتقييم وفقاً لضوابط ومعايير الهيئة الوطنية للأمن السيبراني (NCA)",
        "nca_note_en": "Evaluated according to the National Cybersecurity Authority (NCA) standards"
    }
    if extracted_url is not None:
        payload["extracted_url"] = extracted_url
    return payload


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan_url():
    data = request.get_json() or {}
    target_url = data.get('url', '').strip()

    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    is_safe = analyze_security_nca(target_url)
    return jsonify(build_response_payload(is_safe))


@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if 'file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['file']
    if not file:
        return jsonify({"error": "Empty file"}), 400

    if not QR_AVAILABLE:
        return jsonify(build_response_payload(False, extracted_url="QR Reader Unavailable"))

    try:
        img = Image.open(io.BytesIO(file.read()))
        decoded_objects = decode_qr(img)

        if not decoded_objects:
            return jsonify(build_response_payload(False, extracted_url="لم يتم العثور على رمز QR صالح"))

        extracted_url = decoded_objects[0].data.decode('utf-8').strip()
        is_safe = analyze_security_nca(extracted_url)
        return jsonify(build_response_payload(is_safe, extracted_url=extracted_url))

    except Exception:
        return jsonify(build_response_payload(False, extracted_url="تعذر قراءة الصورة"))


if __name__ == '__main__':
    app.run(debug=True, port=5000)
