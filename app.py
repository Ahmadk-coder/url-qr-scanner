import os
import re
import socket
import ssl
from urllib.parse import urlparse, unquote
from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from PIL import Image
from pyzbar import pyzbar

app = Flask(__name__)

SHORTENER_DOMAINS = {
    'bit.ly', 't.co', 'goo.gl', 'ow.ly', 'me-qr.com',
    'tinyurl.com', 'lnkiy.in', 'is.gd', 'buff.ly', 'cutt.ly', 'rebrand.ly'
}

KNOWN_BRANDS = {
    'absher': '.gov.sa',
    'nafath': '.gov.sa',
    'moe': '.gov.sa',
    'energy': '.gov.sa',
    'moh': '.gov.sa',
    'moi': '.gov.sa',
    'zatca': '.gov.sa',
    'stc': '.com.sa',
    'alrajhi': '.com.sa',
    'alahli': '.com.sa',
    'alinma': '.com.sa',
    'riyadbank': '.com.sa',
    'aramco': '.com'
}

SUSPICIOUS_TLDS = {'.xyz', '.top', '.club', '.online', '.site', '.info', '.biz', '.click', '.link', '.zip', '.mov'}
DANGEROUS_FILE_EXTS = ('.exe', '.apk', '.bat', '.cmd', '.scr', '.vbs', '.ps1', '.msi', '.iso', '.zip', '.rar')
IP_PATTERN = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')


def normalize_url(raw_url: str) -> str:
    url = raw_url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url


def check_ssl_certificate(hostname: str) -> bool:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname=hostname):
                return True
    except Exception:
        return False


def check_dns_resolution(hostname: str) -> bool:
    try:
        socket.getaddrinfo(hostname, None)
        return True
    except Exception:
        return False


def has_punycode(text: str) -> bool:
    return bool(re.search(r'(^|[.@/])xn--', text.lower()))


def analyze_html_sandbox(html_content: str, final_domain: str):
    """
    Logical & Stateless Sandbox:
    Inspects raw HTML statically via BeautifulSoup without executing scripts.
    Focuses on real credential/exfiltration/evasion indicators.
    """
    deductions = 0
    findings = []
    soup = BeautifulSoup(html_content, 'html.parser')

    # 1. Password fields on non-official domains
    password_inputs = soup.find_all('input', {'type': 'password'})
    if password_inputs:
        is_official = final_domain.endswith(('.gov.sa', '.edu.sa', '.org.sa', '.com.sa'))
        if not is_official:
            deductions += 25
            findings.append("حقل كلمة مرور على نطاق عام: الصفحة تطلب كلمة مرور خارج نطاق رسمي معروف؛ لا تدخل بيانات حساسة إلا بعد التحقق من مصدر الرابط.")

    # 2. Forms submitting to a different external domain
    forms = soup.find_all('form')
    for form in forms:
        action = form.get('action', '').strip()
        if action.startswith(('http://', 'https://')):
            action_domain = urlparse(action).netloc.lower().split(':')[0]
            if action_domain and action_domain != final_domain and not action_domain.endswith('.' + final_domain):
                deductions += 35
                findings.append(f"إرسال بيانات لنطاق خارجي ({action_domain}): النموذج يرسل المدخلات لخادم مختلف عن نطاق الصفحة؛ تجنب إدخال أي بيانات هنا.")
                break

    # 3. Hidden iframes
    for iframe in soup.find_all('iframe'):
        style = iframe.get('style', '').replace(' ', '').lower()
        if 'display:none' in style or 'visibility:hidden' in style or iframe.get('width') == '0' or iframe.get('height') == '0':
            deductions += 25
            findings.append("إطار مخفي (Hidden Iframe): توجد نافذة مضمنة مخفية داخل الصفحة قد تُستخدم للتحميل أو التتبع الخفي.")
            break

    # 4. Obfuscated inline scripts
    obfuscation_hits = 0
    for script in soup.find_all('script'):
        script_text = script.string or ''
        if any(pattern in script_text for pattern in ('eval(atob(', 'String.fromCharCode(', 'unescape(')):
            obfuscation_hits += 1

    if obfuscation_hits > 0:
        deductions += 25
        findings.append("كود جافا سكريبت مموه: الصفحة تحتوي على دوال فك تشفير/تمويه شائعة في إخفاء السلوك البرمجي.")

    # 5. Meta refresh auto-redirect
    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'^refresh$', re.I)})
    if meta_refresh:
        content = meta_refresh.get('content', '').lower()
        if 'url=' in content:
            deductions += 20
            findings.append("إعادة توجيه تلقائية (Meta Refresh): الصفحة تحوّل المستخدم تلقائياً إلى وجهة أخرى.")

    return deductions, findings


def evaluate_url_nca(raw_url: str):
    """
    Balanced Multi-Layer Risk Scoring Model:
    Evaluates URL structure, brand impersonation, DNS/SSL, redirects, and static HTML sandbox.
    """
    score = 100
    warnings = []

    url = normalize_url(raw_url)
    decoded_url = unquote(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    path_lower = parsed.path.lower()

    if not domain or '.' not in domain:
        return 0, "رابط غير صالح", ["صيغة الرابط غير صحيحة؛ تأكد من كتابة اسم النطاق بشكل صحيح."], url, "لم يتم الفحص"

    is_ip = bool(IP_PATTERN.match(domain))
    dns_ok = check_dns_resolution(domain)

    # 1. Direct executable/archive download
    if path_lower.endswith(DANGEROUS_FILE_EXTS):
        score -= 40
        warnings.append("ملف قابل للتنفيذ أو مضغوط مباشرة: لا تشغّل الملف بعد تحميله إلا إذا كنت واثقاً تماماً من مصدره.")

    # 2. Lexical & structural checks
    if '@' in decoded_url:
        score -= 35
        warnings.append("وجود رمز (@) في الرابط: يُستخدم أحياناً للتمويه وإيهام المستخدم بنطاق مختلف عن الوجهة الفعلية.")

    if has_punycode(decoded_url):
        score -= 35
        warnings.append("ترميز Punycode (xn--): قد يُستخدم لتقليد حروف متشابهة بصرياً؛ تحقق من عنوان الموقع يدوياً.")

    if is_ip:
        score -= 40
        warnings.append("عنوان IP مباشر بدل اسم نطاق: الروابط المباشرة بأرقام IP شائعة في الصفحات غير الموثوقة أو المؤقتة.")
    elif domain.count('.') >= 3 and not domain.endswith('.sa'):
        score -= 15
        warnings.append("نطاقات فرعية متعددة: كثرة النطاقات الفرعية قد تُستخدم لإخفاء النطاق الأساسي.")

    if not is_ip and any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score -= 20
        warnings.append("امتداد نطاق عالي المخاطر: هذا الامتداد يظهر بكثرة في الروابط المشبوهة؛ تعامل مع محتواه بحذر.")

    # 3. Brand impersonation check
    if not is_ip:
        for brand, expected_suffix in KNOWN_BRANDS.items():
            if brand in domain and not domain.endswith(expected_suffix):
                score -= 45
                warnings.append(f"احتمال انتحال جهة ({brand}): النطاق لا ينتهي بالامتداد المتوقع ({expected_suffix})؛ افتح الموقع الرسمي مباشرة من المتصفح.")

    # 4. Shortener check
    is_shortener = any(domain == s or domain.endswith('.' + s) for s in SHORTENER_DOMAINS)
    if is_shortener:
        score -= 15
        warnings.append("رابط مختصر: الوجهة النهائية مخفية خلف خدمة اختصار؛ تأكد من موثوقية مرسل الرابط.")

    # 5. DNS & Transport security (HTTPS & SSL)
    if not dns_ok:
        score -= 35
        warnings.append("تعذر حل اسم النطاق عبر DNS: النطاق قد يكون غير مسجل أو معطلاً أو كُتب بشكل خاطئ.")
        score = max(0, min(100, score))
        status = "الموقع خطير ومشبوه جداً" if score < 50 else "الموقع مشبوه ويحتاج الحذر"
        return score, status, warnings, url, "تعذر الوصول (DNS)"

    if url.startswith('http://'):
        score -= 35
        warnings.append("اتصال غير مشفر (HTTP): البيانات المرسلة لا تمر عبر HTTPS؛ لا تدخل كلمات مرور أو بيانات بنكية.")
    elif not is_ip:
        if not check_ssl_certificate(domain):
            score -= 25
            warnings.append("مشكلة في شهادة SSL/TLS: تعذر التحقق من شهادة الأمان للخادم؛ يُنصح بعدم متابعة العمليات الحساسة.")

    # 6. Redirect chain & HTML sandbox inspection
    redirect_info = "مباشر (لا توجد إعادة توجيه)"
    final_url = url
    final_domain = domain

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
        }
        response = requests.get(url, timeout=6, allow_redirects=True, headers=headers)
        final_url = response.url
        final_domain = urlparse(final_url).netloc.lower().split(':')[0]

        if len(response.history) > 0:
            redirect_info = f"تم التتبع عبر {len(response.history)} قفزة إلى: {final_domain}"
            if final_domain != domain and not final_domain.endswith('.' + domain):
                score -= 20
                warnings.append(f"تغيير النطاق بعد التوجيه: انتقل الرابط من ({domain}) إلى ({final_domain})؛ راجع الوجهة النهائية قبل التفاعل.")

        if response.status_code >= 400:
            score -= 10
            warnings.append(f"استجابة خادم غير طبيعية (HTTP {response.status_code}): الصفحة قد تكون مقيدة أو غير متاحة بشكل طبيعي.")

        if 'text/html' in response.headers.get('Content-Type', ''):
            sandbox_deductions, sandbox_findings = analyze_html_sandbox(response.text, final_domain)
            score -= sandbox_deductions
            warnings.extend(sandbox_findings)

    except requests.exceptions.Timeout:
        score -= 20
        warnings.append("تأخر استجابة الخادم (Timeout): الخادم لم يستجب خلال المهلة المحددة؛ قد يكون بطيئاً أو مقيداً للفحص الآلي.")
    except requests.exceptions.RequestException:
        if is_shortener:
            warnings.append("ملاحظة: خدمة اختصار الروابط قيّدت الفحص الآلي؛ تحقق من مصدر الرابط قبل فتحه.")
        else:
            score -= 20
            warnings.append("تعذر قراءة محتوى الصفحة: الخادم قد يمنع الفحص الآلي أو يواجه مشكلة مؤقتة.")

    score = max(0, min(100, score))

    if score >= 80:
        status = "الموقع يبدو آمن"
    elif score >= 50:
        status = "الموقع مشبوه ويحتاج الحذر"
    else:
        status = "الموقع خطير ومشبوه جداً"

    if not warnings:
        warnings.append("لا توجد مؤشرات خطورة واضحة في الفحص الهيكلي أو السلوكي أو محتوى الصفحة؛ مع ذلك يظل الحذر مطلوباً عند إدخال أي بيانات.")

    return score, status, warnings, final_url, redirect_info


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json(silent=True)
    if not data or 'url' not in data:
        return jsonify({'error': 'الرجاء إرسال الرابط بشكل صحيح'}), 400

    raw_url = str(data.get('url', '')).strip()
    if not raw_url:
        return jsonify({'error': 'حقل الرابط فارغ'}), 400

    score, status, warnings, final_url, redirect_info = evaluate_url_nca(raw_url)

    return jsonify({
        'url': final_url,
        'score': score,
        'status': status,
        'warnings': warnings,
        'redirect_info': redirect_info
    })


@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    if 'file' not in request.files:
        return jsonify({'error': 'لم يتم إرفاق صورة الباركود'}), 400

    file = request.files['file']
    if not file or file.filename == '':
        return jsonify({'error': 'لم يتم اختيار ملف صالح'}), 400

    try:
        image = Image.open(file.stream)
        decoded_objects = pyzbar.decode(image)

        if not decoded_objects:
            return jsonify({'error': 'تعذر قراءة رمز QR من الصورة المرفوعة'}), 400

        extracted_url = decoded_objects[0].data.decode('utf-8').strip()
        score, status, warnings, final_url, redirect_info = evaluate_url_nca(extracted_url)

        return jsonify({
            'success': True,
            'extracted_url': final_url,
            'score': score,
            'status': status,
            'warnings': warnings,
            'redirect_info': redirect_info
        })
    except Exception as e:
        return jsonify({'error': f'خطأ في معالجة الصورة: {str(e)}'}), 500


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
