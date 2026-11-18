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
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False


def analyze_html_sandbox(html_content: str, final_domain: str):
    """
    Logical & Stateless Sandbox:
    Inspects raw HTML statically via BeautifulSoup without executing active scripts.
    Differentiates between normal legitimate websites (blogs, news, stores) and malicious credential harvesters.
    """
    deductions = 0
    findings = []
    soup = BeautifulSoup(html_content, 'html.parser')

    # 1. Inspect forms & sensitive data collection (Passwords, National ID, Card numbers)
    forms = soup.find_all('form')
    password_inputs = soup.find_all('input', {'type': 'password'})

    if password_inputs:
        is_official = final_domain.endswith(('.gov.sa', '.edu.sa', '.org.sa', '.com.sa'))
        if not is_official:
            deductions += 25
            findings.append("تنبيه سلوكي: الصفحة تطلب إدخال كلمة مرور (Password) ضمن نطاق تجاري عام.")

    # Check if forms submit data to a completely different external domain (Data Exfiltration indicator)
    for form in forms:
        action = form.get('action', '').strip()
        if action.startswith(('http://', 'https://')):
            action_domain = urlparse(action).netloc.lower().split(':')[0]
            if action_domain and action_domain != final_domain and not action_domain.endswith('.' + final_domain):
                deductions += 35
                findings.append(f"تحذير خطير: نموذج الإدخال يرسل بيانات المستخدم إلى خادم خارجي مختلف ({action_domain}).")

    # 2. Check hidden iframes (Drive-by / Clickjacking indicator)
    for iframe in soup.find_all('iframe'):
        style = iframe.get('style', '').replace(' ', '').lower()
        if 'display:none' in style or 'visibility:hidden' in style or iframe.get('width') == '0' or iframe.get('height') == '0':
            deductions += 25
            findings.append("تحذير هيكلي: تم اكتشاف إطار مخفي (Hidden Iframe) داخل كود الصفحة.")
            break

    # 3. Check suspicious external scripts or obfuscated inline JS (eval / atob / document.write)
    obfuscation_hits = 0
    for script in soup.find_all('script'):
        script_text = script.string or ''
        if any(pattern in script_text for pattern in ('eval(atob(', 'String.fromCharCode(', 'unescape(')):
            obfuscation_hits += 1

    if obfuscation_hits > 0:
        deductions += 25
        findings.append("تحذير برمجي: وجود أكواد JavaScript مشفرة أو مموهة (Obfuscated Scripts) داخل الصفحة.")

    # 4. Check meta refresh automatic redirects
    meta_refresh = soup.find('meta', attrs={'http-equiv': re.compile(r'^refresh$', re.I)})
    if meta_refresh:
        content = meta_refresh.get('content', '').lower()
        if 'url=' in content:
            deductions += 20
            findings.append("تحذير توجيه: الصفحة تستخدم إعادة توجيه تلقائية مخفية عبر وسم Meta Refresh.")

    return deductions, findings


def evaluate_url_nca(raw_url: str):
    """
    Comprehensive Multi-Layer Risk Scoring Model (NCA Aligned).
    Fairly evaluates lesser-known legitimate sites (giving them high scores if clean)
    while catching technical, structural, and behavioral threats.
    """
    score = 100
    warnings = []
    positive_notes = []

    url = normalize_url(raw_url)
    decoded_url = unquote(url)
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    path_lower = parsed.path.lower()

    if not domain or '.' not in domain:
        return 0, "رابط غير صالح", ["صيغة الرابط المدخل غير صحيحة."], url, "لم يتم الفحص"

    # Layer 1: DNS & Network Reachability
    if not check_dns_resolution(domain):
        return 25, "موقع غير موجود أو معطل", ["فشل فحص DNS: النطاق غير مسجل أو لا يرتبط بأي خادم نشط."], url, "فشل الاتصال"

    # Layer 2: Transport Layer Security (HTTPS & SSL/TLS)
    if url.startswith('http://'):
        score -= 40
        warnings.append("مخالفة معايير التشفير (NCA): الموقع يستخدم بروتوكول HTTP غير المشفر.")
    else:
        if check_ssl_certificate(domain):
            positive_notes.append("شهادة التشفير SSL/TLS صالحة ومفعلة.")
        else:
            score -= 30
            warnings.append("تحذير شهادة الأمان: شهادة SSL/TLS غير صالحة أو منتهية الصلاحية.")

    # Layer 3: Direct Malicious Payload Check (Downloads)
    if path_lower.endswith(DANGEROUS_FILE_EXTS):
        score -= 45
        warnings.append("تحذير تحميل مباشر: الرابط يؤدي مباشرة إلى تحميل ملف تنفيذي أو مضغوط قد يحتوي برمجيات خبيثة.")

    # Layer 4: Lexical & Structural Obfuscation Checks
    if '@' in decoded_url:
        score -= 35
        warnings.append("تمويه الرابط: وجود الرمز '@' يستخدم لإخفاء الوجهة الحقيقية للمستخدم.")

    if domain.startswith('xn--') or '.xn--' in domain:
        score -= 35
        warnings.append("هجوم تشابه الأحرف (IDN Homograph): النطاق يستخدم ترميز Punycode لتقليد مواقع موثوقة.")

    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if ip_pattern.match(domain):
        score -= 45
        warnings.append("تحذير عالي: الرابط يستخدم عنوان IP مباشر بدلاً من اسم نطاق مسجل.")

    if domain.count('.') >= 3 and not domain.endswith('.sa'):
        score -= 20
        warnings.append("بنية نطاق معقدة: كثرة النطاقات الفرعية (Subdomains) مؤشر شائع للتمويه.")

    if any(domain.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score -= 20
        warnings.append("امتداد نطاق عالي المخاطر: النطاق ينتهي بامتداد شائع الاستخدام في حملات التصيد.")

    # Layer 5: Brand & Government Impersonation Check
    for brand, expected_suffix in KNOWN_BRANDS.items():
        if brand in domain and not domain.endswith(expected_suffix):
            score -= 45
            warnings.append(f"انتحال هوية محتمل: النطاق يحتوي على اسم ({brand}) ولكنه لا يتبع النطاق الرسمي ({expected_suffix}).")

    # Layer 6: Redirect Chain & Deep Static Sandbox Inspection
    redirect_info = "مباشر (لا توجد إعادة توجيه)"
    final_url = url
    final_domain = domain
    is_shortener = any(domain == s or domain.endswith('.' + s) for s in SHORTENER_DOMAINS)

    if is_shortener:
        score -= 15
        warnings.append("رابط مختصر: تم استخدام خدمة تقصير روابط تخفي الوجهة الفعلية.")

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
                warnings.append(f"تغيير الوجهة السلوكي: الرابط قام بإعادة توجيهك من ({domain}) إلى نطاق مختلف ({final_domain}).")

        if response.status_code >= 400:
            score -= 15
            warnings.append(f"تنبيه حالة الخادم: الخادم أعاد رمز خطأ HTTP ({response.status_code}).")

        if 'text/html' in response.headers.get('Content-Type', ''):
            sandbox_deductions, sandbox_findings = analyze_html_sandbox(response.text, final_domain)
            score -= sandbox_deductions
            warnings.extend(sandbox_findings)

    except requests.exceptions.Timeout:
        score -= 25
        warnings.append("انتهاء مهلة الاتصال (Sandbox Timeout): الخادم بطيء جداً أو لا يستجيب.")
    except requests.exceptions.RequestException:
        if is_shortener:
            warnings.append("ملاحظة: خادم اختصار الروابط يحجب الفحص الآلي، يُرجى التأكد من مصدر الرمز.")
        else:
            score -= 30
            warnings.append("تعذر فحص محتوى الصفحة: الخادم يحجب الفحص الآلي أو غير متاح حالياً.")

    score = max(0, min(100, score))

    if score >= 80:
        status = "الموقع يبدو آمن"
    elif score >= 50:
        status = "الموقع مشبوه ويحتاج الحذر"
    else:
        status = "الموقع خطير ومشبوه جداً"

    if not warnings:
        warnings.append("تم اجتياز كافة الفحوصات (التشفير، DNS، الهيكل، والـ Sandbox): الموقع سليم ولا يظهر سلوكاً ضاراً حتى لو كان غير مشهور.")

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
