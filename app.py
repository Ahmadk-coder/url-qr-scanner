import os
import re
from flask import Flask, render_template, request, jsonify
import requests
from bs4 import BeautifulSoup
from PIL import Image
from pyzbar import pyzbar
import io
from urllib.parse import urlparse

app = Flask(__name__)

# قائمة النطاقات المختصرة الشهيرة لمعالجة الروابط
SHORTENER_DOMAINS = [
    'bit.ly', 't.co', 'goo.gl', 'ow.ly', 'Me-qr.com', 
    'tinyurl.com', 'lnkiy.in', 'is.gd', 'buff.ly'
]

# كلمات التصيد الاحتيالي المستهدفة
PHISHING_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'absher', 
    'nafath', 'stc', 'bank', 'account', 'secure', 'confirm'
]

def evaluate_url_nca(url):
    """
    خوارزمية تقييم المخاطر المتقدمة وفق معايير الهيئة الوطنية للأمن السيبراني (NCA Risk Scoring Model)
    """
    score = 100
    warnings = []
    
    # 1. التصحيح التلقائي للرابط إذا نسخ المستخدم الرابط بدون بروتوكول
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()

    # 2. فحص البروتوكول (HTTP غير آمن)
    if url.startswith('http://'):
        score -= 40
        warnings.append("تحذير أمني: الموقع لا يستخدم بروتوكول التشفير الآمن HTTP بدلاً من HTTPS.")

    # 3. فحص الكلمات المفتاحية للتصيد الاحتيالي (Phishing Keywords)
    url_lower = url.lower()
    for kw in PHISHING_KEYWORDS:
        if kw in url_lower:
            score -= 35
            warnings.append(f"تحذير: الرابط يحتوي على كلمة حساسة تستخدم غالباً في عمليات التصيد ({kw}).")

    # 4. فحص الرموز المشبوهة مثل @ أو عناوين IP المباشرة
    if '@' in url:
        score -= 30
        warnings.append("تحذير أمني: وجود رمز '@' في الرابط قد يكون محاولة لتمويه الوجهة الحقيقية.")
    
    # فحص ما إذا كان النطاق عبارة عن IP مباشر
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if ip_pattern.match(domain):
        score -= 40
        warnings.append("تحذير عالي الخطورة: الرابط يستخدم عنوان IP مباشر بدلاً من نطاق رسمي موثق.")

    # 5. تتبع إعادة التوجيه للرابط (Redirect Chain Resolution)
    redirect_info = "الرابط مباشر ولا يوجد إعادة توجيه."
    try:
        response = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        if len(response.history) > 0:
            final_domain = urlparse(response.url).netloc
            redirect_info = f"تم رصد إعادة توجيه إلى النطاق النهائي: {final_domain}"
            if final_domain != domain:
                score -= 15
                warnings.append(f"تحذير: تم توجيهك من نطاق مختلف إلى الوجهة ({final_domain}).")
    except requests.exceptions.RequestException:
        score -= 20
        warnings.append("تنبيه: تعذر الاتصال بالخادم المضيف للموقع (قد يكون الموقع غير متاح أو يحجب الفحص الآلي).")

    # 6. فحص الروابط المختصرة
    is_shortener = any(short_domain in domain for short_domain in SHORTENER_DOMAINS)
    if is_shortener:
        score -= 10
        warnings.append("تنبيه: هذا الرابط مسجل كخدمة تقصير روابط، يرجى الحذر من الوجهة النهائية.")

    # منع نزول النسبة تحت الصفر أو تجاوز 100
    score = max(0, min(100, score))
    
    # تحديد الحالة بناءً على النسبة
    status = "آمن"
    if score < 50:
        status = "مشبوه جداً وخطير"
    elif score < 80:
        status = "مشبوه ويحتاج الحذر"

    return score, status, warnings, url, redirect_info

@app.route('/')
def home():
    """عرض صفحة الواجهة الرئيسية"""
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    """مسار استقبال وفحص الروابط النصية"""
    data = request.get_json()
    if not data or 'url' not in data:
        return jsonify({'error': 'بيانات غير صالحة'}), 400
        
    raw_url = data.get('url', '').strip()
    if not raw_url:
        return jsonify({'error': 'الرجاء إدخال رابط صحيح'}), 400

    # تنفيذ خوارزمية الفحص الكاملة
    score, status, warnings, normalized_url, redirect_info = evaluate_url_nca(raw_url)

    return jsonify({
        'url': normalized_url,
        'score': score,
        'status': status,
        'warnings': warnings,
        'redirect_info': redirect_info
    })

@app.route('/scan-qr', methods=['POST'])
def scan_qr():
    """مسار فحص وفك شفرة باركود QR المرفوع كصورة على السيرفر (Pyzbar Fallback)"""
    if 'file' not in request.files:
        return jsonify({'error': 'لم يتم العثور على ملف الصورة'}), 400
        
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'لم يتم اختيار أي ملف'}), 400

    try:
        # قراءة الصورة وفك شفرة الباركود باستخدام pyzbar و Pillow
        image = Image.open(file.stream)
        decoded_objects = pyzbar.decode(image)
        
        if not decoded_objects:
            return jsonify({'error': 'لم يتم العثور على رمز QR صالح داخل الصورة'}), 400
            
        extracted_url = decoded_objects[0].data.decode('utf-8')
        
        # فحص الرابط المستخرج مباشرة عبر خوارزمية NCA
        score, status, warnings, normalized_url, redirect_info = evaluate_url_nca(extracted_url)

        return jsonify({
            'success': True,
            'extracted_url': normalized_url,
            'score': score,
            'status': status,
            'warnings': warnings,
            'redirect_info': redirect_info
        })
        
    except Exception as e:
        return jsonify({'error': f'حدث خطأ أثناء معالجة الصورة: الحيوان المنوي أو الملف التالف {str(e)}'}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
